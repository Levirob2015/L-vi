"""ASGI-Middleware.

Reines ASGI ohne Framework-Import - laeuft mit FastAPI, Starlette, Quart,
Litestar oder jedem anderen ASGI-Server::

    from loginshield import Guard, load_config
    from loginshield.middleware import ShieldMiddleware

    guard = Guard(load_config())
    app = ShieldMiddleware(app, guard, login_paths=["/login", "/api/auth/*"])

Die Middleware erkennt Login-Fehlschlaege am HTTP-Status der Antwort. Wer den
Benutzernamen mitzaehlen will (fuer Spraying-Erkennung), gibt
``identity_from_scope`` mit - oder ruft ``guard.record_failure(...)`` direkt
im eigenen Login-Handler auf, das ist praeziser.
"""

from __future__ import annotations

import json
from typing import Callable, Iterable, Optional, Sequence

from .engine import Guard
from .models import Decision


def path_matches(path: str, patterns: Sequence[str]) -> bool:
    """Exakter Treffer oder Praefix, wenn das Muster auf ``*`` endet."""
    for pattern in patterns:
        if pattern.endswith("*"):
            if path.startswith(pattern[:-1]):
                return True
        elif path == pattern:
            return True
    return False


class ShieldMiddleware:
    def __init__(
        self,
        app,
        guard: Guard,
        *,
        login_paths: Iterable[str] = ("/login",),
        login_methods: Iterable[str] = ("POST",),
        failure_statuses: Iterable[int] = (401, 403, 422),
        exempt_paths: Iterable[str] = (),
        identity_from_scope: Optional[Callable[[dict], Optional[str]]] = None,
        protect_all_paths: bool = True,
    ) -> None:
        self.app = app
        self.guard = guard
        self.login_paths = tuple(login_paths)
        self.login_methods = {method.upper() for method in login_methods}
        self.failure_statuses = frozenset(failure_statuses)
        self.exempt_paths = tuple(exempt_paths)
        self.identity_from_scope = identity_from_scope
        #: False = nur Login-Pfade pruefen, alles andere ungebremst durchlassen.
        self.protect_all_paths = protect_all_paths

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.exempt_paths and path_matches(path, self.exempt_paths):
            await self.app(scope, receive, send)
            return

        headers = _headers(scope)
        client = scope.get("client") or (None, None)
        ip = self.guard.resolve_ip(client[0], headers.get("x-forwarded-for"))
        method = scope.get("method", "GET").upper()
        is_login = method in self.login_methods and path_matches(path, self.login_paths)

        identity = None
        if self.identity_from_scope is not None:
            try:
                identity = self.identity_from_scope(scope)
            except Exception:  # pragma: no cover - Nutzer-Callback
                identity = None

        if self.protect_all_paths or is_login:
            decision = self.guard.check(ip, identity=identity, route=path)
            if not decision.allowed:
                await _send_denied(send, decision)
                return

        if not is_login:
            await self.app(scope, receive, send)
            return

        status_holder = {"status": 200}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message["status"])
            await send(message)

        await self.app(scope, receive, send_wrapper)

        status = status_holder["status"]
        user_agent = headers.get("user-agent", "")
        if status in self.failure_statuses:
            self.guard.record_failure(
                ip, identity=identity, route=path, user_agent=user_agent,
                detail=f"HTTP {status}",
            )
        elif 200 <= status < 400:
            self.guard.record_success(
                ip, identity=identity, route=path, user_agent=user_agent
            )


def _headers(scope) -> dict:
    result = {}
    for raw_key, raw_value in scope.get("headers") or ():
        key = raw_key.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        # Mehrfach gesetzte Header zusammenfassen (relevant bei X-Forwarded-For).
        result[key] = f"{result[key]}, {value}" if key in result else value
    return result


async def _send_denied(send, decision: Decision) -> None:
    payload = json.dumps(
        {
            "error": "blocked",
            "reason": decision.reason,
            "retry_after": decision.retry_after,
            "message": "Zu viele Versuche. Bitte spaeter erneut probieren.",
        }
    ).encode("utf-8")
    headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if decision.retry_after > 0:
        headers.append((b"retry-after", str(decision.retry_after).encode("ascii")))
    await send(
        {"type": "http.response.start", "status": decision.status_code, "headers": headers}
    )
    await send({"type": "http.response.body", "body": payload})


class WSGIShield:
    """Gleiche Logik fuer WSGI (Flask, Django, Bottle).

        app.wsgi_app = WSGIShield(app.wsgi_app, guard, login_paths=["/login"])
    """

    def __init__(self, app, guard: Guard, *, login_paths: Iterable[str] = ("/login",),
                 login_methods: Iterable[str] = ("POST",),
                 failure_statuses: Iterable[int] = (401, 403, 422),
                 exempt_paths: Iterable[str] = (),
                 protect_all_paths: bool = True) -> None:
        self.app = app
        self.guard = guard
        self.login_paths = tuple(login_paths)
        self.login_methods = {method.upper() for method in login_methods}
        self.failure_statuses = frozenset(failure_statuses)
        self.exempt_paths = tuple(exempt_paths)
        self.protect_all_paths = protect_all_paths

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if self.exempt_paths and path_matches(path, self.exempt_paths):
            return self.app(environ, start_response)

        ip = self.guard.resolve_ip(
            environ.get("REMOTE_ADDR"), environ.get("HTTP_X_FORWARDED_FOR")
        )
        method = environ.get("REQUEST_METHOD", "GET").upper()
        is_login = method in self.login_methods and path_matches(path, self.login_paths)

        if self.protect_all_paths or is_login:
            decision = self.guard.check(ip, route=path)
            if not decision.allowed:
                payload = json.dumps(
                    {
                        "error": "blocked",
                        "reason": decision.reason,
                        "retry_after": decision.retry_after,
                    }
                ).encode("utf-8")
                headers = [
                    ("Content-Type", "application/json; charset=utf-8"),
                    ("Content-Length", str(len(payload))),
                    ("Cache-Control", "no-store"),
                ]
                if decision.retry_after > 0:
                    headers.append(("Retry-After", str(decision.retry_after)))
                start_response(f"{decision.status_code} Blocked", headers)
                return [payload]

        if not is_login:
            return self.app(environ, start_response)

        captured = {"status": 200}

        def start_response_wrapper(status, headers, exc_info=None):
            try:
                captured["status"] = int(str(status).split(" ", 1)[0])
            except ValueError:  # pragma: no cover - defensiv
                pass
            return start_response(status, headers, exc_info)

        result = self.app(environ, start_response_wrapper)
        status = captured["status"]
        user_agent = environ.get("HTTP_USER_AGENT", "")
        if status in self.failure_statuses:
            self.guard.record_failure(
                ip, route=path, user_agent=user_agent, detail=f"HTTP {status}"
            )
        elif 200 <= status < 400:
            self.guard.record_success(ip, route=path, user_agent=user_agent)
        return result
