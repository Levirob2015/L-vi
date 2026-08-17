import asyncio
import json

from loginshield.middleware import ShieldMiddleware, WSGIShield, path_matches


# -- Mini-ASGI-Testgeschirr ---------------------------------------------
def make_app(status=200):
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain")],
        })
        await send({"type": "http.response.body", "body": b"ok"})

    return app


def make_scope(path="/login", method="POST", ip="198.51.100.5", headers=None):
    raw_headers = [(b"user-agent", b"pytest")]
    for key, value in (headers or {}).items():
        raw_headers.append((key.encode(), value.encode()))
    return {
        "type": "http",
        "path": path,
        "method": method,
        "client": (ip, 51234),
        "headers": raw_headers,
    }


def call(app, scope):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    return messages


def status_of(messages):
    return next(m["status"] for m in messages if m["type"] == "http.response.start")


def body_of(messages):
    return b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")


def headers_of(messages):
    start = next(m for m in messages if m["type"] == "http.response.start")
    return {key.decode().lower(): value.decode() for key, value in start["headers"]}


# -- Tests ---------------------------------------------------------------
def test_path_matches():
    assert path_matches("/login", ["/login"])
    assert not path_matches("/login/extra", ["/login"])
    assert path_matches("/api/auth/token", ["/api/auth/*"])
    assert not path_matches("/other", ["/api/*"])


def test_fehlversuche_werden_gezaehlt_und_gesperrt(guard, config):
    app = ShieldMiddleware(make_app(401), guard, login_paths=["/login"])

    for _ in range(config.rules.ip_failure_threshold):
        messages = call(app, make_scope())
        assert status_of(messages) == 401

    # Ab jetzt kommt der Request gar nicht mehr in der Anwendung an.
    messages = call(app, make_scope())
    assert status_of(messages) == 403
    payload = json.loads(body_of(messages))
    assert payload["reason"] == "ip_blocked"
    assert "retry-after" in headers_of(messages)


def test_erfolgreicher_login_wird_gemeldet(guard):
    app = ShieldMiddleware(make_app(200), guard, login_paths=["/login"])
    call(app, make_scope())
    successes = guard.store.recent_attempts(limit=10, events=["login_success"])
    assert len(successes) == 1
    assert successes[0].ip == "198.51.100.5"


def test_nur_login_pfade_werden_bewertet(guard, config):
    app = ShieldMiddleware(make_app(401), guard, login_paths=["/login"])
    for _ in range(config.rules.ip_failure_threshold + 3):
        call(app, make_scope(path="/api/data"))
    assert guard.store.active_block("198.51.100.5", now=guard.clock()) is None


def test_nur_konfigurierte_methoden(guard, config):
    app = ShieldMiddleware(make_app(401), guard, login_paths=["/login"],
                           login_methods=["POST"])
    for _ in range(config.rules.ip_failure_threshold + 2):
        call(app, make_scope(method="GET"))
    assert guard.store.active_block("198.51.100.5", now=guard.clock()) is None


def test_exempt_pfade_ueberspringen_alles(config, store, clock):
    from loginshield import Guard

    config.rules.request_limit = 1
    guard = Guard(config, store, clock=clock)
    app = ShieldMiddleware(make_app(200), guard, exempt_paths=["/health"])
    for _ in range(10):
        assert status_of(call(app, make_scope(path="/health", method="GET"))) == 200


def test_rate_limit_greift_fuer_alle_pfade(config, store, clock):
    from loginshield import Guard

    config.rules.request_limit = 2
    guard = Guard(config, store, clock=clock)
    app = ShieldMiddleware(make_app(200), guard, protect_all_paths=True)

    for _ in range(2):
        assert status_of(call(app, make_scope(path="/", method="GET"))) == 200
    messages = call(app, make_scope(path="/", method="GET"))
    assert status_of(messages) == 429
    assert json.loads(body_of(messages))["reason"] == "rate_limited"


def test_gefaelschter_forwarded_header_wird_ignoriert(guard, config):
    app = ShieldMiddleware(make_app(401), guard, login_paths=["/login"])
    scope_headers = {"x-forwarded-for": "1.2.3.4"}
    for _ in range(config.rules.ip_failure_threshold):
        call(app, make_scope(headers=scope_headers))
    # Gesperrt wird der echte Absender, nicht die erfundene Adresse.
    now = guard.clock()
    assert guard.store.active_block("198.51.100.5", now=now) is not None
    assert guard.store.active_block("1.2.3.4", now=now) is None


def test_identity_callback_erkennt_spraying(config, store, clock):
    from loginshield import Guard

    config.rules.ip_failure_threshold = 100
    config.rules.spray_identity_threshold = 3
    guard = Guard(config, store, clock=clock)

    def identity_from_scope(scope):
        headers = dict(scope["headers"])
        value = headers.get(b"x-user")
        return value.decode() if value else None

    app = ShieldMiddleware(make_app(401), guard, login_paths=["/login"],
                           identity_from_scope=identity_from_scope)

    for index in range(3):
        call(app, make_scope(headers={"x-user": f"user{index}"}))
    assert guard.store.active_block("198.51.100.5", now=clock.now) is not None


def test_websocket_wird_durchgereicht(guard):
    seen = {}

    async def app(scope, receive, send):
        seen["type"] = scope["type"]

    middleware = ShieldMiddleware(app, guard)
    asyncio.run(middleware({"type": "websocket"}, None, None))
    assert seen["type"] == "websocket"


# -- WSGI ----------------------------------------------------------------
def wsgi_app(status="401 Unauthorized"):
    def app(environ, start_response):
        start_response(status, [("Content-Type", "text/plain")])
        return [b"ok"]

    return app


def test_wsgi_sperrt_nach_fehlversuchen(guard, config):
    app = WSGIShield(wsgi_app(), guard, login_paths=["/login"])
    environ = {
        "PATH_INFO": "/login",
        "REQUEST_METHOD": "POST",
        "REMOTE_ADDR": "198.51.100.9",
        "HTTP_USER_AGENT": "pytest",
    }
    captured = []

    def start_response(status, headers, exc_info=None):
        captured.append(status)

    for _ in range(config.rules.ip_failure_threshold):
        app(dict(environ), start_response)
    body = app(dict(environ), start_response)

    assert captured[-1].startswith("403")
    assert json.loads(b"".join(body))["reason"] == "ip_blocked"


# -- Grosse Uploads duerfen den Server nicht umlegen ---------------------
# Vorher wurde der ganze Koerper eingelesen, um ihn danach wieder
# bereitzustellen: Bei 300 MB waren das 600 MB Speicher - verursacht von
# der Schutzschicht, die den Server verteidigen soll.
class LangerStrom:
    """Liefert viele Bytes, ohne sie selbst im Speicher zu halten."""

    def __init__(self, gesamt):
        self.uebrig = gesamt

    def read(self, groesse=-1):
        if self.uebrig <= 0:
            return b""
        menge = self.uebrig if groesse is None or groesse < 0 else min(groesse, self.uebrig)
        self.uebrig -= menge
        return b"x" * menge


def test_wsgi_liest_nicht_den_ganzen_koerper(guard):
    """Nur der gepruefte Anfang wird gelesen - der Rest bleibt, wo er ist."""
    from loginshield.middleware import _wsgi_body

    GESAMT = 8 * 1024 * 1024
    strom = LangerStrom(GESAMT)
    environ = {"CONTENT_LENGTH": str(GESAMT), "wsgi.input": strom}

    geprueft = _wsgi_body(environ, 64 * 1024)
    assert len(geprueft) == 64 * 1024
    # Entscheidend: Der Rest wurde noch nicht angefasst.
    assert strom.uebrig == GESAMT - 64 * 1024


def test_die_anwendung_bekommt_trotzdem_alles(guard):
    """Bei aller Sparsamkeit darf kein Byte verloren gehen."""
    GESAMT = 5 * 1024 * 1024
    gelesen = {"summe": 0}

    def app(environ, start_response):
        strom = environ["wsgi.input"]
        while True:
            stueck = strom.read(65536)
            if not stueck:
                break
            gelesen["summe"] += len(stueck)
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    WSGIShield(app, guard)({
        "PATH_INFO": "/upload", "REQUEST_METHOD": "POST",
        "REMOTE_ADDR": "198.51.100.5", "HTTP_USER_AGENT": "x",
        "CONTENT_TYPE": "application/octet-stream",
        "CONTENT_LENGTH": str(GESAMT),
        "wsgi.input": LangerStrom(GESAMT),
    }, lambda s, h, e=None: None)

    assert gelesen["summe"] == GESAMT


def test_kettenstrom_liest_ueber_die_grenze_hinweg():
    import io

    from loginshield.middleware import _Kettenstrom

    strom = _Kettenstrom(b"Kopf-", io.BytesIO(b"Rest-Daten"))
    assert strom.read(7) == b"Kopf-Re"          # ueber die Naht hinweg
    assert strom.read() == b"st-Daten"
    assert strom.read(5) == b""


def test_kettenstrom_zeilenweise():
    import io

    from loginshield.middleware import _Kettenstrom

    # Die Naht liegt mitten in der zweiten Zeile.
    strom = _Kettenstrom(b"eins\nzw", io.BytesIO(b"ei\ndrei\n"))
    assert list(strom) == [b"eins\n", b"zwei\n", b"drei\n"]


def test_kleiner_koerper_bleibt_ein_einfacher_puffer(guard):
    import io

    from loginshield.middleware import _wsgi_body

    environ = {"CONTENT_LENGTH": "5", "wsgi.input": io.BytesIO(b"hallo")}
    assert _wsgi_body(environ, 64 * 1024) == b"hallo"
    assert environ["wsgi.input"].read() == b"hallo"
