"""Lauffaehiges Beispiel: eine Mini-Login-Seite mit LoginShield davor.

Start::

    python examples/demo_login_app.py

Dann http://127.0.0.1:8080/ oeffnen. Zugangsdaten: anna / geheim123
Ein paar falsche Passwoerter eingeben - nach 5 Fehlversuchen ist die IP
gesperrt. Parallel laeuft das Dashboard auf http://127.0.0.1:8787/

Bewusst ohne Framework (nur Standardbibliothek), damit das Beispiel ohne
Installation zusaetzlicher Pakete laeuft. Die Einbindung in Flask/FastAPI
ist in der README beschrieben.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loginshield import Config, Guard  # noqa: E402
from loginshield.dashboard import Dashboard  # noqa: E402

# Demo-Benutzer. In echt kommen die aus der Datenbank, das Passwort
# natuerlich nur als Hash (argon2/bcrypt/scrypt) - nie im Klartext.
USERS = {"anna": "geheim123", "ben": "hunter2!"}

config = Config()
config.db_path = "demo-loginshield.db"
config.allowlist = []  # damit man sich in der Demo selbst sperren kann
config.rules.ip_failure_threshold = 5
config.rules.ip_failure_window = 300
config.rules.block_base_seconds = 60  # kurze Sperre, damit die Demo nicht nervt
config.dashboard.port = 8787
guard = Guard(config)

PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<title>Demo-Login</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font:16px/1.5 system-ui,sans-serif;background:#0f1216;color:#e7eaee;
display:grid;place-items:center;height:100vh;margin:0}}
form{{background:#171b21;border:1px solid #262c34;border-radius:12px;padding:28px;width:320px}}
h1{{font-size:18px;margin:0 0 4px}} p{{color:#98a2ae;font-size:13px;margin:0 0 18px}}
input{{width:100%;padding:9px 11px;margin-bottom:10px;border-radius:7px;
border:1px solid #262c34;background:#0f1216;color:#e7eaee;font:inherit}}
button{{width:100%;padding:10px;border:0;border-radius:7px;background:#5a8dff;
color:#fff;font:inherit;font-weight:600;cursor:pointer}}
.msg{{padding:9px 11px;border-radius:7px;margin-bottom:14px;font-size:14px}}
.err{{background:#3a1d1d;color:#f0665f}} .ok{{background:#14331f;color:#4cc57f}}
</style></head><body><form method="post" action="/login">
<h1>Demo-Login</h1><p>anna / geheim123 &middot; Dashboard: Port 8787</p>
{message}
<input name="username" placeholder="Benutzername" autocomplete="off" autofocus>
<input name="password" type="password" placeholder="Passwort">
<button>Anmelden</button></form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        return guard.resolve_ip(self.client_address[0],
                                self.headers.get("X-Forwarded-For"))

    def _respond(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path != "/":
            self._respond(404, "nicht gefunden", "text/plain; charset=utf-8")
            return
        self._respond(200, PAGE.format(message=""))

    def do_POST(self):
        if self.path != "/login":
            self._respond(404, "nicht gefunden", "text/plain; charset=utf-8")
            return

        ip = self._client_ip()

        # 1) Vor jeder Passwortpruefung: darf diese IP ueberhaupt?
        decision = guard.check(ip, route="/login")
        if not decision.allowed:
            message = (
                f'<div class="msg err">Zu viele Versuche. Gesperrt fuer noch '
                f"{decision.retry_after} Sekunden ({html.escape(decision.reason)}).</div>"
            )
            self._respond(
                decision.status_code,
                PAGE.format(message=message),
                headers={"Retry-After": str(decision.retry_after)},
            )
            return

        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = (form.get("username") or [""])[0].strip()
        password = (form.get("password") or [""])[0]

        expected = USERS.get(username)
        # compare_digest: keine messbaren Zeitunterschiede beim Vergleich
        valid = expected is not None and hmac.compare_digest(
            hashlib.sha256(password.encode()).digest(),
            hashlib.sha256(expected.encode()).digest(),
        )

        if valid:
            # 2a) Erfolg melden - setzt die Fehlerzaehler zurueck
            guard.record_success(ip, identity=username, route="/login",
                                 user_agent=self.headers.get("User-Agent", ""))
            self._respond(200, PAGE.format(
                message=f'<div class="msg ok">Willkommen, {html.escape(username)}!</div>'
            ))
            return

        # 2b) Fehlschlag melden - die Antwort sagt, ob jetzt gesperrt wird
        result = guard.record_failure(ip, identity=username or None, route="/login",
                                      user_agent=self.headers.get("User-Agent", ""),
                                      detail="HTTP 401")
        if not result.allowed:
            message = (
                f'<div class="msg err">Zu viele Fehlversuche - IP gesperrt fuer '
                f"{result.retry_after} Sekunden.</div>"
            )
        else:
            # Nie verraten, ob der Benutzername existiert (Konto-Enumeration).
            message = '<div class="msg err">Benutzername oder Passwort falsch.</div>'
        self._respond(401, PAGE.format(message=message))


def main():
    dashboard = Dashboard(guard, config.dashboard)
    dashboard.start_background()
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    print("Demo-Login:  http://127.0.0.1:8080/")
    print("Dashboard:   http://127.0.0.1:8787/")
    print("Beenden mit Strg+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        dashboard.stop()
        server.server_close()
        guard.close()


if __name__ == "__main__":
    main()
