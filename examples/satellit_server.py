"""Die Satellitenwerkstatt auf dem eigenen Server - mit LoginShield davor.

Start::

    python examples/satellit_server.py

Dann http://127.0.0.1:8080/ oeffnen. Parallel laeuft das LoginShield-
Dashboard auf http://127.0.0.1:8787/ - dort sieht man jeden Angriff.

Was LoginShield hier abwehrt:

* Schwachstellen-Scanner: Wer nach /.env, /wp-admin, /phpmyadmin & Co.
  sucht, bekommt eine Koederdatei und ist sofort gesperrt.
* Angriffe in der Adresse: SQL-Injection, Pfad-Tricks (../), Skript-Code
  in Parametern werden von der Anfrage-Firewall abgewiesen.
* Ueberflutung: Mehr als ``FLUT_GRENZE`` Anfragen pro Minute von einer
  Adresse werden gebremst (HTTP 429), wer weiter haemmert, wird gesperrt.
* Gesperrte Adressen kommen gar nicht mehr bis zur Seite.

Dazu schickt der Server Sicherheits-Kopfzeilen mit (Content-Security-
Policy, kein Einbetten in fremde Seiten, kein MIME-Raten). Damit kann eine
fremde Seite die Werkstatt weder einrahmen noch Skripte einschleusen.

Zum Ausprobieren (danach ist die eigene IP gesperrt,
``loginshield unblock 127.0.0.1`` hebt das wieder auf):

* http://127.0.0.1:8080/.env              -> Falle, sofortige Sperre
* http://127.0.0.1:8080/?id=1' OR '1'='1  -> Anfrage-Firewall

Fuer den echten Betrieb: hinter einen Webserver mit HTTPS stellen (nginx,
Caddy), dessen Adresse in ``config.trusted_proxies`` eintragen, damit
LoginShield die echte Besucher-IP sieht, und ``loginshield firewall --setup``
ausfuehren - dann gilt jede Sperre auch auf Netzwerkebene.

Bewusst nur Standardbibliothek, damit das Beispiel ohne weitere Pakete laeuft.
"""

from __future__ import annotations

import json
import os
import sys
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))

from loginshield import Config, Guard, Reason  # noqa: E402
from loginshield.dashboard import Dashboard  # noqa: E402
from loginshield.middleware import WSGIShield  # noqa: E402
from loginshield.ratelimit import SlidingWindow  # noqa: E402

APP_DATEI = os.path.join(os.path.dirname(HIER), "docs", "satellit.html")
HOST = os.environ.get("SATELLIT_HOST", "127.0.0.1")
PORT = int(os.environ.get("SATELLIT_PORT", "8080"))
FLUT_GRENZE = 120          # Anfragen pro Minute und Adresse
FLUT_SPERRE = 600          # Sekunden Sperre fuer Dauerhaemmerer

config = Config()
config.db_path = "satellit-loginshield.db"
config.allowlist = []      # damit man die Fallen in der Demo selbst testen kann
config.dashboard.port = 8787
guard = Guard(config)
flut = SlidingWindow(FLUT_GRENZE, 60)

# Die Seite laedt three.js von zwei bekannten CDNs und Schriften von Google -
# alles andere ist verboten. Inline-Skript ist noetig, weil die ganze App in
# einer Datei steckt; eingeschleuster Code von fremden Adressen laeuft nicht.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
])

SICHERHEIT = [
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
]


def seite() -> bytes:
    """Die Werkstatt als vollstaendiges Dokument.

    Bei jedem Aufruf frisch gelesen: Wer docs/satellit.html aendert, sieht
    die neue Fassung ohne Neustart.
    """
    with open(APP_DATEI, encoding="utf-8") as datei:
        inhalt = datei.read()
    return (
        '<!doctype html><html lang="de"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        "</head><body>\n" + inhalt + "\n</body></html>"
    ).encode("utf-8")


def antwort(start_response, status: str, typ: str, body: bytes, extra=()):
    kopf = [("Content-Type", typ), ("Content-Length", str(len(body)))]
    start_response(status, kopf + SICHERHEIT + list(extra))
    return [body]


def werkstatt(environ, start_response):
    """Die eigentliche Anwendung: nur zwei Adressen, nur Lesen."""
    methode = environ.get("REQUEST_METHOD", "GET").upper()
    pfad = environ.get("PATH_INFO", "/")

    if methode not in ("GET", "HEAD"):
        return antwort(start_response, "405 Method Not Allowed",
                       "text/plain; charset=utf-8", b"Nur Lesen erlaubt.\n",
                       [("Allow", "GET, HEAD")])
    if pfad in ("/", "/satellit.html", "/index.html"):
        body = seite()
        return antwort(start_response, "200 OK", "text/html; charset=utf-8",
                       b"" if methode == "HEAD" else body,
                       [("Cache-Control", "no-cache")])
    if pfad == "/robots.txt":
        return antwort(start_response, "200 OK", "text/plain; charset=utf-8",
                       b"User-agent: *\nAllow: /\n")
    return antwort(start_response, "404 Not Found", "text/plain; charset=utf-8",
                   b"Nicht gefunden.\n")


def flutbremse(app):
    """Bremst Adressen, die die Seite mit Anfragen ueberschuetten.

    Vor LoginShield geschaltet - wer gesperrt ist, kostet so kaum Arbeit.
    Wer die Grenze dreifach reisst, wird ueber LoginShield gesperrt und
    taucht damit auch im Dashboard und (falls eingerichtet) in der Firewall auf.
    """
    def mitte(environ, start_response):
        ip = guard.resolve_ip(environ.get("REMOTE_ADDR"),
                              environ.get("HTTP_X_FORWARDED_FOR"))
        erlaubt, warten, anzahl = flut.hit(ip)
        if not erlaubt:
            if anzahl > FLUT_GRENZE * 3 and not guard.is_allowlisted(ip):
                guard.block(ip, seconds=FLUT_SPERRE, reason=Reason.RATE_LIMIT_ABUSE,
                            detail="Satellitenwerkstatt ueberflutet")
            body = json.dumps({"error": "zu viele Anfragen",
                               "retry_after": warten}).encode("utf-8")
            return antwort(start_response, "429 Too Many Requests",
                           "application/json; charset=utf-8", body,
                           [("Retry-After", str(warten))])
        return app(environ, start_response)
    return mitte


# Reihenfolge von aussen nach innen: Flutbremse -> LoginShield -> Werkstatt.
# Die Werkstatt hat keinen Login; LoginShield arbeitet hier mit Fallen,
# Anfrage-Firewall und Sperrliste. login_paths bleibt leer.
app = flutbremse(WSGIShield(werkstatt, guard, login_paths=(), protect_all_paths=True))


class LeiserHandler(WSGIRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - Signatur der Basisklasse
        sys.stderr.write("%s %s\n" % (self.address_string(), format % args))


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def main():
    dashboard = Dashboard(guard, config.dashboard)
    dashboard.start_background()
    server = make_server(HOST, PORT, app, server_class=ThreadingWSGIServer,
                         handler_class=LeiserHandler)
    print(f"Satellitenwerkstatt: http://{HOST}:{PORT}/")
    print("LoginShield-Dashboard: http://127.0.0.1:8787/")
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
