"""Web-Dashboard.

Laeuft auf dem HTTP-Server der Standardbibliothek - kein Framework, kein
zusaetzliches Paket. Standardmaessig lauscht es nur auf 127.0.0.1; fuer alles
andere ist ein Token Pflicht (siehe :class:`~loginshield.config.DashboardConfig`).

Sicherheitsentscheidungen:

* Aendernde Aufrufe verlangen den Token im Header ``X-Auth-Token``. Ein
  Browser kann diesen Header bei fremden Seiten nicht setzen, ohne dass ein
  CORS-Preflight scheitert - damit ist CSRF ausgeschlossen.
* Der Token wird per :func:`hmac.compare_digest` verglichen (keine
  Zeitunterschiede, die sich ausmessen lassen).
* Strikte CSP, kein externes Skript, keine Inline-Event-Handler.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .config import DashboardConfig
from .engine import Guard
from .models import Event
from .version import __version__

log = logging.getLogger("loginshield.dashboard")

MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _png(groesse: int = 180) -> bytes:
    """Erzeugt das Symbol fuer den iOS-Startbildschirm - ohne Zusatzpaket.

    iOS nimmt fuer ``apple-touch-icon`` nur PNG; ein SVG wird ignoriert und
    man bekommt ein Bildschirmfoto der Seite als Symbol. Ein PNG von Hand
    zu schreiben ist unaufwendiger, als es klingt: Kopf, ein Datenblock,
    Ende - und jede Zeile mit einem Filterbyte 0 davor.
    """
    import struct
    import zlib

    mitte = groesse / 2.0
    rohdaten = bytearray()
    for y in range(groesse):
        rohdaten.append(0)                       # Filter: keiner
        for x in range(groesse):
            # Ein Schild: oben eckig, unten spitz zulaufend.
            nx = (x - mitte) / (groesse * 0.30)
            ny = (y - groesse * 0.30) / (groesse * 0.46)
            if ny < 0:
                innen = abs(nx) <= 1.0 and ny >= -0.62
            else:
                innen = abs(nx) <= max(0.0, 1.0 - ny * ny * 0.95) and ny <= 1.0
            if innen:
                rohdaten += b"\xff\xff\xff"      # weiss
            else:
                rohdaten += b"\x2f\x6f\xeb"      # dasselbe Blau wie im Dashboard

    def block(art: bytes, inhalt: bytes) -> bytes:
        return (struct.pack(">I", len(inhalt)) + art + inhalt
                + struct.pack(">I", zlib.crc32(art + inhalt) & 0xFFFFFFFF))

    kopf = struct.pack(">IIBBBBB", groesse, groesse, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + block(b"IHDR", kopf)
            + block(b"IDAT", zlib.compress(bytes(rohdaten), 9))
            + block(b"IEND", b""))


#: Erst beim ersten Abruf erzeugt, dann behalten.
#:
#: Vorher stand hier ein Aufruf von :func:`_png`, der beim Import lief -
#: also bei **jedem** Aufruf von ``loginshield``, auch bei ``--version``
#: oder ``block``. Gemessen: 12 ms fuer ein Bild, das die meisten Aufrufe
#: nie brauchen. Ein Achtel der gesamten Startzeit fuer nichts.
_icon_zwischenspeicher: Optional[bytes] = None


def apple_touch_icon() -> bytes:
    global _icon_zwischenspeicher
    if _icon_zwischenspeicher is None:
        _icon_zwischenspeicher = _png(180)
    return _icon_zwischenspeicher

#: Die Beschreibung fuer den Startbildschirm. Android und Chrome lesen sie,
#: iOS nimmt die apple-Meta-Angaben - deshalb beides.
MANIFEST = json.dumps({
    "name": "LoginShield",
    "short_name": "LoginShield",
    "description": "Angriffe sehen und sperren",
    "start_url": "./",
    "scope": "./",
    "display": "standalone",
    "orientation": "any",
    "background_color": "#f6f7f9",
    "theme_color": "#171b21",
    "icons": [{"src": "apple-touch-icon.png", "sizes": "180x180",
               "type": "image/png", "purpose": "any"}],
}, ensure_ascii=False)


def _handler_factory(guard: Guard, config: DashboardConfig):
    token = config.token or ""
    token_required = bool(token) or config.host not in LOOPBACK_HOSTS

    class Handler(BaseHTTPRequestHandler):
        server_version = f"LoginShield/{__version__}"
        protocol_version = "HTTP/1.1"

        # -- Infrastruktur --------------------------------------------
        def log_message(self, fmt, *args):  # noqa: A003 - Signatur vorgegeben
            log.debug("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: int, body: bytes, content_type: str,
                  extra_headers: Optional[dict] = None) -> None:
            self.send_response(status)
            kopfzeilen = {
                "Content-Type": content_type,
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                # img-src und manifest-src sind noetig, seit die Seite ein
                # Symbol fuer den Startbildschirm hat: Bei 'default-src
                # none' wuerde der Browser beides verwerfen. Beide bleiben
                # auf 'self' beschraenkt, es wird nichts von aussen geladen.
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; connect-src 'self'; "
                    "img-src 'self' data:; manifest-src 'self'; "
                    "base-uri 'none'; form-action 'none'"
                ),
            }
            # Angegebene Kopfzeilen ersetzen die Voreinstellung, statt
            # doppelt gesendet zu werden.
            kopfzeilen.update(extra_headers or {})
            for key, value in kopfzeilen.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(
                status,
                json.dumps(payload, default=str).encode("utf-8"),
                "application/json; charset=utf-8",
            )

        def _authorized(self, *, allow_query_token: bool) -> bool:
            if not token_required:
                return True
            supplied = self.headers.get("X-Auth-Token") or ""
            if not supplied and allow_query_token:
                supplied = _query(self.path).get("token", [""])[0]
            if not supplied:
                return False
            return hmac.compare_digest(supplied, token)

        def _read_json(self) -> Tuple[Optional[dict], Optional[str]]:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None, "Ungueltiger Content-Length"
            if length <= 0:
                return {}, None
            if length > MAX_BODY_BYTES:
                return None, "Anfrage zu gross"
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None, "Ungueltiges JSON"
            if not isinstance(data, dict):
                return None, "JSON-Objekt erwartet"
            return data, None

        # -- Routen ----------------------------------------------------
        def do_GET(self):  # noqa: N802 - Signatur vorgegeben
            route = urlparse(self.path).path
            if route in ("/", "/index.html"):
                # Ohne Token kommt dieselbe Seite, nur mit Status 401: Sie
                # zeigt dann den Anmeldebildschirm statt der Lage.
                #
                # Frueher stand hier eine Textzeile - und damit war die App
                # auf dem iPad nach jedem Kaltstart tot: Das Symbol auf dem
                # Startbildschirm zeigt auf "/" ohne Token (die Seite nimmt
                # ihn ja aus der Adresse heraus, bevor man "Zum
                # Home-Bildschirm" tippt), und einen Weg, ihn nachzureichen,
                # gab es in der Anzeige nicht.
                #
                # Die Seite selbst enthaelt keine Daten. Alles Inhaltliche
                # liegt hinter /api/ und bleibt ohne Token verschlossen.
                if self._authorized(allow_query_token=True):
                    self._send(200, INDEX_HTML.encode("utf-8"),
                               "text/html; charset=utf-8")
                    return
                # Die Seite ist 55 kB. Wer sie ohne Token anfordert und
                # dabei nicht nach HTML fragt, ist kein Browser, sondern
                # ein Scanner - der bekommt weiterhin die eine Zeile.
                # Jeder Browser schickt beim Oeffnen einer Adresse
                # "Accept: text/html", auch die App vom Startbildschirm.
                if "text/html" not in (self.headers.get("Accept") or ""):
                    self._send(401, b"Token fehlt oder ist falsch.\n",
                               "text/plain; charset=utf-8")
                    return
                self._send(401, INDEX_HTML.encode("utf-8"),
                           "text/html; charset=utf-8")
                return

            # Symbol und Beschreibung fuer den Startbildschirm. Bewusst
            # ohne Token: Safari holt beides beim "Zum Home-Bildschirm"
            # ohne die Kopfzeile mitzuschicken, und es steht nichts darin,
            # was jemanden etwas anginge.
            if route == "/apple-touch-icon.png":
                self._send(200, apple_touch_icon(), "image/png",
                           {"Cache-Control": "public, max-age=86400"})
                return
            if route == "/manifest.webmanifest":
                self._send(200, MANIFEST.encode("utf-8"),
                           "application/manifest+json; charset=utf-8",
                           {"Cache-Control": "public, max-age=86400"})
                return

            if not route.startswith("/api/"):
                self._json(404, {"error": "not_found"})
                return
            if not self._authorized(allow_query_token=False):
                self._json(401, {"error": "unauthorized"})
                return

            params = _query(self.path)
            if route == "/api/session":
                # Der kleinste Aufruf, der einen Token verlangt. Der
                # Anmeldebildschirm prueft damit eine Eingabe, ohne die
                # ganze Lage zu laden; die App erkennt daran ausserdem,
                # ob ueberhaupt ein Token noetig ist (auf localhost nicht).
                self._json(200, {
                    "ok": True,
                    "version": __version__,
                    "mutations": config.allow_mutations,
                    "token_required": token_required,
                })
            elif route == "/api/summary":
                self._json(200, self._summary(params))
            elif route == "/api/attempts":
                self._json(200, self._attempts(params))
            elif route == "/api/blocks":
                now = guard.clock()
                self._json(200, {
                    "blocks": [b.as_dict(now) for b in guard.store.list_blocks(limit=200)],
                    "now": now,
                })
            elif route == "/api/anomalies":
                self._json(200, self._anomalies(params))
            elif route == "/api/files":
                self._json(200, self._files())
            elif route == "/api/allowlist":
                self._json(200, {"allowlist": guard.store.allow_list()})
            else:
                self._json(404, {"error": "not_found"})

        def do_HEAD(self):  # noqa: N802
            self.do_GET()

        def do_POST(self):  # noqa: N802
            route = urlparse(self.path).path
            if not self._authorized(allow_query_token=False):
                self._json(401, {"error": "unauthorized"})
                return
            if not config.allow_mutations:
                self._json(403, {"error": "mutations_disabled"})
                return

            data, error = self._read_json()
            if error:
                self._json(400, {"error": error})
                return

            try:
                if route == "/api/block":
                    self._json(200, self._block(data))
                elif route == "/api/unblock":
                    ip = str(data.get("ip", "")).strip()
                    self._json(200, {"ok": guard.unblock(ip), "ip": ip})
                elif route == "/api/allow":
                    cidr = str(data.get("cidr", "")).strip()
                    guard.allow(cidr, str(data.get("note", ""))[:200])
                    self._json(200, {"ok": True, "cidr": cidr})
                elif route == "/api/allow/remove":
                    cidr = str(data.get("cidr", "")).strip()
                    self._json(200, {"ok": guard.disallow(cidr), "cidr": cidr})
                elif route == "/api/maintenance":
                    self._json(200, guard.maintenance())
                else:
                    self._json(404, {"error": "not_found"})
            except ValueError as exc:
                self._json(400, {"error": str(exc)})

        # -- Datenaufbereitung ----------------------------------------
        def _summary(self, params) -> dict:
            hours = _float(params.get("hours", ["24"])[0], 24.0, 0.1, 24 * 365)
            now = guard.clock()
            since = now - hours * 3600
            stats = guard.store.stats(since, now=now)
            return {
                "version": __version__,
                "now": now,
                "hours": hours,
                "refresh_seconds": config.refresh_seconds,
                "mutations": config.allow_mutations,
                "stats": stats,
                "top_offenders": guard.store.top_offenders(since, limit=10),
                "timeline": guard.store.failure_timeline(since, buckets=32, now=now),
                "blocks": [
                    b.as_dict(now) for b in guard.store.list_blocks(limit=50, now=now)
                ],
                "allowlist": guard.store.allow_list(),
                "anomaly": self._anomalies({"hours": ["1"]}),
            }

        def _anomalies(self, params) -> dict:
            hours = _float(params.get("hours", ["1"])[0], 1.0, 0.1, 168)
            status = guard.anomaly.status()
            if not status.get("ready"):
                return {"ready": False, "reason": status.get("reason", ""),
                        "reports": []}
            berichte = guard.anomaly.cached_scan(window=hours * 3600)
            gesamt = guard.anomaly.global_report(window=hours * 3600)
            return {
                "ready": True,
                "baseline": status,
                "global": gesamt.as_dict() if gesamt.signals else None,
                "reports": [r.as_dict() for r in berichte],
            }

        def _files(self) -> dict:
            """Zustand der Dateipruefung: Grundlage, letzter Befund, Quarantaene.

            Bisher landeten diese Ergebnisse nur im Protokoll. Wer das
            Dashboard benutzt, sah von der ganzen Dateipruefung nichts -
            also ausgerechnet vom deutlichsten Hinweis darauf, dass jemand
            schon im Haus ist.
            """
            status = guard.integrity.status()
            bericht = guard.last_integrity
            try:
                quarantaene = guard.quarantine.list()
            except OSError:      # pragma: no cover - Rechte
                quarantaene = []

            return {
                "malware_enabled": bool(guard.config.malware.enabled),
                "scan_uploads": bool(guard.config.malware.scan_uploads),
                "clamav": guard.filescan.clamav_binary() or "",
                "action": guard.config.malware.action,
                "integrity": {
                    "enabled": bool(guard.config.integrity.enabled),
                    "ready": bool(status.get("ready")),
                    "reason": status.get("reason", ""),
                    "files": status.get("files", 0),
                    "paths": status.get("paths", []),
                    "interval": guard.config.integrity.check_interval,
                },
                "last_report": bericht.as_dict() if bericht is not None else None,
                "quarantine": [
                    {"id": eintrag.get("id", ""),
                     "original": eintrag.get("original", ""),
                     "ts": eintrag.get("quarantined_ts", 0),
                     "summary": (eintrag.get("result") or {}).get("summary", "")}
                    for eintrag in quarantaene[:50]
                ],
            }

        def _attempts(self, params) -> dict:
            limit = int(_float(params.get("limit", ["100"])[0], 100, 1, 1000))
            event = params.get("event", [""])[0]
            valid = {Event.LOGIN_FAILURE, Event.LOGIN_SUCCESS, Event.DENIED, Event.REQUEST}
            events = [event] if event in valid else None
            attempts = guard.store.recent_attempts(limit=limit, events=events)
            return {"attempts": [a.as_dict() for a in attempts], "now": guard.clock()}

        def _block(self, data: dict) -> dict:
            ip = str(data.get("ip", "")).strip()
            minutes = _float(data.get("minutes", 60), 60.0, 1, 60 * 24 * 365)
            reason = str(data.get("reason", "manual"))[:100]
            block = guard.block(ip, seconds=minutes * 60, reason=reason or "manual")
            return {"ok": True, "block": block.as_dict(guard.clock())}

    return Handler


def _query(path: str) -> dict:
    return parse_qs(urlparse(path).query)


def _float(value, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(number, low), high)


class Dashboard:
    """Startet und stoppt den Dashboard-Server."""

    def __init__(self, guard: Guard, config: Optional[DashboardConfig] = None) -> None:
        self.guard = guard
        self.config = config or DashboardConfig()
        self.config.validate()
        handler = _handler_factory(guard, self.config)
        self.httpd = ThreadingHTTPServer((self.config.host, self.config.port), handler)
        self.httpd.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        host = self.config.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        base = f"http://{host}:{self.port}/"
        return base + (f"?token={self.config.token}" if self.config.token else "")

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


INDEX_HTML = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<!-- viewport-fit=cover: Ohne das bleiben auf dem iPhone links und rechts
     graue Balken neben der Kamera-Aussparung. Die Seite haelt dafuer
     selbst Abstand (siehe env(safe-area-inset-*) weiter unten). -->
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#171b21" media="(prefers-color-scheme: dark)">
<!-- Zum Home-Bildschirm hinzufuegen: eigenes Symbol statt Bildschirmfoto,
     Start ohne Safari-Leisten. iOS liest die apple-Angaben, Android das
     Manifest - deshalb beides. -->
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="LoginShield">
<meta name="format-detection" content="telephone=no">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="icon" href="apple-touch-icon.png" type="image/png">
<link rel="manifest" href="manifest.webmanifest">
<title>LoginShield</title>
<style>
:root {
  --bg:#f6f7f9; --panel:#ffffff; --line:#e3e6ea; --text:#1b1f24; --muted:#5c6672;
  --accent:#2f6feb; --danger:#c8332e; --ok:#1f8a4c; --warn:#b7791f; --bar:#2f6feb;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#0f1216; --panel:#171b21; --line:#262c34; --text:#e7eaee; --muted:#98a2ae;
    --accent:#5a8dff; --danger:#f0665f; --ok:#4cc57f; --warn:#e0a94a; --bar:#5a8dff;
  }
}
* { box-sizing:border-box; }
html { -webkit-text-size-adjust:100%; text-size-adjust:100%; }
body { margin:0; background:var(--bg); color:var(--text);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-tap-highlight-color:rgba(47,111,235,.15);
  /* Kein Querscrollen der ganzen Seite: Breites (Tabellen) scrollt in
     seinem eigenen Kasten, nicht das Dokument. */
  overflow-x:hidden; }
header { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between;
  padding:16px 20px; border-bottom:1px solid var(--line); background:var(--panel);
  /* Auf dem iPhone im Vollbild liegt hier sonst die Uhr/Aussparung. */
  padding-top:calc(16px + env(safe-area-inset-top));
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right)); }
h1 { font-size:17px; margin:0; letter-spacing:-.01em; }
h1 span { color:var(--muted); font-weight:400; font-size:13px; margin-left:8px; }
main { padding:20px; max-width:1200px; margin:0 auto;
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right));
  padding-bottom:calc(20px + env(safe-area-inset-bottom)); }
.cards { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.card .value { font-size:28px; font-weight:600; margin-top:4px; font-variant-numeric:tabular-nums; }
.card.danger .value { color:var(--danger); }
.card.ok .value { color:var(--ok); }
.card.warn .value { color:var(--warn); }
section { background:var(--panel); border:1px solid var(--line); border-radius:10px;
  margin-top:16px; overflow:hidden; }
section > h2 { font-size:14px; margin:0; padding:12px 16px; border-bottom:1px solid var(--line);
  color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
.body { padding:12px 16px; overflow-x:auto; -webkit-overflow-scrolling:touch; }
.body.scroll { max-height:520px; overflow-y:auto; }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
th { text-align:left; color:var(--muted); font-weight:500; padding:6px 10px 6px 0;
  border-bottom:1px solid var(--line); white-space:nowrap; }
td { padding:7px 10px 7px 0; border-bottom:1px solid var(--line); white-space:nowrap;
  font-variant-numeric:tabular-nums; }
tr:last-child td { border-bottom:none; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
td.wrap { white-space:normal; word-break:break-all; min-width:12ch; }
/* Fliesstext in einer Tabelle darf umbrechen. Ohne das schiebt die
   Begruendung einer Sperre ("12 Fehlversuche in 300s") die Schaltflaeche
   zum Entsperren aus dem Bild, sobald die Tabelle in einer Spalte steht -
   also genau auf dem iPad im Querformat. */
td.satz { white-space:normal; min-width:14ch; }
.klein { font-size:11px; }
.tag { display:inline-block; padding:1px 7px; border-radius:20px; font-size:12px;
  border:1px solid var(--line); color:var(--muted); }
.tag.fail { color:var(--danger); border-color:var(--danger); }
.tag.ok { color:var(--ok); border-color:var(--ok); }
.tag.deny { color:var(--warn); border-color:var(--warn); }
.tag.trap { color:#fff; background:var(--warn); border-color:var(--warn); }
.tag.net { color:#fff; background:var(--danger); border-color:var(--danger); }
button { font:inherit; font-size:13px; padding:4px 11px; border-radius:6px; cursor:pointer;
  border:1px solid var(--line); background:transparent; color:var(--text); }
button:hover { border-color:var(--accent); color:var(--accent); }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
button.primary:hover { opacity:.9; color:#fff; }
input, select { font:inherit; font-size:13px; padding:5px 9px; border-radius:6px;
  border:1px solid var(--line); background:var(--bg); color:var(--text); }
.chart { display:flex; align-items:flex-end; gap:3px; height:110px; }
.chart div { flex:1; background:var(--bar); border-radius:2px 2px 0 0; min-height:2px; opacity:.85; }
.chart div.empty { background:var(--line); }
.row { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
.muted { color:var(--muted); }
.empty-state { color:var(--muted); padding:6px 0; }
#toast { position:fixed; right:16px; background:var(--panel); color:var(--text);
  border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:8px;
  padding:10px 14px; box-shadow:0 6px 24px rgba(0,0,0,.18); display:none; max-width:min(90vw,420px);
  /* Ueber dem Streifen der Home-Taste, nicht darunter. */
  bottom:calc(16px + env(safe-area-inset-bottom));
  right:calc(16px + env(safe-area-inset-right)); }

/* Ohne das gewinnt die Anzeigeart aus den Regeln unten gegen das
   hidden-Merkmal, und Verborgenes stuende trotzdem auf der Seite. */
[hidden] { display:none !important; }

/* ------------------------------------------------------------------
   Anmeldung
   ------------------------------------------------------------------
   Die App auf dem Startbildschirm startet auf "/" - ohne Token in der
   Adresse. Ohne diesen Bildschirm waere sie nach jedem Kaltstart tot.
   ------------------------------------------------------------------ */
#login { display:flex; justify-content:center; padding:32px 20px;
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right));
  padding-bottom:calc(32px + env(safe-area-inset-bottom)); }
.login-box { background:var(--panel); border:1px solid var(--line); border-radius:12px;
  padding:20px; width:min(420px,100%); display:flex; flex-direction:column; gap:12px; }
.login-box h2 { font-size:16px; margin:0; }
.login-box p { margin:0; font-size:13.5px; color:var(--muted); }
#login-token { width:100%; }
#login-error { color:var(--danger); font-size:13.5px; }
#login-error:empty { display:none; }

/* ------------------------------------------------------------------
   Verbindungsband
   ------------------------------------------------------------------
   Bleibt stehen, solange der Server nicht antwortet. Ein Hinweis, der
   nach vier Sekunden verschwindet, taugt dafuer nicht: Unterwegs ist
   "nicht erreichbar" der Normalfall und keine Ausnahme - das Tablet ist
   dann einfach nicht im selben Netz. Ohne dieses Band zeigt die App
   veraltete Zahlen, ohne dass es jemandem auffaellt.
   ------------------------------------------------------------------ */
#offline { display:flex; flex-wrap:wrap; gap:10px; align-items:center;
  justify-content:space-between; background:var(--danger); color:#fff;
  font-size:14px; padding:10px 20px;
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right)); }
#offline button { border-color:rgba(255,255,255,.6); color:#fff; }
#offline button:hover { border-color:#fff; color:#fff; }

/* ------------------------------------------------------------------
   Telefon und Tablet
   ------------------------------------------------------------------
   Zwei Dinge sind auf dem iPhone keine Geschmacksfrage:

   * Schaltflaechen unter 44 Punkten trifft man mit dem Daumen nicht
     zuverlaessig - das ist Apples eigene Mindestgroesse.
   * Ein Eingabefeld mit weniger als 16px Schrift laesst Safari beim
     Antippen in die Seite hineinzoomen, und man findet nicht mehr
     heraus. Deshalb hier ueberall genau 16px.
   ------------------------------------------------------------------ */
@media (max-width:760px) {
  header { padding:12px 14px; padding-top:calc(12px + env(safe-area-inset-top)); }
  h1 span { display:block; margin-left:0; }
  main { padding:14px; padding-bottom:calc(28px + env(safe-area-inset-bottom)); }
  .cards { grid-template-columns:repeat(auto-fit,minmax(132px,1fr)); gap:10px; }
  .card { padding:12px; }
  .card .value { font-size:24px; }
  section { margin-top:12px; }
  .body { padding:10px 12px; }
  table { font-size:14px; }
  button { font-size:15px; padding:10px 14px; min-height:44px; }
  input, select { font-size:16px; padding:9px 11px; min-height:44px; }
  .row { gap:10px; }
  .row > * { flex:1 1 auto; }
  #toast { left:calc(12px + env(safe-area-inset-left));
           right:calc(12px + env(safe-area-inset-right)); max-width:none; }
}

/* Wer keine genaue Zeigevorrichtung hat - also jedes Touchgeraet -
   bekommt die groesseren Ziele auch auf dem iPad im Querformat. Dort
   greift die Breitenabfrage oben naemlich nicht: Ein iPad Pro quer ist
   1194 Punkte breit, zoomt beim Antippen eines kleinen Feldes aber
   genauso hinein wie ein iPhone. */
@media (pointer:coarse) {
  button, input, select { min-height:44px; }
  button { font-size:15px; padding:10px 14px; }
  input, select { font-size:16px; padding:9px 11px; }
  th, td { padding-top:10px; padding-bottom:10px; }
}

/* Ein iPad im Querformat ist 1194 Punkte breit. Untereinander gestellt
   stehen dort schmale Tabellen in einer sehr breiten Flaeche, und die
   Ereignisse liegen drei Bildschirmhoehen tiefer. Paarweise nebeneinander
   passt die Lage aufs Bild, ohne dass etwas kleiner wird. */
@media (min-width:980px) {
  .paar { display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start; }
}
</style>
</head>
<body>
<header>
  <h1>LoginShield <span id="meta"></span></h1>
  <div class="row" id="kopf-bedienung" hidden>
    <select id="hours">
      <option value="1">Letzte Stunde</option>
      <option value="24" selected>Letzte 24 Stunden</option>
      <option value="168">Letzte 7 Tage</option>
      <option value="720">Letzte 30 Tage</option>
    </select>
    <button id="refresh">Aktualisieren</button>
    <button id="logout" hidden>Abmelden</button>
  </div>
</header>

<div id="offline" hidden role="status">
  <span>Keine Verbindung zum Server. Die Zahlen sind der letzte Stand.</span>
  <button id="offline-retry">Erneut versuchen</button>
</div>

<div id="login" hidden>
  <div class="login-box">
    <h2>Anmelden</h2>
    <p>Dieses Geraet braucht den Dashboard-Token einmalig. Er steht in der
       Konfiguration unter <span class="mono">dashboard.token</span> und
       bleibt danach auf dem Geraet gespeichert.</p>
    <!-- autocapitalize und autocorrect sind hier keine Feinheit: Safari
         schreibt sonst den ersten Buchstaben des Tokens gross und
         verbessert ihn unterwegs, und die Anmeldung scheitert an etwas,
         das auf dem Bildschirm richtig aussieht. -->
    <input id="login-token" type="password" placeholder="Token"
           autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false">
    <button class="primary" id="login-go">Anmelden</button>
    <div id="login-error" role="alert"></div>
  </div>
</div>

<main hidden>
  <div class="cards">
    <div class="card danger"><div class="label">Fehlversuche</div><div class="value" id="c-fail">-</div></div>
    <div class="card"><div class="label">Angreifende IPs</div><div class="value" id="c-ips">-</div></div>
    <div class="card danger"><div class="label">Aktive Sperren</div><div class="value" id="c-blocks">-</div></div>
    <div class="card warn"><div class="label">Honeypot-Treffer</div><div class="value" id="c-honeypot">-</div></div>
    <div class="card"><div class="label">Abgewiesen</div><div class="value" id="c-denied">-</div></div>
    <div class="card ok"><div class="label">Erfolgreiche Logins</div><div class="value" id="c-ok">-</div></div>
  </div>

  <section>
    <h2>Fehlversuche im Zeitverlauf</h2>
    <div class="body"><div class="chart" id="chart"></div>
      <div class="muted" style="font-size:12px;margin-top:6px" id="chart-range"></div></div>
  </section>

  <div class="paar">
  <section>
    <h2>Aktive Sperren</h2>
    <div class="body"><table id="blocks"><thead><tr>
      <th>IP</th><th>Grund</th><th>Rest</th><th>Stufe</th><th>Details</th><th></th>
    </tr></thead><tbody></tbody></table>
    <div class="empty-state" id="blocks-empty" hidden>Keine aktiven Sperren.</div></div>
  </section>

  <section>
    <h2>Auffaelligste IPs</h2>
    <div class="body"><table id="offenders"><thead><tr>
      <th>IP</th><th>Fehlversuche</th><th>Konten</th><th>Zuletzt</th><th></th>
    </tr></thead><tbody></tbody></table>
    <div class="empty-state" id="offenders-empty" hidden>Nichts Auffaelliges im Zeitraum.</div></div>
  </section>
  </div>

  <div class="paar">
  <section>
    <h2>Abweichungen vom Normalzustand</h2>
    <div class="body">
      <div class="muted" id="anomaly-note" style="font-size:13px"></div>
      <table id="anomalies" hidden><thead><tr>
        <th>IP</th><th>Bewertung</th><th>Begruendung</th><th></th>
      </tr></thead><tbody></tbody></table>
    </div>
  </section>

  <section>
    <h2>Dateien auf dem Server</h2>
    <div class="body">
      <div class="muted" id="files-note" style="font-size:13px"></div>
      <table id="files" hidden><thead><tr>
        <th>Art</th><th>Datei</th><th>Schwere</th><th>Bedeutung</th>
      </tr></thead><tbody></tbody></table>
      <div id="quarantine-note" class="muted" style="font-size:13px;margin-top:8px"></div>
    </div>
  </section>
  </div>

  <section>
    <h2>Letzte Ereignisse</h2>
    <div class="body scroll">
      <div class="row" style="margin-bottom:10px">
        <select id="event-filter">
          <option value="">Alle Ereignisse</option>
          <option value="login_failure">Nur Fehlversuche</option>
          <option value="login_success">Nur Erfolge</option>
          <option value="honeypot">Nur Honeypot-Treffer</option>
          <option value="denied">Nur abgewiesene</option>
        </select>
      </div>
      <table id="attempts"><thead><tr>
        <th>Zeit</th><th>Ereignis</th><th>IP</th><th>Konto</th><th>Pfad</th><th>Quelle</th><th>Details</th>
      </tr></thead><tbody></tbody></table>
      <div class="empty-state" id="attempts-empty" hidden>Noch keine Ereignisse aufgezeichnet.</div>
    </div>
  </section>

  <section>
    <h2>Allowlist &amp; manuelle Sperre</h2>
    <div class="body">
      <div class="row" style="margin-bottom:12px">
        <input id="allow-cidr" placeholder="z.B. 203.0.113.0/24" size="20">
        <input id="allow-note" placeholder="Notiz (optional)" size="20">
        <button class="primary" id="allow-add">Zur Allowlist</button>
        <span style="flex:1"></span>
        <input id="block-ip" placeholder="IP sperren" size="16">
        <input id="block-min" type="number" value="60" min="1" size="5" style="width:80px"> Min.
        <button id="block-add">Sperren</button>
      </div>
      <table id="allowlist"><thead><tr><th>Eintrag</th><th>Notiz</th><th></th></tr></thead><tbody></tbody></table>
      <div class="empty-state" id="allowlist-empty" hidden>Allowlist ist leer.</div>
    </div>
  </section>
</main>
<div id="toast"></div>

<script>
(function () {
  "use strict";

  var TOKEN_SCHLUESSEL = "ls_token";
  var timer = null;
  var intervall = 0;
  var angemeldet = false;

  // Token aus der URL holen und sofort aus der Adresszeile entfernen,
  // damit er nicht im Verlauf oder auf einem Bildschirmfoto landet.
  var params = new URLSearchParams(location.search);
  var url_token = params.get("token") || "";
  if (url_token) { history.replaceState({}, "", location.pathname); }

  // Der Token liegt in localStorage, nicht mehr in sessionStorage.
  //
  // Das ist der Unterschied zwischen einer Seite und einer App: iOS wirft
  // eine App vom Startbildschirm aus dem Speicher, sobald der Platz
  // knapp wird. Mit sessionStorage war der Token danach weg, und das
  // Symbol fuehrte auf eine Fehlermeldung - jedes Mal.
  //
  // Der Preis: Wer das entsperrte Tablet in die Hand bekommt, hat auch
  // den Token. Auf einem Geraet mit Code ist das derselbe Schutz wie fuer
  // alles andere darauf; wer ihn nicht will, meldet sich ab.
  function merken(wert) {
    try {
      if (wert) { localStorage.setItem(TOKEN_SCHLUESSEL, wert); }
      else { localStorage.removeItem(TOKEN_SCHLUESSEL); }
    } catch (fehler) {
      // Safari mit blockierten Website-Daten. Dann gilt der Token eben
      // nur, solange die App offen bleibt - das ist immer noch besser
      // als ein Abbruch an dieser Stelle.
    }
  }

  function gemerkt() {
    try {
      var alt = sessionStorage.getItem(TOKEN_SCHLUESSEL);
      if (alt) {
        // Umzug von frueher: einmal uebernehmen, dann aufraeumen.
        sessionStorage.removeItem(TOKEN_SCHLUESSEL);
        if (!localStorage.getItem(TOKEN_SCHLUESSEL)) {
          localStorage.setItem(TOKEN_SCHLUESSEL, alt);
        }
      }
      return localStorage.getItem(TOKEN_SCHLUESSEL) || "";
    } catch (fehler) {
      return "";
    }
  }

  var TOKEN = url_token || gemerkt();
  if (url_token) { merken(url_token); }

  function api(path, options) {
    options = options || {};
    options.headers = Object.assign({"X-Auth-Token": TOKEN}, options.headers || {});
    return fetch(path, options).then(function (response) {
      verbindung(true);
      if (response.status === 401) {
        var abgelehnt = new Error("Token fehlt oder ist falsch.");
        abgelehnt.unauthorized = true;
        throw abgelehnt;
      }
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      return response.json();
    }, function () {
      // fetch scheitert nur, wenn die Anfrage gar nicht erst ankommt:
      // Server aus, anderes Netz, Flugmodus. Ein Statuscode waere hier
      // schon eine Antwort gewesen.
      verbindung(false);
      var weg = new Error("Keine Verbindung zum Server.");
      weg.offline = true;
      throw weg;
    });
  }

  // -- Zustand der Anzeige --------------------------------------------

  function verbindung(erreichbar) {
    document.getElementById("offline").hidden = !!erreichbar;
  }

  function zeigeAnmeldung(meldung) {
    angemeldet = false;
    stopTimer();
    document.getElementById("login").hidden = false;
    document.querySelector("main").hidden = true;
    document.getElementById("kopf-bedienung").hidden = true;
    document.getElementById("login-error").textContent = meldung || "";
  }

  function zeigeApp(info) {
    angemeldet = true;
    document.getElementById("login").hidden = true;
    document.getElementById("login-error").textContent = "";
    document.querySelector("main").hidden = false;
    document.getElementById("kopf-bedienung").hidden = false;
    // Ohne Token gibt es nichts abzumelden (Dashboard nur auf localhost).
    document.getElementById("logout").hidden = !(info && info.token_required);
  }

  // Eine Stelle fuer alles, was schiefgehen kann: abgelaufener Token
  // zurueck zur Anmeldung, fehlende Verbindung sagt schon das Band,
  // alles andere als Einblendung.
  function melde(fehler) {
    if (fehler && fehler.unauthorized) {
      TOKEN = "";
      merken("");
      zeigeAnmeldung("Der Token gilt hier nicht. Bitte neu anmelden.");
      return;
    }
    if (fehler && fehler.offline) { return; }
    toast(fehler.message, true);
  }

  function stopTimer() {
    if (timer !== null) { clearInterval(timer); timer = null; }
  }

  // Im Hintergrund laeuft nichts weiter. iOS friert die App ohnehin ein;
  // ein Wecker, der jede halbe Minute Daten holt, kostet nur Strom -
  // gesehen hat sie in der Zeit niemand.
  function starteTimer() {
    stopTimer();
    if (intervall > 0 && angemeldet && !document.hidden) {
      timer = setInterval(load, intervall * 1000);
    }
  }

  function toast(message, isError) {
    var box = document.getElementById("toast");
    box.textContent = message;
    box.style.borderLeftColor = isError ? "var(--danger)" : "var(--ok)";
    box.style.display = "block";
    setTimeout(function () { box.style.display = "none"; }, 4000);
  }

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (className) { node.className = className; }
    return node;
  }

  function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleString("de-DE");
  }

  function fmtDuration(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    if (seconds < 60) { return seconds + " s"; }
    if (seconds < 3600) { return Math.round(seconds / 60) + " min"; }
    if (seconds < 86400) { return (seconds / 3600).toFixed(1) + " h"; }
    return (seconds / 86400).toFixed(1) + " Tage";
  }

  function fill(tableId, emptyId, rows, builder) {
    document.getElementById(emptyId).hidden = rows.length > 0;
    fillTable(tableId, rows, builder);
  }

  // Nur die Tabelle fuellen, ohne einen zweiten Text auszublenden. Wird
  // dort gebraucht, wo die Zeile darueber eine Zusammenfassung ist und
  // keine "nichts gefunden"-Meldung: Die soll gerade dann stehen bleiben,
  // wenn es etwas zu sehen gibt.
  function fillTable(tableId, rows, builder) {
    var body = document.querySelector("#" + tableId + " tbody");
    body.textContent = "";
    document.getElementById(tableId).hidden = rows.length === 0;
    rows.forEach(function (item) { body.appendChild(builder(item)); });
  }

  function actionButton(label, className, handler) {
    var button = el("button", label, className);
    button.addEventListener("click", handler);
    var cell = el("td");
    cell.appendChild(button);
    return cell;
  }

  function renderChart(timeline) {
    var chart = document.getElementById("chart");
    chart.textContent = "";
    var max = timeline.reduce(function (acc, bucket) {
      return Math.max(acc, bucket.failures + bucket.denied);
    }, 0);
    timeline.forEach(function (bucket) {
      var total = bucket.failures + bucket.denied;
      var bar = el("div", null, total === 0 ? "empty" : "");
      bar.style.height = max > 0 ? Math.max(2, (total / max) * 100) + "%" : "2px";
      bar.title = fmtTime(bucket.start) + " - " + total + " Ereignisse";
      chart.appendChild(bar);
    });
    if (timeline.length) {
      document.getElementById("chart-range").textContent =
        "Hoechster Balken: " + max + " Ereignisse";
    }
  }

  function renderSummary(data) {
    var stats = data.stats;
    document.getElementById("c-fail").textContent = stats.failures;
    document.getElementById("c-ips").textContent = stats.attacking_ips;
    document.getElementById("c-blocks").textContent = stats.active_blocks;
    document.getElementById("c-honeypot").textContent = stats.honeypot;
    document.getElementById("c-denied").textContent = stats.denied;
    document.getElementById("c-ok").textContent = stats.successes;
    document.getElementById("meta").textContent =
      "v" + data.version + " - Stand " + fmtTime(data.now);

    renderChart(data.timeline);

    fill("blocks", "blocks-empty", data.blocks, function (block) {
      var row = el("tr");
      // "satz": Die Marke "ganzes Netz" darf unter die Adresse rutschen.
      // Nebeneinander macht sie die Spalte 227 Punkte breit - in einer
      // von zwei Spalten auf dem iPad ist das ein Drittel der Tabelle.
      var target = el("td", null, "mono satz");
      target.appendChild(document.createTextNode(block.ip));
      if (block.is_network) {
        target.appendChild(document.createTextNode(" "));
        target.appendChild(el("span", "ganzes Netz", "tag net"));
      }
      row.appendChild(target);
      row.appendChild(el("td", block.reason));
      row.appendChild(el("td", fmtDuration(block.remaining)));
      row.appendChild(el("td", block.strikes));
      row.appendChild(el("td", block.detail, "muted satz"));
      row.appendChild(actionButton("Entsperren", "", function () {
        api("/api/unblock", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ip: block.ip})
        }).then(function () {
          toast(block.ip + " entsperrt.");
          load();
        }).catch(melde);
      }));
      return row;
    });

    fill("offenders", "offenders-empty", data.top_offenders, function (item) {
      var row = el("tr");
      row.appendChild(el("td", item.ip, "mono"));
      row.appendChild(el("td", item.failures));
      row.appendChild(el("td", item.identities));
      row.appendChild(el("td", fmtTime(item.last_seen)));
      row.appendChild(actionButton("Sperren", "", function () {
        api("/api/block", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ip: item.ip, minutes: 60, reason: "manual"})
        }).then(function () {
          toast(item.ip + " fuer 60 Minuten gesperrt.");
          load();
        }).catch(melde);
      }));
      return row;
    });

    renderAnomalies(data.anomaly);

    fill("allowlist", "allowlist-empty", data.allowlist, function (entry) {
      var row = el("tr");
      row.appendChild(el("td", entry.cidr, "mono"));
      row.appendChild(el("td", entry.note, "muted"));
      row.appendChild(actionButton("Entfernen", "", function () {
        api("/api/allow/remove", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({cidr: entry.cidr})
        }).then(function () { toast("Entfernt: " + entry.cidr); load(); })
          .catch(melde);
      }));
      return row;
    });
  }

  function renderAnomalies(data) {
    var note = document.getElementById("anomaly-note");
    var table = document.getElementById("anomalies");
    if (!data || !data.ready) {
      table.hidden = true;
      note.textContent = (data && data.reason) ||
        "Noch keine Grundlinie gelernt (loginshield learn).";
      return;
    }
    var gesamt = data["global"];
    if (!data.reports.length) {
      table.hidden = true;
      note.textContent = gesamt
        ? "Gesamtlage " + gesamt.score + "/100: " + gesamt.summary +
          " - keine einzelne Adresse faellt auf."
        : "Nichts Auffaelliges. Grundlinie: " + data.baseline.events +
          " Ereignisse von " + data.baseline.addresses + " Adressen.";
      return;
    }
    note.textContent = data.reports.length +
      " Adresse(n) weichen vom Normalzustand ab.";
    fillTable("anomalies", data.reports, function (item) {
      var row = el("tr");
      row.appendChild(el("td", item.ip, "mono"));
      var cell = el("td");
      cell.appendChild(el("span", item.score + "/100",
        "tag " + (item.verdict === "kritisch" ? "fail" : "deny")));
      row.appendChild(cell);
      row.appendChild(el("td", item.summary, "muted satz"));
      row.appendChild(actionButton("Sperren", "", function () {
        api("/api/block", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ip: item.ip, minutes: 60, reason: "anomaly"})
        }).then(function () { toast(item.ip + " gesperrt."); load(); })
          .catch(melde);
      }));
      return row;
    });
    table.hidden = false;
    note.textContent = data.reports.length +
      " Adresse(n) weichen vom Normalzustand ab.";
  }

  var TAGS = {
    login_failure: ["Fehlversuch", "tag fail"],
    login_success: ["Erfolg", "tag ok"],
    honeypot: ["Honeypot", "tag trap"],
    denied: ["Abgewiesen", "tag deny"],
    request: ["Request", "tag"]
  };

  function renderAttempts(data) {
    fill("attempts", "attempts-empty", data.attempts, function (item) {
      var row = el("tr");
      row.appendChild(el("td", fmtTime(item.ts)));
      var info = TAGS[item.event] || [item.event, "tag"];
      var cell = el("td");
      cell.appendChild(el("span", info[0], info[1]));
      row.appendChild(cell);
      row.appendChild(el("td", item.ip, "mono"));
      row.appendChild(el("td", item.identity || "-", "mono"));
      row.appendChild(el("td", item.route || "-"));
      row.appendChild(el("td", item.source, "muted"));
      row.appendChild(el("td", item.detail || "", "muted"));
      return row;
    });
  }

  function load() {
    var hours = document.getElementById("hours").value;
    var event = document.getElementById("event-filter").value;
    api("/api/summary?hours=" + encodeURIComponent(hours))
      .then(function (data) {
        renderSummary(data);
        intervall = data.refresh_seconds || 0;
        starteTimer();
      })
      .catch(melde);
    api("/api/attempts?limit=100&event=" + encodeURIComponent(event))
      .then(renderAttempts)
      .catch(melde);
    api("/api/files")
      .then(renderFiles)
      .catch(melde);
  }

  // Erster Aufruf und jeder Versuch danach: Erst fragen, ob der Token
  // hier gilt - daran haengt, ob die Anmeldung oder die Lage kommt.
  function start() {
    api("/api/session").then(function (info) {
      zeigeApp(info);
      load();
    }).catch(function (fehler) {
      if (fehler.unauthorized) {
        zeigeAnmeldung(TOKEN ? "Der Token gilt hier nicht. Bitte neu anmelden." : "");
        return;
      }
      // Kein Netz: Wer angemeldet ist, bleibt es. Ein Anmeldebildschirm
      // waere hier die falsche Auskunft - der Token ist ja in Ordnung.
      if (!TOKEN) { zeigeAnmeldung(""); }
      else { zeigeApp({token_required: true}); }
    });
  }

  function anmelden() {
    var feld = document.getElementById("login-token");
    var eingabe = feld.value.trim();
    if (!eingabe) { return; }
    var vorher = TOKEN;
    TOKEN = eingabe;
    api("/api/session").then(function (info) {
      merken(eingabe);
      feld.value = "";
      zeigeApp(info);
      load();
    }).catch(function (fehler) {
      TOKEN = vorher;
      document.getElementById("login-error").textContent = fehler.unauthorized
        ? "Dieser Token stimmt nicht."
        : fehler.message;
    });
  }

  function renderFiles(data) {
    var note = document.getElementById("files-note");
    var table = document.getElementById("files");
    var quarantaene = document.getElementById("quarantine-note");

    var teile = [];
    teile.push(data.malware_enabled
      ? "Dateipruefung aktiv" + (data.clamav ? " (mit ClamAV)" : "")
      : "Dateipruefung abgeschaltet");
    if (data.scan_uploads) { teile.push("Uploads werden geprueft"); }

    if (!data.integrity.enabled) {
      teile.push("Integritaetspruefung aus - eine abgelegte Webshell faellt nicht auf");
    } else if (!data.integrity.ready) {
      teile.push(data.integrity.reason || "keine Vergleichsgrundlage");
    } else {
      teile.push(data.integrity.files === 1
        ? "1 Datei wird ueberwacht"
        : data.integrity.files + " Dateien werden ueberwacht");
    }

    quarantaene.textContent = data.quarantine.length
      ? data.quarantine.length + " Datei(en) in Quarantaene. Zurueckholen: " +
        "loginshield quarantine --restore <ID>"
      : "";

    var bericht = data.last_report;
    if (!bericht || !bericht.changes || !bericht.changes.length) {
      table.hidden = true;
      if (bericht && !bericht.error) {
        teile.push("zuletzt geprueft: unveraendert");
      }
      note.textContent = teile.join(" - ") + ".";
      return;
    }

    note.textContent = bericht.changes.length + " Veraenderung(en), Bewertung " +
      bericht.verdict + ". " + teile.join(" - ") + ".";
    fillTable("files", bericht.changes, function (change) {
      var row = el("tr");
      var art = el("td");
      art.appendChild(el("span", change.kind,
        "tag " + (change.severity >= 9 ? "fail" : "deny")));
      row.appendChild(art);
      // Der Dateiname zuerst und gross, der Ordner klein darunter: Auf
      // dem Telefon draengt ein langer Pfad sonst alles Wichtige aus dem
      // Bild.
      var teile = change.path.split("/");
      var name = teile.pop();
      var zelle = el("td", null, "mono wrap");
      zelle.appendChild(el("div", name));
      if (teile.length) {
        var ordner = teile.join("/") + "/";
        // Sehr lange Pfade von links kuerzen - hinten steht das
        // Interessante (welches Verzeichnis), vorne nur /var/www/...
        if (ordner.length > 44) { ordner = "..." + ordner.slice(-44); }
        zelle.appendChild(el("div", ordner, "muted klein"));
      }
      row.appendChild(zelle);
      row.appendChild(el("td", String(change.severity)));
      // Auch das ist Fliesstext: ohne Umbruch steht in der schmalen
      // Spalte nur der Anfang, und der Rest liegt hinter dem Rand.
      row.appendChild(el("td", change.description, "muted satz"));
      return row;
    });
  }

  document.getElementById("login-go").addEventListener("click", anmelden);
  document.getElementById("login-token").addEventListener("keydown", function (ereignis) {
    // Auf dem iPad steht dort "Return" - das soll anmelden, nicht nichts tun.
    if (ereignis.key === "Enter") { anmelden(); }
  });

  document.getElementById("logout").addEventListener("click", function () {
    TOKEN = "";
    merken("");
    document.getElementById("login-token").value = "";
    zeigeAnmeldung("Abgemeldet.");
  });

  document.getElementById("offline-retry").addEventListener("click", function () {
    if (angemeldet) { load(); } else { start(); }
  });

  // Zurueck aus dem Hintergrund: Die App war eingefroren, die Zahlen auf
  // dem Bildschirm sind so alt wie der letzte Blick. Also sofort neu
  // laden, statt bis zum naechsten Wecker veraltete Werte zu zeigen.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { stopTimer(); return; }
    if (angemeldet) { load(); starteTimer(); }
  });

  document.getElementById("refresh").addEventListener("click", load);
  document.getElementById("hours").addEventListener("change", load);
  document.getElementById("event-filter").addEventListener("change", load);

  document.getElementById("allow-add").addEventListener("click", function () {
    var cidr = document.getElementById("allow-cidr").value.trim();
    if (!cidr) { return; }
    api("/api/allow", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({cidr: cidr, note: document.getElementById("allow-note").value})
    }).then(function () {
      document.getElementById("allow-cidr").value = "";
      document.getElementById("allow-note").value = "";
      toast("Zur Allowlist hinzugefuegt: " + cidr);
      load();
    }).catch(melde);
  });

  document.getElementById("block-add").addEventListener("click", function () {
    var ip = document.getElementById("block-ip").value.trim();
    if (!ip) { return; }
    api("/api/block", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        ip: ip,
        minutes: Number(document.getElementById("block-min").value) || 60,
        reason: "manual"
      })
    }).then(function () {
      document.getElementById("block-ip").value = "";
      toast(ip + " gesperrt.");
      load();
    }).catch(melde);
  });

  start();
})();
</script>
</body>
</html>
"""


# ----------------------------------------------------------------------
# Vorschau: dieselbe Seite als einzelne Datei
# ----------------------------------------------------------------------
# Keine Nachbildung, sondern das Original: Es wird nur der Server
# ausgetauscht, den es dabei nicht gibt. ``window.fetch`` beantwortet die
# Aufrufe unter /api/ aus einer erfundenen Lage im Speicher. Alles davor
# - Anmeldung, Token auf dem Geraet, Verbindungsband, Neuladen aus dem
# Hintergrund, die zwei Spalten im Querformat - ist derselbe Code, der
# auch auf dem Server ausgeliefert wird.
#
# Damit kann eine Vorschau nicht anders aussehen als die Anwendung: Sie
# ist die Anwendung.
#
# Neu erzeugen nach jeder Aenderung an der Seite:
#
#     python -c "from loginshield.dashboard import preview_html; \
#                open('docs/ipad.html','w').write(preview_html())"
#
# ``tests/test_dashboard.py`` prueft, dass die Datei aktuell ist.

#: Der Token, den die Vorschau annimmt. Steht sichtbar auf der Seite.
PREVIEW_TOKEN = "vorschau"

_PREVIEW_STYLE = """
/* --- nur in der Vorschau ------------------------------------------ */
#vorfuehrung { display:flex; flex-wrap:wrap; gap:10px; align-items:center;
  justify-content:space-between; background:var(--panel); color:var(--muted);
  border-bottom:1px dashed var(--line); font-size:13px; padding:10px 20px;
  padding-top:calc(10px + env(safe-area-inset-top));
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right)); }
#vorfuehrung b { color:var(--text); }
#vorfuehrung code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:var(--bg); border:1px solid var(--line); border-radius:5px;
  padding:1px 6px; color:var(--text); }
#vorfuehrung .row { gap:8px; }
/* Der Kopf der Anwendung haelt jetzt keinen Abstand mehr nach oben:
   Darueber steht dieser Streifen, nicht die Uhr des iPads. */
#vorfuehrung + header { padding-top:16px; }
.erklaerung { max-width:760px; margin:0 auto; padding:8px 20px 40px;
  padding-left:calc(20px + env(safe-area-inset-left));
  padding-right:calc(20px + env(safe-area-inset-right));
  padding-bottom:calc(40px + env(safe-area-inset-bottom));
  color:var(--muted); font-size:14px; }
.erklaerung h2 { color:var(--text); font-size:15px; margin:24px 0 8px; }
.erklaerung p { margin:0 0 10px; }
.erklaerung ul { margin:0 0 10px; padding-left:20px; }
.erklaerung li { margin-bottom:6px; }
.erklaerung strong { color:var(--text); }
@media (max-width:760px) {
  #vorfuehrung { padding:10px 14px; padding-top:calc(10px + env(safe-area-inset-top)); }
  #vorfuehrung + header { padding-top:12px; }
  .erklaerung { padding-left:14px; padding-right:14px; }
}
"""

_PREVIEW_BANNER = """<div id="vorfuehrung">
  <span><b>Vorschau.</b> Erfundene Daten, kein Server. Token: <code>vorschau</code></span>
  <span class="row">
    <button id="v-angriff" type="button">Angriff ausloesen</button>
    <button id="v-netz" type="button">Netz weg</button>
    <button id="v-neustart" type="button">App neu starten</button>
    <button id="v-vergessen" type="button">Alles vergessen</button>
  </span>
</div>
"""

_PREVIEW_FOOTER = """<div class="erklaerung">
  <h2>Was hier gerade passiert</h2>
  <p>Das ist nicht das Bild einer Anwendung, sondern die Anwendung. Es
     fehlt nur der Server: Die Seite fragt wie immer unter <code>/api/</code>
     nach, und geantwortet wird ihr aus einer erfundenen Lage im
     Speicher dieses Browsers. Alles andere ist derselbe Code, der auf
     dem Server ausgeliefert wird.</p>

  <h2>Wie der Schutz aufgebaut ist</h2>
  <p>Die Arbeit macht ein Dienst auf dem Server, den LoginShield schuetzt
     - nicht das Tablet. Er zaehlt Fehlversuche, faellt jemand auf einen
     Koederpfad herein, sperrt die Adresse mit ansteigender Dauer und
     schreibt jedes Ereignis in eine Datenbank. Diese Seite liest sie und
     darf Sperren aufheben.</p>
  <ul>
    <li><strong>Anmeldung.</strong> Ohne Token kommt genau diese Seite mit
        Status 401 und fragt nach ihm. Sie enthaelt keine Daten - die
        liegen hinter <code>/api/</code>.</li>
    <li><strong>Der Token bleibt auf dem Geraet</strong> (in
        <code>localStorage</code>) und ueberlebt damit, dass iOS die App
        aus dem Speicher wirft. <em>App neu starten</em> oben fuehrt das
        vor: Es geht ohne Nachfrage weiter. <em>Alles vergessen</em>
        loescht ihn, dann ist wieder der erste Start.</li>
    <li><strong>Aendernde Aufrufe</strong> - sperren, entsperren, Allowlist -
        schicken den Token in der Kopfzeile <code>X-Auth-Token</code>, nie
        in der Adresse. Eine fremde Seite kann diese Kopfzeile nicht
        setzen; damit ist CSRF ausgeschlossen.</li>
    <li><strong>Ohne Verbindung</strong> bleibt der letzte Stand stehen,
        aber ein rotes Band sagt, dass er alt ist. <em>Netz weg</em> zeigt
        es.</li>
    <li><strong>Im Hintergrund</strong> fragt die App nichts ab; kommt sie
        nach vorn, laedt sie sofort neu.</li>
  </ul>

  <h2>Was hier anders ist als in der frueheren Vorschau</h2>
  <p>Die aeltere Vorschau (<code>demo.html</code>) zeigt den <em>Angriff</em>:
     Man loest Brute-Force, Password-Spraying oder einen Honeypot-Scan aus
     und sieht zu, wie die Sperre zuschnappt. Sie ist von Hand gebaut und
     ahmt die Oberflaeche nach.</p>
  <p>Diese hier zeigt die <em>App auf dem iPad</em> und ist aus dem
     Programm selbst erzeugt. Deshalb kann sie zeigen, was eine Nachbildung
     nicht zeigen koennte: den Anmeldebildschirm, den Kaltstart, das
     Verbindungsband, die zwei Spalten im Querformat.</p>

  <h2>Auf dem iPad ablegen</h2>
  <p>In Safari <em>Teilen &rarr; Zum Home-Bildschirm</em>. Die Vorschau
     startet dann ohne Browserleisten, mit eigenem Symbol - wie die
     richtige App. Nur schuetzt sie nichts: Keine App auf einem iPad kann
     das iPad schuetzen, und diese hier haengt an keinem Server. Sie ist
     zum Ansehen da.</p>
</div>
"""

_PREVIEW_SCRIPT = """<script>
/* Der Server, den es hier nicht gibt.
 *
 * Beantwortet die Aufrufe unter /api/ aus einer erfundenen Lage im
 * Speicher. Laeuft vor dem Skript der Anwendung, damit die es schon
 * vorfindet - die Anwendung selbst weiss von alldem nichts.
 */
(function () {
  "use strict";

  var TOKEN = "__TOKEN__";
  var VERSION = "__VERSION__";
  var erreichbar = true;

  // -- Die erfundene Lage ----------------------------------------------
  var n0 = Math.floor(Date.now() / 1000);
  var konten = ["user:a2935c74e1", "user:55579b5578", "user:c31f0ab992"];
  var ereignisse = [];
  var allowlist = [
    {cidr: "127.0.0.1", note: "localhost"},
    {cidr: "192.168.1.0/24", note: "eigenes Netz"}
  ];
  var sperren = [
    {ip: "203.0.113.0/24", is_network: true, reason: "subnet_abuse", strikes: 0,
     detail: "4 gesperrte Adressen in 3600s", bis: n0 + 6 * 3600},
    {ip: "203.0.113.7", is_network: false, reason: "brute_force_ip", strikes: 2,
     detail: "24 Fehlversuche in 300s", bis: n0 + 28 * 60},
    {ip: "198.51.100.23", is_network: false, reason: "honeypot", strikes: 1,
     detail: "Koederpfad /wp-admin.php", bis: n0 + 5 * 3600 + 54 * 60}
  ];

  function ereignis(vorher, art, ip, konto, pfad, quelle, text) {
    ereignisse.push({ts: n0 - vorher, event: art, ip: ip, identity: konto || "",
                     route: pfad || "", source: quelle, detail: text || ""});
  }

  var i;
  // Ein Durchprobieren, das gerade eben zur Sperre gefuehrt hat.
  for (i = 0; i < 24; i++) {
    ereignis(60 + i * 28, "login_failure", "203.0.113.7", konten[i % 3],
             "/login", "app", "");
  }
  // Password Spraying: viele Konten, je ein Versuch, langsam.
  for (i = 0; i < 9; i++) {
    ereignis(900 + i * 260, "login_failure", "203.0.113.19",
             "user:" + (813 + i * 137), "/login", "app", "");
  }
  // Wer auf einen Koederpfad hereinfaellt, sucht nicht nach dem Login.
  var koeder = ["/wp-admin.php", "/.env", "/phpmyadmin/"];
  for (i = 0; i < 3; i++) {
    ereignis(300 + i * 90, "honeypot", "198.51.100.23", "", koeder[i],
             "honeypot", "Koederpfad");
  }
  for (i = 0; i < 6; i++) {
    ereignis(120 + i * 30, "denied", "198.51.100.23", "", "/login",
             "middleware", "gesperrt");
  }
  // Aelter als 24 Stunden: sichtbar erst im Blick auf sieben Tage.
  for (i = 0; i < 14; i++) {
    ereignis(2 * 86400 + i * 400, "login_failure", "192.0.2.44",
             konten[i % 3], "/login", "app", "");
  }
  // Und der Normalfall, damit die Zahlen nicht nur aus Angriff bestehen.
  for (i = 0; i < 6; i++) {
    ereignis(3600 * (7 + i * 11), "login_success", "192.168.1.24", konten[0],
             "/login", "app", "");
  }

  function jetzt() { return Math.floor(Date.now() / 1000); }

  function offeneSperren() {
    var n = jetzt();
    return sperren.filter(function (s) { return s.bis > n; })
      .map(function (s) {
        return {ip: s.ip, is_network: s.is_network, reason: s.reason,
                strikes: s.strikes, detail: s.detail, active: true,
                remaining: s.bis - n};
      });
  }

  function seitDann(seit) {
    return ereignisse.filter(function (e) { return e.ts >= seit; });
  }

  function auffaellige(seit) {
    var proAdresse = {};
    seitDann(seit).forEach(function (e) {
      if (e.event !== "login_failure") { return; }
      var eintrag = proAdresse[e.ip];
      if (!eintrag) {
        eintrag = proAdresse[e.ip] = {failures: 0, konten: {}, last_seen: 0};
      }
      eintrag.failures += 1;
      if (e.identity) { eintrag.konten[e.identity] = true; }
      if (e.ts > eintrag.last_seen) { eintrag.last_seen = e.ts; }
    });
    return Object.keys(proAdresse).map(function (ip) {
      var e = proAdresse[ip];
      return {ip: ip, failures: e.failures,
              identities: Object.keys(e.konten).length,
              last_seen: e.last_seen};
    }).sort(function (a, b) { return b.failures - a.failures; }).slice(0, 10);
  }

  function verlauf(seit, n) {
    var eimer = [];
    var breite = (n - seit) / 32;
    for (var k = 0; k < 32; k++) {
      var start = seit + k * breite;
      var ende = start + breite;
      var drin = ereignisse.filter(function (e) {
        return e.ts >= start && e.ts < ende;
      });
      eimer.push({
        start: Math.round(start),
        failures: drin.filter(function (e) { return e.event === "login_failure"; }).length,
        denied: drin.filter(function (e) { return e.event === "denied"; }).length
      });
    }
    return eimer;
  }

  function zaehle(liste, art) {
    return liste.filter(function (e) { return e.event === art; }).length;
  }

  function zusammenfassung(stunden) {
    var n = jetzt();
    var seit = n - stunden * 3600;
    var teil = seitDann(seit);
    var adressen = {};
    teil.forEach(function (e) {
      if (e.event === "login_failure") { adressen[e.ip] = true; }
    });
    return {
      version: VERSION, now: n, hours: stunden, refresh_seconds: 20,
      mutations: true,
      stats: {
        failures: zaehle(teil, "login_failure"),
        attacking_ips: Object.keys(adressen).length,
        active_blocks: offeneSperren().length,
        honeypot: zaehle(teil, "honeypot"),
        denied: zaehle(teil, "denied"),
        successes: zaehle(teil, "login_success")
      },
      top_offenders: auffaellige(seit),
      timeline: verlauf(seit, n),
      blocks: offeneSperren(),
      allowlist: allowlist,
      anomaly: {
        ready: true,
        baseline: {events: 4812, addresses: 96},
        "global": {score: 34, summary: "erhoehte Fehlerquote, sonst wie sonst"},
        reports: [{
          ip: "203.0.113.19", score: 71, verdict: "kritisch",
          summary: "9 Konten in 40 Minuten, Adresse nie zuvor gesehen, kein Erfolg"
        }]
      }
    };
  }

  function dateien() {
    return {
      malware_enabled: true, scan_uploads: true, action: "quarantine",
      clamav: "/usr/bin/clamscan",
      integrity: {enabled: true, ready: true, reason: "", files: 1284,
                  paths: ["/var/www"], interval: 900},
      last_report: {
        verdict: "kritisch",
        changes: [
          {kind: "neu", severity: 10,
           path: "/var/www/html/wp-content/uploads/2026/09/th.php",
           description: "PHP im Upload-Ordner, fuehrt uebergebenen Text aus"},
          {kind: "geaendert", severity: 6, path: "/var/www/html/index.php",
           description: "Inhalt weicht von der Grundlage ab"}
        ]
      },
      quarantine: [{id: "q-8fa1", ts: n0 - 400, summary: "Webshell",
                    original: "/var/www/html/wp-content/uploads/2026/09/th.php"}]
    };
  }

  // -- Aendernde Aufrufe -----------------------------------------------
  function sperre(daten) {
    var ip = String(daten.ip || "").trim();
    if (!ip) { return {error: "IP fehlt"}; }
    sperren = sperren.filter(function (s) { return s.ip !== ip; });
    sperren.push({ip: ip, is_network: ip.indexOf("/") > -1,
                  reason: String(daten.reason || "manual"), strikes: 1,
                  detail: "von Hand gesperrt",
                  bis: jetzt() + (Number(daten.minutes) || 60) * 60});
    return {ok: true};
  }

  function entsperre(daten) {
    var ip = String(daten.ip || "").trim();
    var vorher = sperren.length;
    sperren = sperren.filter(function (s) { return s.ip !== ip; });
    return {ok: sperren.length < vorher, ip: ip};
  }

  function erlaube(daten) {
    var cidr = String(daten.cidr || "").trim();
    var bekannt = allowlist.some(function (e) { return e.cidr === cidr; });
    if (cidr && !bekannt) {
      allowlist.push({cidr: cidr, note: String(daten.note || "")});
    }
    return {ok: true, cidr: cidr};
  }

  function entferne(daten) {
    var cidr = String(daten.cidr || "").trim();
    var vorher = allowlist.length;
    allowlist = allowlist.filter(function (e) { return e.cidr !== cidr; });
    return {ok: allowlist.length < vorher, cidr: cidr};
  }

  // -- Der vorgetaeuschte Server ---------------------------------------
  function frage(adresse, name, standard) {
    var teil = String(adresse).split("?")[1] || "";
    var wert = new URLSearchParams(teil).get(name);
    return wert === null ? standard : wert;
  }

  function antwort(status, daten) {
    return {
      status: status,
      ok: status >= 200 && status < 300,
      json: function () { return Promise.resolve(daten); }
    };
  }

  function ergebnis(weg, adresse, daten) {
    if (weg === "/api/session") {
      return {ok: true, version: VERSION, mutations: true, token_required: true};
    }
    if (weg === "/api/summary") {
      return zusammenfassung(Number(frage(adresse, "hours", "24")) || 24);
    }
    if (weg === "/api/attempts") {
      var art = frage(adresse, "event", "");
      var liste = ereignisse.slice().sort(function (a, b) { return b.ts - a.ts; });
      if (art) {
        liste = liste.filter(function (e) { return e.event === art; });
      }
      return {attempts: liste.slice(0, 100), now: jetzt()};
    }
    if (weg === "/api/files") { return dateien(); }
    if (weg === "/api/block") { return sperre(daten); }
    if (weg === "/api/unblock") { return entsperre(daten); }
    if (weg === "/api/allow") { return erlaube(daten); }
    if (weg === "/api/allow/remove") { return entferne(daten); }
    return {error: "not_found"};
  }

  window.fetch = function (adresse, optionen) {
    optionen = optionen || {};
    var kopf = (optionen.headers || {})["X-Auth-Token"] || "";
    var weg = String(adresse).split("?")[0];
    var daten = {};
    try { daten = JSON.parse(optionen.body || "{}"); } catch (e) { daten = {}; }
    return new Promise(function (erfuellen, ablehnen) {
      // Etwas Verzoegerung, damit es sich anfuehlt wie ein Netz.
      setTimeout(function () {
        if (!erreichbar) {
          // So scheitert fetch wirklich: kein Statuscode, keine Antwort.
          ablehnen(new TypeError("Failed to fetch"));
          return;
        }
        if (kopf !== TOKEN) {
          erfuellen(antwort(401, {error: "unauthorized"}));
          return;
        }
        erfuellen(antwort(200, ergebnis(weg, adresse, daten)));
      }, 140);
    });
  };

  // -- Die Knoepfe der Vorfuehrung -------------------------------------
  // Sie fassen die Anwendung nicht an, sondern druecken ihre eigenen
  // Schalter - so, wie ein Finger es taete.
  function anstossen() {
    var lage = document.querySelector("main");
    var knopf = document.getElementById(
      lage && !lage.hidden ? "refresh" : "offline-retry");
    if (knopf) { knopf.click(); }
  }

  document.getElementById("v-angriff").addEventListener("click", function () {
    var ip = "203.0.113." + (40 + Math.floor(Math.random() * 200));
    var n = jetzt();
    for (var k = 0; k < 12; k++) {
      ereignisse.push({ts: n - k * 9, event: "login_failure", ip: ip,
                       identity: konten[k % 3], route: "/login",
                       source: "app", detail: ""});
    }
    sperren.push({ip: ip, is_network: false, reason: "brute_force_ip",
                  strikes: 1, detail: "12 Fehlversuche in 300s",
                  bis: n + 15 * 60});
    anstossen();
  });

  var netz = document.getElementById("v-netz");
  netz.addEventListener("click", function () {
    erreichbar = !erreichbar;
    netz.textContent = erreichbar ? "Netz weg" : "Netz da";
    anstossen();
  });

  document.getElementById("v-neustart").addEventListener("click", function () {
    location.reload();
  });

  document.getElementById("v-vergessen").addEventListener("click", function () {
    try { localStorage.removeItem("ls_token"); } catch (fehler) { /* egal */ }
    location.reload();
  });
})();
</script>"""


def _ersetze(seite: str, alt: str, neu: str) -> str:
    """Wie ``str.replace``, aber es faellt auf, wenn die Stelle wegfaellt."""
    if seite.count(alt) != 1:
        raise RuntimeError(
            "Die Vorschau findet in der Seite nicht mehr genau einmal: "
            + alt[:60]
        )
    return seite.replace(alt, neu)


def preview_html(token: str = PREVIEW_TOKEN) -> str:
    """Dieselbe Seite als einzelne Datei, mit vorgetaeuschtem Server.

    Alles, was zum Server gehoert, wird ersetzt: das Symbol und die
    Beschreibung liegen dort als eigene Adressen, hier muessen sie in die
    Datei. Der Rest - Anmeldung, Token auf dem Geraet, Verbindungsband,
    die zwei Spalten - bleibt Zeile fuer Zeile derselbe Code.
    """
    import base64

    symbol = ("data:image/png;base64,"
              + base64.b64encode(apple_touch_icon()).decode("ascii"))
    hinweis = ("<!-- Erzeugt aus loginshield/dashboard.py "
               "(preview_html). Nicht von Hand aendern. -->")

    seite = INDEX_HTML
    seite = _ersetze(seite, "<!doctype html>", "<!doctype html>\n" + hinweis)
    seite = _ersetze(seite,
                     '<link rel="apple-touch-icon" href="apple-touch-icon.png">',
                     '<link rel="apple-touch-icon" href="%s">' % symbol)
    seite = _ersetze(seite,
                     '<link rel="icon" href="apple-touch-icon.png" type="image/png">',
                     '<link rel="icon" href="%s" type="image/png">' % symbol)
    # Das Manifest ist eine eigene Adresse beim Server. Eine einzelne
    # Datei hat keine - der Verweis ginge ins Leere.
    seite = _ersetze(seite, '<link rel="manifest" href="manifest.webmanifest">\n', "")
    seite = _ersetze(seite, "<title>LoginShield</title>",
                     "<title>LoginShield - Vorschau</title>")
    seite = _ersetze(seite, "</style>\n</head>", _PREVIEW_STYLE + "</style>\n</head>")
    seite = _ersetze(seite, "<body>\n<header>", "<body>\n" + _PREVIEW_BANNER + "<header>")
    seite = _ersetze(seite, '</main>\n<div id="toast"></div>',
                     "</main>\n" + _PREVIEW_FOOTER + '<div id="toast"></div>')
    seite = _ersetze(seite, '<div id="toast"></div>\n\n<script>',
                     '<div id="toast"></div>\n\n'
                     + _PREVIEW_SCRIPT.replace("__TOKEN__", token)
                                      .replace("__VERSION__", __version__)
                     + "\n<script>")
    seite = seite.replace("<code>vorschau</code>", "<code>%s</code>" % token)
    return seite
