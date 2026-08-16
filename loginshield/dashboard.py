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
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'",
            )
            for key, value in (extra_headers or {}).items():
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
                if not self._authorized(allow_query_token=True):
                    self._send(401, b"Token fehlt oder ist falsch.\n", "text/plain; charset=utf-8")
                    return
                self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return

            if not route.startswith("/api/"):
                self._json(404, {"error": "not_found"})
                return
            if not self._authorized(allow_query_token=False):
                self._json(401, {"error": "unauthorized"})
                return

            params = _query(self.path)
            if route == "/api/summary":
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
            return {
                "ready": True,
                "baseline": status,
                "reports": [r.as_dict() for r in berichte],
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
<meta name="viewport" content="width=device-width, initial-scale=1">
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
body { margin:0; background:var(--bg); color:var(--text);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
header { display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between;
  padding:16px 20px; border-bottom:1px solid var(--line); background:var(--panel); }
h1 { font-size:17px; margin:0; letter-spacing:-.01em; }
h1 span { color:var(--muted); font-weight:400; font-size:13px; margin-left:8px; }
main { padding:20px; max-width:1200px; margin:0 auto; }
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
.body { padding:12px 16px; overflow-x:auto; }
.body.scroll { max-height:520px; overflow-y:auto; }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
th { text-align:left; color:var(--muted); font-weight:500; padding:6px 10px 6px 0;
  border-bottom:1px solid var(--line); white-space:nowrap; }
td { padding:7px 10px 7px 0; border-bottom:1px solid var(--line); white-space:nowrap;
  font-variant-numeric:tabular-nums; }
tr:last-child td { border-bottom:none; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
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
#toast { position:fixed; right:16px; bottom:16px; background:var(--panel); color:var(--text);
  border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:8px;
  padding:10px 14px; box-shadow:0 6px 24px rgba(0,0,0,.18); display:none; max-width:min(90vw,420px); }
</style>
</head>
<body>
<header>
  <h1>LoginShield <span id="meta"></span></h1>
  <div class="row">
    <select id="hours">
      <option value="1">Letzte Stunde</option>
      <option value="24" selected>Letzte 24 Stunden</option>
      <option value="168">Letzte 7 Tage</option>
      <option value="720">Letzte 30 Tage</option>
    </select>
    <button id="refresh">Aktualisieren</button>
  </div>
</header>

<main>
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

  // Token aus der URL holen, merken und aus der Adresszeile entfernen,
  // damit er nicht im Verlauf oder in Screenshots landet.
  var params = new URLSearchParams(location.search);
  if (params.get("token")) {
    sessionStorage.setItem("ls_token", params.get("token"));
    history.replaceState({}, "", location.pathname);
  }
  var TOKEN = sessionStorage.getItem("ls_token") || "";
  var timer = null;

  function api(path, options) {
    options = options || {};
    options.headers = Object.assign({"X-Auth-Token": TOKEN}, options.headers || {});
    return fetch(path, options).then(function (response) {
      if (response.status === 401) { throw new Error("Nicht autorisiert - Token pruefen."); }
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      return response.json();
    });
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
    var body = document.querySelector("#" + tableId + " tbody");
    body.textContent = "";
    document.getElementById(emptyId).hidden = rows.length > 0;
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
      var target = el("td", null, "mono");
      target.appendChild(document.createTextNode(block.ip));
      if (block.is_network) {
        target.appendChild(document.createTextNode(" "));
        target.appendChild(el("span", "ganzes Netz", "tag net"));
      }
      row.appendChild(target);
      row.appendChild(el("td", block.reason));
      row.appendChild(el("td", fmtDuration(block.remaining)));
      row.appendChild(el("td", block.strikes));
      row.appendChild(el("td", block.detail, "muted"));
      row.appendChild(actionButton("Entsperren", "", function () {
        api("/api/unblock", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ip: block.ip})
        }).then(function () {
          toast(block.ip + " entsperrt.");
          load();
        }).catch(function (error) { toast(error.message, true); });
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
        }).catch(function (error) { toast(error.message, true); });
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
          .catch(function (error) { toast(error.message, true); });
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
    if (!data.reports.length) {
      table.hidden = true;
      note.textContent = "Nichts Auffaelliges. Grundlinie: " +
        data.baseline.events + " Ereignisse von " + data.baseline.addresses +
        " Adressen.";
      return;
    }
    note.textContent = data.reports.length +
      " Adresse(n) weichen vom Normalzustand ab.";
    fill("anomalies", "anomaly-note", data.reports, function (item) {
      var row = el("tr");
      row.appendChild(el("td", item.ip, "mono"));
      var cell = el("td");
      cell.appendChild(el("span", item.score + "/100",
        "tag " + (item.verdict === "kritisch" ? "fail" : "deny")));
      row.appendChild(cell);
      row.appendChild(el("td", item.summary, "muted"));
      row.appendChild(actionButton("Sperren", "", function () {
        api("/api/block", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ip: item.ip, minutes: 60, reason: "anomaly"})
        }).then(function () { toast(item.ip + " gesperrt."); load(); })
          .catch(function (error) { toast(error.message, true); });
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
        if (timer === null && data.refresh_seconds > 0) {
          timer = setInterval(load, data.refresh_seconds * 1000);
        }
      })
      .catch(function (error) { toast(error.message, true); });
    api("/api/attempts?limit=100&event=" + encodeURIComponent(event))
      .then(renderAttempts)
      .catch(function (error) { toast(error.message, true); });
  }

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
    }).catch(function (error) { toast(error.message, true); });
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
    }).catch(function (error) { toast(error.message, true); });
  });

  load();
})();
</script>
</body>
</html>
"""
