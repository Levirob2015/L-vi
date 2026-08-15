import json
import urllib.error
import urllib.request

import pytest

from loginshield import Guard
from loginshield.config import HoneypotConfig, LogSourceConfig
from loginshield.honeypot import DEFAULT_TRAPS, Honeypot, HoneypotServer
from loginshield.logwatch import LogWatcher, parse_line
from loginshield.models import Event, Reason

SCANNER = "198.51.100.200"


# -- Falle 1: Koeder-Pfade ----------------------------------------------
def test_erkennt_eingebaute_koeder(guard):
    honeypot = guard.honeypot
    for path in ("/.env", "/.git/config", "/backup.sql", "/wp-login.php"):
        assert honeypot.match(path) is not None, path


def test_praefix_koeder(guard):
    honeypot = guard.honeypot
    assert honeypot.match("/wp-admin/setup-config.php") is not None
    assert honeypot.match("/phpmyadmin/index.php") is not None


def test_gross_kleinschreibung_und_query_egal(guard):
    honeypot = guard.honeypot
    assert honeypot.match("/.ENV") is not None
    assert honeypot.match("/.env?x=1") is not None
    assert honeypot.match("/.env/") is not None


def test_normale_pfade_sind_keine_falle(guard):
    honeypot = guard.honeypot
    for path in ("/", "/login", "/api/users", "/static/app.css", "/robots.txt"):
        assert honeypot.match(path) is None, path


def test_eigene_koeder_und_ausnahmen():
    config = HoneypotConfig(extra_paths=["/api/debug*"], exclude_paths=["/.env"])
    honeypot = Honeypot(config)
    assert honeypot.match("/api/debug/dump") is not None
    assert honeypot.match("/.env") is None
    assert honeypot.match("/.git/config") is not None


def test_eigene_liste_ersetzt_die_eingebaute():
    honeypot = Honeypot(HoneypotConfig(paths=["/nur-das"]))
    assert len(honeypot.traps) == 1
    assert honeypot.match("/.env") is None
    assert honeypot.match("/nur-das") is not None


def test_konflikt_mit_eigenen_routen(guard):
    # Vor dem Scharfschalten pruefen, sonst sperrt man die eigenen Nutzer aus.
    assert guard.honeypot.conflicts_with(["/login", "/profil"]) == []
    assert guard.honeypot.conflicts_with(["/admin.php"]) == ["/admin.php"]


def test_ein_treffer_genuegt_fuer_sperre(guard, config, clock):
    block = guard.honeypot.trigger(SCANNER, route="/.env")
    assert block is not None
    assert block.reason == Reason.HONEYPOT_PATH
    assert block.remaining(clock.now) == config.honeypot.block_seconds

    decision = guard.check(SCANNER)
    assert not decision.allowed
    assert decision.detail == Reason.HONEYPOT_PATH


def test_honeypot_sperrt_laenger_als_ein_fehlversuch(guard, config):
    assert config.honeypot.block_seconds > config.rules.block_base_seconds


def test_treffer_wird_protokolliert(guard):
    guard.honeypot.trigger(SCANNER, route="/.env", detail="env")
    events = guard.store.recent_attempts(limit=10, events=[Event.HONEYPOT])
    assert len(events) == 1
    assert events[0].route == "/.env"
    assert Reason.HONEYPOT_PATH in events[0].detail


def test_allowlist_wird_respektiert(config, store, clock):
    # Der eigene Sicherheitsscanner soll den Betrieb nicht lahmlegen.
    config.allowlist = ["198.51.100.0/24"]
    guard = Guard(config, store, clock=clock)
    assert guard.honeypot.trigger(SCANNER, route="/.env") is None
    assert guard.store.active_block(SCANNER, now=clock.now) is None
    # Protokolliert wird der Treffer trotzdem.
    assert len(guard.store.recent_attempts(limit=5, events=[Event.HONEYPOT])) == 1


def test_abschaltbar(config, store, clock):
    config.honeypot.enabled = False
    guard = Guard(config, store, clock=clock)
    assert guard.honeypot.match("/.env") is None
    assert guard.honeypot.trigger(SCANNER, route="/.env") is None


# -- Falle 2: Koeder-Zugangsdaten ---------------------------------------
def test_zugangsdaten_sind_stabil_aber_pro_installation_anders():
    a = Honeypot(HoneypotConfig(), secret="schluessel-a")
    b = Honeypot(HoneypotConfig(), secret="schluessel-b")
    assert a.credentials() == a.credentials()      # stabil ueber Neustarts
    assert a.credentials()[1] != b.credentials()[1]  # aber nicht vorhersagbar


def test_eigenes_koeder_passwort():
    honeypot = Honeypot(HoneypotConfig(decoy_user="backup", decoy_password="geheim"))
    assert honeypot.credentials() == ("backup", "geheim")


def test_honeytoken_erkennung(guard):
    honeypot = guard.honeypot
    user, password = honeypot.credentials()

    assert honeypot.is_honeytoken(user)
    assert honeypot.is_honeytoken(user.upper())      # Schreibweise egal
    assert honeypot.is_honeytoken(user, password)
    assert not honeypot.is_honeytoken(user, "falsches-passwort")
    assert not honeypot.is_honeytoken("anna")
    assert not honeypot.is_honeytoken("")
    assert not honeypot.is_honeytoken(None)


def test_honeytoken_steht_in_der_koederdatei(guard):
    honeypot = guard.honeypot
    user, password = honeypot.credentials()
    trap = honeypot.match("/.env")
    _, _, body = honeypot.decoy_response(trap)
    text = body.decode()
    # Genau so findet der Angreifer die Daten - und verraet sich damit.
    assert user in text
    assert password in text


def test_benutzung_des_koeders_sperrt_sofort(guard, clock):
    user, _ = guard.honeypot.credentials()
    assert guard.honeypot.is_honeytoken(user)
    block = guard.honeypot.trigger(SCANNER, route="/login",
                                   reason=Reason.HONEYPOT_TOKEN)
    assert block.reason == Reason.HONEYPOT_TOKEN
    assert not guard.check(SCANNER).allowed


# -- Falle 3: unsichtbares Formularfeld ---------------------------------
def test_hidden_field_html(guard):
    html = guard.honeypot.hidden_field_html()
    assert 'name="website"' in html
    assert "-9999px" in html          # ausserhalb des Bildschirms
    assert 'aria-hidden="true"' in html  # Screenreader ignorieren es


def test_ausgefuelltes_feld_ist_ein_bot(guard):
    honeypot = guard.honeypot
    assert honeypot.check_hidden_field({"website": ["http://spam.example"]})
    assert honeypot.check_hidden_field({"website": "irgendwas"})
    # Ein Mensch laesst es leer - das Feld ist fuer ihn unsichtbar.
    assert not honeypot.check_hidden_field({"website": [""]})
    assert not honeypot.check_hidden_field({"website": ["   "]})
    assert not honeypot.check_hidden_field({"username": ["anna"]})


# -- Gefaelschte Antworten ----------------------------------------------
@pytest.mark.parametrize("path", [trap.pattern.rstrip("*") for trap in DEFAULT_TRAPS])
def test_jeder_koeder_liefert_eine_glaubwuerdige_antwort(guard, path):
    honeypot = guard.honeypot
    trap = honeypot.match(path)
    assert trap is not None, path
    status, content_type, body = honeypot.decoy_response(trap)
    assert status == 200          # 404 wuerde den Angreifer weiterziehen lassen
    assert content_type
    assert len(body) > 20


def test_koeder_verraet_den_honeypot_nicht(guard):
    for path in ("/.env", "/phpmyadmin/", "/backup.sql", "/.git/config"):
        _, _, body = guard.honeypot.decoy_response(guard.honeypot.match(path))
        text = body.decode().lower()
        for verraeterisch in ("loginshield", "honeypot", "koeder", "falle", "trap"):
            assert verraeterisch not in text, (path, verraeterisch)


# -- Middleware ----------------------------------------------------------
def test_middleware_serviert_koeder_und_sperrt(guard):
    from tests.test_middleware import call, make_app, make_scope, status_of, body_of
    from loginshield.middleware import ShieldMiddleware

    app = ShieldMiddleware(make_app(200), guard)
    messages = call(app, make_scope(path="/.env", method="GET"))

    assert status_of(messages) == 200
    assert b"DB_PASSWORD" in body_of(messages)
    assert guard.store.active_block("198.51.100.5", now=guard.clock()) is not None

    # Der naechste Zugriff auf die echte Anwendung ist gesperrt.
    assert status_of(call(app, make_scope(path="/", method="GET"))) == 403


def test_middleware_honeypot_abschaltbar(guard):
    from tests.test_middleware import call, make_app, make_scope, status_of
    from loginshield.middleware import ShieldMiddleware

    app = ShieldMiddleware(make_app(200), guard, honeypot=False)
    assert status_of(call(app, make_scope(path="/.env", method="GET"))) == 200
    assert guard.store.active_block("198.51.100.5", now=guard.clock()) is None


def test_wsgi_middleware_serviert_koeder(guard):
    from loginshield.middleware import WSGIShield

    def app(environ, start_response):  # pragma: no cover - darf nie laufen
        start_response("200 OK", [])
        return [b"echte anwendung"]

    shield = WSGIShield(app, guard)
    captured = []
    body = shield(
        {"PATH_INFO": "/.git/config", "REQUEST_METHOD": "GET",
         "REMOTE_ADDR": "198.51.100.9"},
        lambda status, headers, exc_info=None: captured.append(status),
    )
    assert captured[0].startswith("200")
    assert b"git.example.com" in b"".join(body)
    assert guard.store.active_block("198.51.100.9", now=guard.clock()) is not None


# -- Logwatch ------------------------------------------------------------
def test_nginx_scan_wird_erkannt_trotz_404(guard, tmp_path):
    source = LogSourceConfig(path="dummy", format="nginx")
    line = ('45.155.205.9 - - [15/Aug/2026:10:00:01 +0000] "GET /.env HTTP/1.1" '
            '404 153 "-" "python-requests/2.31"')

    # Ohne Honeypot ist ein 404 uninteressant ...
    assert parse_line(line, source) is None
    # ... mit Honeypot ist es ein Treffer.
    event = parse_line(line, source, guard.honeypot)
    assert event is not None
    assert event.kind == "honeypot"
    assert event.ip == "45.155.205.9"


def test_watcher_sperrt_scanner_aus_dem_log(tmp_path, guard):
    path = tmp_path / "access.log"
    path.write_text("", encoding="utf-8")
    watcher = LogWatcher(guard, [LogSourceConfig(path=str(path), format="nginx")])
    watcher.poll_once()

    with open(path, "a", encoding="utf-8") as handle:
        handle.write('45.155.205.9 - - [15/Aug/2026:10:00:01 +0000] '
                     '"GET /.env HTTP/1.1" 404 1 "-" "curl/8"\n')

    assert watcher.poll_once() == 1
    assert guard.store.active_block("45.155.205.9", now=guard.clock()) is not None
    watcher.close()


# -- Eigenstaendiger Koeder-Server ---------------------------------------
@pytest.fixture
def server(guard):
    server = HoneypotServer(guard, host="127.0.0.1", port=0)
    server.start_background()
    yield server
    server.stop()


def fetch(server, path, data=None):
    url = f"http://127.0.0.1:{server.port}{path}"
    request = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, response.read(), dict(response.getheaders())


def test_server_liefert_koeder_und_sperrt(server, guard):
    status, body, _ = fetch(server, "/.env")
    assert status == 200
    assert b"DB_PASSWORD" in body
    assert guard.store.active_block("127.0.0.1", now=guard.clock()) is not None


def test_server_sperrt_auch_unbekannte_pfade(server, guard):
    status, body, _ = fetch(server, "/irgendwas")
    assert status == 200
    assert b"Index of" in body
    assert guard.store.active_block("127.0.0.1", now=guard.clock()) is not None


def test_server_tarnt_sich(server):
    _, _, headers = fetch(server, "/.env")
    banner = headers.get("Server", "")
    assert "LoginShield" not in banner
    assert "Python" not in banner


def test_server_protokolliert_login_versuch(server, guard):
    fetch(server, "/admin.php", data=b"username=root&password=123456")
    events = guard.store.recent_attempts(limit=5, events=[Event.HONEYPOT])
    detail = events[0].detail
    assert "root" in detail
    # Das Passwort wird nie gespeichert.
    assert "123456" not in detail


def test_server_nur_bekannte_koeder(guard):
    server = HoneypotServer(guard, host="127.0.0.1", port=0,
                            block_every_request=False)
    server.start_background()
    try:
        fetch(server, "/harmlos")
        assert guard.store.active_block("127.0.0.1", now=guard.clock()) is None
        fetch(server, "/.env")
        assert guard.store.active_block("127.0.0.1", now=guard.clock()) is not None
    finally:
        server.stop()
