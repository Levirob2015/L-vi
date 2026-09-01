import json
import urllib.error
import urllib.request

import pytest

from loginshield.config import DashboardConfig
from loginshield.dashboard import Dashboard
from loginshield.models import Event

TOKEN = "test-token-abc"


@pytest.fixture
def dashboard(guard):
    config = DashboardConfig(host="127.0.0.1", port=0, token=TOKEN, refresh_seconds=0)
    dashboard = Dashboard(guard, config)
    dashboard.start_background()
    yield dashboard
    dashboard.stop()


def request(dashboard, path, *, method="GET", token=TOKEN, payload=None,
            accept=None):
    url = f"http://127.0.0.1:{dashboard.port}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if accept is not None:
        req.add_header("Accept", accept)
    if token is not None:
        req.add_header("X-Auth-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as response:
        body = response.read()
        return response.status, body


def json_request(dashboard, path, **kwargs):
    status, body = request(dashboard, path, **kwargs)
    return status, json.loads(body)


def test_html_seite(dashboard):
    status, body = request(dashboard, "/")
    assert status == 200
    assert b"LoginShield" in body


def test_html_akzeptiert_token_aus_der_url(dashboard):
    url = f"http://127.0.0.1:{dashboard.port}/?token={TOKEN}"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200


def test_ohne_token_kein_zugriff(dashboard):
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/api/summary", token=None)
    assert exc.value.code == 401


def test_falscher_token(dashboard):
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/api/summary", token="falsch")
    assert exc.value.code == 401


def test_api_token_nicht_per_query(dashboard):
    # Query-Token nur fuer die HTML-Seite - APIs verlangen den Header,
    # sonst waere CSRF ueber einen Bild-Tag moeglich.
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, f"/api/summary?token={TOKEN}", token=None)
    assert exc.value.code == 401


def test_summary(dashboard, guard):
    guard.store.record_attempt("203.0.113.5", Event.LOGIN_FAILURE, ts=guard.clock())
    status, data = json_request(dashboard, "/api/summary?hours=24")
    assert status == 200
    assert data["stats"]["failures"] == 1
    assert data["timeline"]
    assert data["top_offenders"][0]["ip"] == "203.0.113.5"


def test_attempts_mit_filter(dashboard, guard):
    guard.store.record_attempt("1.1.1.1", Event.LOGIN_FAILURE, ts=guard.clock())
    guard.store.record_attempt("2.2.2.2", Event.LOGIN_SUCCESS, ts=guard.clock())
    _, data = json_request(dashboard, "/api/attempts?limit=10&event=login_failure")
    assert len(data["attempts"]) == 1
    assert data["attempts"][0]["ip"] == "1.1.1.1"


def test_sperren_und_entsperren_ueber_api(dashboard, guard):
    _, data = json_request(
        dashboard, "/api/block", method="POST",
        payload={"ip": "203.0.113.9", "minutes": 30, "reason": "manual"},
    )
    assert data["ok"] is True
    assert guard.store.active_block("203.0.113.9", now=guard.clock()) is not None

    _, data = json_request(
        dashboard, "/api/unblock", method="POST", payload={"ip": "203.0.113.9"}
    )
    assert data["ok"] is True
    assert guard.store.active_block("203.0.113.9", now=guard.clock()) is None


def test_allowlist_ueber_api(dashboard, guard):
    json_request(dashboard, "/api/allow", method="POST",
                 payload={"cidr": "10.0.0.0/8", "note": "intern"})
    _, data = json_request(dashboard, "/api/allowlist")
    assert data["allowlist"][0]["cidr"] == "10.0.0.0/8"

    json_request(dashboard, "/api/allow/remove", method="POST",
                 payload={"cidr": "10.0.0.0/8"})
    _, data = json_request(dashboard, "/api/allowlist")
    assert data["allowlist"] == []


def test_ungueltige_eingabe_wird_abgewiesen(dashboard):
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/api/block", method="POST", payload={"ip": "kein-ip"})
    assert exc.value.code == 400


def test_unbekannte_route(dashboard):
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/api/gibt-es-nicht")
    assert exc.value.code == 404


def test_sicherheitsheader(dashboard):
    url = f"http://127.0.0.1:{dashboard.port}/?token={TOKEN}"
    with urllib.request.urlopen(url, timeout=5) as response:
        headers = {key.lower(): value for key, value in response.getheaders()}
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in headers


def test_mutationen_abschaltbar(guard):
    config = DashboardConfig(host="127.0.0.1", port=0, token=TOKEN, allow_mutations=False)
    dashboard = Dashboard(guard, config)
    dashboard.start_background()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            request(dashboard, "/api/block", method="POST", payload={"ip": "1.2.3.4"})
        assert exc.value.code == 403
    finally:
        dashboard.stop()


def test_ohne_token_auf_localhost_erlaubt(guard):
    config = DashboardConfig(host="127.0.0.1", port=0, token="")
    dashboard = Dashboard(guard, config)
    dashboard.start_background()
    try:
        status, _ = json_request(dashboard, "/api/summary", token=None)
        assert status == 200
    finally:
        dashboard.stop()


# -- Auf dem iPhone brauchbar --------------------------------------------
# Der Server laeuft nicht auf iOS - das kann er nicht. Was auf dem iPhone
# laufen soll, ist die Bedienoberflaeche: nachsehen, wer angreift, und
# eine Sperre aufheben, ohne am Rechner zu sitzen.
def test_symbol_fuer_den_startbildschirm(dashboard):
    """iOS nimmt nur PNG - ein SVG wird still ignoriert."""
    status, body = request(dashboard, "/apple-touch-icon.png", token=None)
    assert status == 200
    assert body[:8] == b"\x89PNG\r\n\x1a\n"

    import struct
    breite, hoehe = struct.unpack(">II", body[16:24])
    assert (breite, hoehe) == (180, 180)


def test_manifest_fuer_den_startbildschirm(dashboard):
    status, body = request(dashboard, "/manifest.webmanifest", token=None)
    assert status == 200
    daten = json.loads(body)
    assert daten["display"] == "standalone"
    assert daten["icons"][0]["sizes"] == "180x180"


def test_symbol_und_manifest_brauchen_keinen_token(dashboard):
    """Safari holt beides ohne die Kopfzeile - und beide enthalten nichts."""
    for pfad in ("/apple-touch-icon.png", "/manifest.webmanifest"):
        assert request(dashboard, pfad, token=None)[0] == 200
    # Die Daten dahinter bleiben geschuetzt.
    with pytest.raises(urllib.error.HTTPError):
        request(dashboard, "/api/summary", token=None)


def test_richtlinie_erlaubt_das_eigene_symbol(dashboard):
    """Bei 'default-src none' wuerde der Browser das Symbol verwerfen."""
    url = f"http://127.0.0.1:{dashboard.port}/?token={TOKEN}"
    with urllib.request.urlopen(url, timeout=5) as response:
        richtlinie = response.getheader("Content-Security-Policy")
    assert "img-src 'self' data:" in richtlinie
    assert "manifest-src 'self'" in richtlinie
    # Von aussen wird weiterhin nichts geladen.
    assert "http" not in richtlinie


def test_kopfzeilen_werden_nicht_doppelt_gesendet(dashboard):
    url = f"http://127.0.0.1:{dashboard.port}/apple-touch-icon.png"
    with urllib.request.urlopen(url, timeout=5) as response:
        cache = response.getheaders()
    treffer = [wert for name, wert in cache if name.lower() == "cache-control"]
    assert treffer == ["public, max-age=86400"]


def test_seite_ist_fuer_das_telefon_vorbereitet(dashboard):
    seite = request(dashboard, "/")[1].decode("utf-8")

    # Ohne viewport-fit bleiben neben der Kamera-Aussparung graue Balken.
    assert "viewport-fit=cover" in seite
    assert 'name="apple-mobile-web-app-capable"' in seite
    assert 'rel="apple-touch-icon"' in seite
    assert 'rel="manifest"' in seite
    # iOS macht aus IP-Adressen sonst Telefonnummern-Links.
    assert 'name="format-detection" content="telephone=no"' in seite


def test_bedienelemente_sind_auf_touch_gross_genug(dashboard):
    """44 Punkte ist Apples Mindestgroesse, 16px verhindert das Hineinzoomen."""
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert "@media (pointer:coarse)" in seite
    assert "min-height:44px" in seite
    assert "font-size:16px" in seite
    assert "env(safe-area-inset-bottom)" in seite


# -- Die Dateipruefung im Dashboard --------------------------------------
# Die Ergebnisse landeten bisher nur im Protokoll. Wer das Dashboard
# benutzt, sah von der ganzen Dateipruefung nichts - also ausgerechnet
# vom deutlichsten Hinweis darauf, dass jemand schon im Haus ist.
def test_dateizustand_ueber_api(dashboard):
    status, daten = json_request(dashboard, "/api/files")
    assert status == 200
    assert daten["malware_enabled"] is True
    assert daten["integrity"]["enabled"] is False
    assert daten["last_report"] is None
    assert daten["quarantine"] == []


def test_befund_taucht_im_dashboard_auf(guard, tmp_path):
    wurzel = tmp_path / "www"
    (wurzel / "uploads").mkdir(parents=True)
    (wurzel / "index.php").write_text("<?php echo 1; ?>")

    guard.config.integrity.enabled = True
    guard.config.integrity.paths = [str(wurzel)]
    guard.config.integrity.check_interval = 60
    guard.integrity.config = guard.config.integrity
    guard.integrity.learn()
    (wurzel / "uploads" / "shell.php").write_text("<?php eval($_POST['x']); ?>")
    guard.clock.advance(61)
    guard.maintenance()

    config = DashboardConfig(host="127.0.0.1", port=0, token=TOKEN)
    dash = Dashboard(guard, config)
    dash.start_background()
    try:
        _, daten = json_request(dash, "/api/files")
        assert daten["integrity"]["ready"] is True
        assert daten["last_report"]["verdict"] == "kritisch"
        pfade = [c["path"] for c in daten["last_report"]["changes"]]
        assert any(p.endswith("shell.php") for p in pfade)
    finally:
        dash.stop()


def test_seite_hat_den_abschnitt(dashboard):
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert "Dateien auf dem Server" in seite
    assert 'id="files-note"' in seite


def test_zusammenfassung_bleibt_sichtbar(dashboard):
    """fill() blendete den Hinweistext aus, sobald es Zeilen gab.

    Damit war die Zusammenfassung ueber der Tabelle nie zu sehen -
    ausgerechnet dann nicht, wenn es etwas zu sehen gab.
    """
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert "function fillTable(" in seite
    assert 'fillTable("files"' in seite
    assert 'fillTable("anomalies"' in seite


def test_symbol_wird_erst_bei_bedarf_erzeugt():
    """Vorher lief die Erzeugung beim Import - bei jedem Aufruf.

    12 ms fuer ein Bild, das 'loginshield --version' oder 'block' nie
    braucht: ein Achtel der gesamten Startzeit fuer nichts.
    """
    import importlib

    from loginshield import dashboard as modul

    importlib.reload(modul)
    assert modul._icon_zwischenspeicher is None      # noch nichts gebaut

    erst = modul.apple_touch_icon()
    assert erst[:8] == b"\x89PNG\r\n\x1a\n"
    # Danach behalten, nicht jedes Mal neu.
    assert modul.apple_touch_icon() is erst


# -- Die App auf dem iPad ------------------------------------------------
# Das Symbol auf dem Startbildschirm zeigt auf "/" - ohne Token in der
# Adresse. Was danach passiert, entscheidet, ob die App benutzbar ist
# oder bei jedem Kaltstart in einer Fehlermeldung endet.
def test_seite_kommt_auch_ohne_token(dashboard):
    """Ohne Token dieselbe Seite mit 401 - sie zeigt dann die Anmeldung.

    Frueher kam hier eine Textzeile. Damit war die App auf dem
    Startbildschirm tot, sobald iOS sie aus dem Speicher geworfen hatte:
    kein Feld, keine Erklaerung, kein Weg zurueck.
    """
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/", token=None, accept="text/html")
    assert exc.value.code == 401
    seite = exc.value.read().decode("utf-8")
    assert exc.value.headers.get("Content-Type").startswith("text/html")
    assert 'id="login"' in seite
    assert 'id="login-token"' in seite


def test_seite_verraet_ohne_token_nichts(dashboard):
    """Die Anmeldeseite ist dieselbe Datei - Daten stehen nicht darin."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/", token=None, accept="text/html")
    assert TOKEN not in exc.value.read().decode("utf-8")
    # Und die Daten dahinter bleiben verschlossen.
    with pytest.raises(urllib.error.HTTPError) as api:
        request(dashboard, "/api/summary", token=None)
    assert api.value.code == 401


def test_session_bestaetigt_den_token(dashboard):
    """Der kleinste Aufruf mit Token: Damit prueft die Anmeldung eine Eingabe."""
    status, daten = json_request(dashboard, "/api/session")
    assert status == 200
    assert daten["ok"] is True
    assert daten["token_required"] is True
    assert daten["version"]


def test_session_weist_falschen_token_ab(dashboard):
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/api/session", token="falsch")
    assert exc.value.code == 401


def test_session_sagt_wenn_kein_token_noetig_ist(guard):
    """Auf localhost ohne Token soll die App keine Anmeldung zeigen."""
    dashboard = Dashboard(guard, DashboardConfig(host="127.0.0.1", port=0, token=""))
    dashboard.start_background()
    try:
        status, daten = json_request(dashboard, "/api/session", token=None)
        assert status == 200
        assert daten["token_required"] is False
    finally:
        dashboard.stop()


def test_token_ueberlebt_den_kaltstart(dashboard):
    """localStorage statt sessionStorage.

    iOS wirft eine App vom Startbildschirm aus dem Speicher, sobald der
    Platz knapp wird. Mit sessionStorage war der Token danach weg.
    """
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert "localStorage.setItem(TOKEN_SCHLUESSEL" in seite
    assert "sessionStorage.setItem" not in seite
    # Der alte Platz wird noch einmal ausgelesen und dann geraeumt.
    assert "sessionStorage.getItem(TOKEN_SCHLUESSEL)" in seite
    assert "sessionStorage.removeItem(TOKEN_SCHLUESSEL)" in seite


def test_token_verlaesst_die_adresszeile(dashboard):
    """Sonst steht er im Verlauf und auf jedem Bildschirmfoto."""
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert 'history.replaceState({}, "", location.pathname)' in seite


def test_abmelden_ist_moeglich(dashboard):
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert 'id="logout"' in seite
    assert 'document.getElementById("login-token").value = "";' in seite


def test_fehlende_verbindung_bleibt_sichtbar(dashboard):
    """Unterwegs ist "nicht erreichbar" der Normalfall, kein Ausrutscher.

    Eine Einblendung, die nach vier Sekunden verschwindet, taugt dafuer
    nicht: Danach zeigt die App alte Zahlen, ohne dass es auffaellt.
    """
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert 'id="offline"' in seite
    assert 'id="offline-retry"' in seite
    assert "function verbindung(" in seite


def test_das_eingabefeld_wird_nicht_verbessert(dashboard):
    """Safari schreibt sonst den ersten Buchstaben des Tokens gross."""
    seite = request(dashboard, "/")[1].decode("utf-8")
    feld = seite.split('id="login-token"', 1)[1].split(">", 1)[0]
    assert 'autocapitalize="none"' in feld
    assert 'autocorrect="off"' in feld
    assert 'spellcheck="false"' in feld
    assert 'type="password"' in feld


def test_im_hintergrund_laeuft_nichts(dashboard):
    """Ein Wecker, der jede halbe Minute Daten holt, kostet nur Strom."""
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert 'document.addEventListener("visibilitychange"' in seite
    assert "if (document.hidden) { stopTimer(); return; }" in seite
    assert "!document.hidden" in seite


def test_zwei_spalten_im_querformat(dashboard):
    """Ein iPad quer ist 1194 Punkte breit - untereinander ist das leer."""
    seite = request(dashboard, "/")[1].decode("utf-8")
    assert "@media (min-width:980px)" in seite
    assert seite.count('<div class="paar">') == 2


def test_manifest_hat_einen_geltungsbereich(dashboard):
    """Ohne scope faellt ein Link aus der App zurueck in Safari."""
    daten = json.loads(request(dashboard, "/manifest.webmanifest", token=None)[1])
    assert daten["scope"] == "./"


def test_scanner_bekommt_nicht_die_ganze_seite(dashboard):
    """55 kB fuer jede Anfrage ohne Token waeren ein Verstaerker.

    Ein Browser fragt beim Oeffnen einer Adresse nach HTML; ein Scanner
    schickt "*/*" und bekommt weiterhin die eine Zeile.
    """
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(dashboard, "/", token=None, accept="*/*")
    assert exc.value.code == 401
    koerper = exc.value.read()
    assert len(koerper) < 200
    assert exc.value.headers.get("Content-Type").startswith("text/plain")


# -- Die Vorschau --------------------------------------------------------
# Sie ist keine Nachbildung, sondern dieselbe Seite mit einem
# vorgetaeuschten Server. Deshalb muss sie mitwandern, wenn sich die
# Seite aendert - sonst zeigt die Vorschau bald etwas, das es nicht gibt.
def test_vorschau_ist_die_seite_selbst():
    from loginshield.dashboard import INDEX_HTML, preview_html

    seite = preview_html()
    # Ein paar Stellen, an denen sich Nachbildung und Original trennen
    # wuerden - hier sind sie Zeile fuer Zeile dieselben.
    for stueck in ('id="login-token"', 'id="offline"', 'id="logout"',
                   'class="paar"', "function starteTimer()",
                   "localStorage.setItem(TOKEN_SCHLUESSEL"):
        assert stueck in INDEX_HTML
        assert stueck in seite


def test_vorschau_kommt_ohne_server_aus():
    """Als einzelne Datei darf nichts auf eine Adresse daneben zeigen."""
    from loginshield.dashboard import preview_html

    seite = preview_html()
    assert 'href="apple-touch-icon.png"' not in seite
    assert "manifest.webmanifest" not in seite
    # Das Symbol steckt stattdessen in der Datei.
    assert "data:image/png;base64," in seite
    assert "window.fetch = function" in seite


def test_vorschau_nimmt_nur_ihren_token():
    from loginshield.dashboard import PREVIEW_TOKEN, preview_html

    seite = preview_html()
    assert 'var TOKEN = "%s"' % PREVIEW_TOKEN in seite
    assert "<code>%s</code>" % PREVIEW_TOKEN in seite


def test_vorschau_sagt_was_sie_ist():
    """Ohne das haelt sie jemand fuer eine laufende Ueberwachung."""
    from loginshield.dashboard import preview_html

    seite = preview_html()
    assert "Erfundene Daten, kein Server" in seite
    assert "Keine App auf einem iPad kann" in seite


def test_vorschau_meldet_sich_wenn_die_seite_umgebaut_wird():
    """Eine verschobene Stelle soll auffallen, nicht still durchgehen."""
    import loginshield.dashboard as modul

    original = modul.INDEX_HTML
    try:
        modul.INDEX_HTML = original.replace('<link rel="manifest"'
                                            ' href="manifest.webmanifest">\n', "")
        with pytest.raises(RuntimeError, match="nicht mehr genau einmal"):
            modul.preview_html()
    finally:
        modul.INDEX_HTML = original


def test_die_abgelegte_vorschau_ist_aktuell():
    """docs/ipad.html wird erzeugt, nicht von Hand gepflegt."""
    import pathlib

    from loginshield.dashboard import preview_html

    datei = pathlib.Path(__file__).resolve().parents[1] / "docs" / "ipad.html"
    assert datei.exists(), "docs/ipad.html fehlt"
    assert datei.read_text(encoding="utf-8") == preview_html(), (
        "docs/ipad.html ist nicht mehr auf dem Stand der Seite. Neu erzeugen:\n"
        "  python -c \"from loginshield.dashboard import preview_html; "
        "open('docs/ipad.html','w').write(preview_html())\""
    )
