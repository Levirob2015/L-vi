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


def request(dashboard, path, *, method="GET", token=TOKEN, payload=None):
    url = f"http://127.0.0.1:{dashboard.port}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
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
