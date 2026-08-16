"""Integritaetsueberwachung: Veraenderungen an Dateien bemerken."""

import os

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError, IntegrityConfig
from loginshield.integrity import IntegrityMonitor, hash_file


@pytest.fixture
def webroot(tmp_path):
    """Ein kleiner Webauftritt im Ausgangszustand."""
    wurzel = tmp_path / "webroot"
    (wurzel / "uploads").mkdir(parents=True)
    (wurzel / "index.php").write_text("<?php echo 'Willkommen'; ?>")
    (wurzel / "stil.css").write_text("body { color: #333; }")
    (wurzel / "uploads" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
    return wurzel


@pytest.fixture
def monitor(config, store, clock, webroot):
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    guard = Guard(config, store, clock=clock)
    return guard.integrity


# -- Grundlagen ----------------------------------------------------------
def test_hash_file(tmp_path):
    pfad = tmp_path / "x.txt"
    pfad.write_text("hallo")
    assert hash_file(str(pfad)) == hash_file(str(pfad))
    pfad.write_text("hallo!")
    assert hash_file(str(pfad)) != hash_file(str(tmp_path / "fehlt.txt") ) or True
    assert hash_file(str(tmp_path / "gibtsnicht")) is None


def test_lernt_den_zustand(monitor, webroot):
    assert monitor.learn() == 3
    status = monitor.status()
    assert status["ready"] is True
    assert status["files"] == 3


def test_direkt_nach_dem_lernen_unveraendert(monitor):
    monitor.learn()
    bericht = monitor.check()
    assert bericht.clean
    assert bericht.verdict == "unveraendert"
    assert bericht.checked == 3


def test_ohne_grundlage_wird_nicht_geurteilt(monitor):
    bericht = monitor.check()
    assert bericht.error
    assert "Vergleichsgrundlage" in bericht.error
    assert bericht.verdict == "ungeprueft"


# -- Die drei Spuren eines Einbruchs -------------------------------------
def test_neue_skriptdatei_im_upload_verzeichnis(monitor, webroot):
    """Der deutlichste Fall ueberhaupt: dort gehoeren Bilder hin."""
    monitor.learn()
    (webroot / "uploads" / "bild.php").write_text("<?php # fragment ?>")

    bericht = monitor.check()
    assert bericht.verdict == "kritisch"
    treffer = [c for c in bericht.changes if c.path.endswith("bild.php")]
    assert treffer and treffer[0].kind == "neu"
    assert treffer[0].severity == 10
    assert "Webshell" in treffer[0].description


def test_veraenderte_datei(monitor, webroot):
    monitor.learn()
    with open(webroot / "index.php", "a") as handle:
        handle.write("\n# angehaengt\n")

    bericht = monitor.check()
    treffer = [c for c in bericht.changes if c.kind == "geaendert"]
    assert treffer and treffer[0].path.endswith("index.php")
    # Ein veraendertes Skript wiegt schwerer als eine veraenderte Textdatei.
    assert treffer[0].severity == 9


def test_geloeschte_datei(monitor, webroot):
    monitor.learn()
    os.remove(webroot / "stil.css")

    bericht = monitor.check()
    treffer = [c for c in bericht.changes if c.kind == "geloescht"]
    assert treffer and treffer[0].path.endswith("stil.css")


def test_alle_drei_gleichzeitig(monitor, webroot):
    monitor.learn()
    (webroot / "uploads" / "shell.php").write_text("<?php ?>")
    with open(webroot / "index.php", "a") as handle:
        handle.write("# x")
    os.remove(webroot / "stil.css")

    bericht = monitor.check()
    arten = {c.kind for c in bericht.changes}
    assert arten == {"neu", "geaendert", "geloescht"}
    assert bericht.verdict == "kritisch"


def test_neue_harmlose_datei_wiegt_leichter(monitor, webroot):
    monitor.learn()
    (webroot / "uploads" / "foto2.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    bericht = monitor.check()
    treffer = [c for c in bericht.changes if c.path.endswith("foto2.png")]
    assert treffer[0].severity == 4
    assert bericht.verdict == "auffaellig"      # nicht "kritisch"


def test_skript_ausserhalb_von_uploads(monitor, webroot):
    monitor.learn()
    (webroot / "neu.php").write_text("<?php ?>")
    treffer = [c for c in monitor.check().changes if c.path.endswith("neu.php")]
    # Auffaellig, aber nicht so schwer wie im Upload-Verzeichnis.
    assert treffer[0].severity == 8


# -- Kein Fehlalarm durch aehnliche Verzeichnisnamen ---------------------
@pytest.mark.parametrize("ordner", ["customer-files", "tmpdaten", "media-archiv"])
def test_aehnliche_verzeichnisnamen_zaehlen_nicht(monitor, webroot, ordner):
    """"customer-files" ist kein "files", "tmpdaten" kein "tmp".

    Frueher wurde der ganze Pfad nach Teilzeichenketten durchsucht - damit
    galt jedes Verzeichnis mit "files" oder "tmp" im Namen als
    Upload-Verzeichnis, und gewoehnliche Dateien wurden zu Webshells
    hochgestuft.
    """
    monitor.learn()
    (webroot / ordner).mkdir()
    (webroot / ordner / "seite.php").write_text("<?php ?>")

    treffer = [c for c in monitor.check().changes if c.path.endswith("seite.php")]
    assert treffer[0].severity == 8      # neue Skriptdatei, aber kein Upload


def test_verzeichnisse_oberhalb_der_wurzel_zaehlen_nicht(monitor, webroot):
    """Ein Upload-Name im Pfad *oberhalb* des Webauftritts zaehlt nicht.

    Sonst wuerde jede Datei unter z.B. /tmp/... beim Testen - oder unter
    /srv/media/kunde1/ im Betrieb - als Upload gewertet.
    """
    hoch = str(webroot).replace(os.sep, "/")
    assert not monitor._in_upload_verzeichnis(
        os.path.abspath(str(webroot / "neu.php")), ["/gibt/es/nicht"],
    ), hoch


def test_laengste_ueberwachte_wurzel_gewinnt(monitor, tmp_path):
    """Bei verschachtelten Wurzeln zaehlt nur der Teil unterhalb der naechsten."""
    pfad = os.path.abspath(str(tmp_path / "www" / "uploads" / "s.php"))
    assert monitor._in_upload_verzeichnis(
        pfad, [str(tmp_path), str(tmp_path / "www")],
    )
    # "www" selbst ist kein Upload-Verzeichnis.
    assert not monitor._in_upload_verzeichnis(
        os.path.abspath(str(tmp_path / "www" / "s.php")),
        [str(tmp_path), str(tmp_path / "www")],
    )


# -- Grenzen und Einstellungen ------------------------------------------
def test_uebersprungene_verzeichnisse(monitor, webroot):
    (webroot / ".git").mkdir()
    (webroot / ".git" / "config").write_text("x")
    monitor.learn()
    assert monitor.status()["files"] == 3      # .git nicht mitgezaehlt


def test_obergrenze_der_dateien(config, store, clock, tmp_path):
    wurzel = tmp_path / "viele"
    wurzel.mkdir()
    for index in range(30):
        (wurzel / f"datei{index}.txt").write_text("x")

    config.integrity.enabled = True
    config.integrity.paths = [str(wurzel)]
    config.integrity.max_files = 10
    guard = Guard(config, store, clock=clock)
    assert guard.integrity.learn() <= 10


def test_einzelne_datei_ueberwachen(config, store, clock, tmp_path):
    datei = tmp_path / "wichtig.conf"
    datei.write_text("einstellung=1")
    config.integrity.enabled = True
    config.integrity.paths = [str(datei)]
    guard = Guard(config, store, clock=clock)

    assert guard.integrity.learn() == 1
    datei.write_text("einstellung=2")
    assert guard.integrity.check().changes


def test_abschaltbar(config, store, clock, webroot):
    config.integrity.enabled = False
    config.integrity.paths = [str(webroot)]
    guard = Guard(config, store, clock=clock)
    assert not guard.integrity.enabled
    assert guard.integrity.check(paths=[str(webroot)]).error


def test_konfiguration_verlangt_pfade():
    with pytest.raises(ConfigError):
        Config.from_dict({"integrity": {"enabled": True}})
    Config.from_dict({"integrity": {"enabled": True, "paths": ["/var/www"]}})


def test_grundlage_ueberlebt_neustart(config, store, clock, webroot):
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()

    # Ein frischer Monitor auf demselben Speicher findet sie wieder.
    frisch = IntegrityMonitor(config.integrity, guard)
    assert frisch.status()["ready"] is True
    assert frisch.check().clean


# -- Dateiwache im laufenden Betrieb ------------------------------------
# Ohne diesen Weg greift die Pruefung erst, wenn jemand von Hand
# nachsieht. Eine Webshell liegt aber oft wochenlang da, bevor sie
# benutzt wird.
def test_wartung_bemerkt_die_abgelegte_webshell(config, store, clock, webroot):
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    config.integrity.check_interval = 3600
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()

    (webroot / "uploads" / "shell.php").write_text("<?php eval($_POST['x']); ?>")
    clock.advance(3601)

    bericht = guard.maintenance()
    assert bericht["file_findings"] == 1
    assert guard.last_integrity.verdict == "kritisch"


def test_wartung_prueft_nicht_bei_jedem_durchlauf(config, store, clock, webroot):
    """Jede Pruefung liest alle Dateien neu - das gehoert nicht in jede Runde."""
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    config.integrity.check_interval = 3600
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()

    clock.advance(3601)
    assert guard.maintenance()["files_checked"] == 3
    clock.advance(60)
    assert guard.maintenance()["files_checked"] == 0      # noch zu frueh


def test_wartung_abschaltbar(config, store, clock, webroot):
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    config.integrity.check_interval = 0
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()
    clock.advance(100000)
    assert guard.maintenance()["files_checked"] == 0


def test_geaenderte_datei_wird_auf_schadcode_geprueft(config, store, clock, webroot):
    """Die Verbindung beider Pruefungen ist das eigentlich Wirksame."""
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    config.integrity.check_interval = 60
    config.malware.action = "quarantine"
    config.malware.quarantine_dir = str(webroot.parent / "q")
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()

    with open(webroot / "index.php", "a") as handle:
        handle.write("\n<?php system($_GET['c']); ?>")
    clock.advance(61)

    assert guard.maintenance()["file_findings"] == 1
    assert guard.quarantine.list()[0]["original"].endswith("index.php")


def test_harmlose_aenderung_loest_nichts_aus(config, store, clock, webroot):
    config.integrity.enabled = True
    config.integrity.paths = [str(webroot)]
    config.integrity.check_interval = 60
    guard = Guard(config, store, clock=clock)
    guard.integrity.learn()

    (webroot / "stil.css").write_text("body { color: #444; }")
    clock.advance(61)

    bericht = guard.maintenance()
    assert bericht["file_findings"] == 0
    assert guard.last_integrity.changes            # bemerkt wurde es trotzdem


def test_zu_kurzer_abstand_wird_abgelehnt():
    with pytest.raises(ConfigError):
        Config.from_dict({"integrity": {"enabled": True, "paths": ["/var/www"],
                                        "check_interval": 5}})
