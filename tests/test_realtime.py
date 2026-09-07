"""Der Waechter: neue Dateien pruefen, sobald sie auftauchen.

Die Faelle, an denen ein solcher Waechter in der Praxis scheitert, sind
nicht die Funde, sondern das Drumherum: der halb geschriebene Download,
die Datei, die bei jedem Durchgang erneut geprueft wird, und das
Verzeichnis der gemerkten Dateien, das immer weiter waechst.
"""

import os

import pytest

from loginshield.config import MalwareConfig, RealtimeConfig
from loginshield.filescan import FileScanner, Quarantine
from loginshield.realtime import RealtimeGuard
from loginshield.signatures import EICAR


@pytest.fixture
def scanner(tmp_path):
    # Ein eigenes, leeres Signaturverzeichnis: Der Test soll nicht davon
    # abhaengen, was auf dem Rechner zufaellig herumliegt.
    return FileScanner(MalwareConfig(
        signature_dir=str(tmp_path / "keine-signaturen"), clamav="off"))


def _waechter(tmp_path, scanner, clock, **einstellungen):
    config = RealtimeConfig(enabled=True, paths=[str(tmp_path / "wache")],
                            **einstellungen)
    os.makedirs(config.paths[0], exist_ok=True)
    return RealtimeGuard(config, scanner, clock=clock)


def _ablegen(ordner, name, inhalt=EICAR, alter=100.0, clock=None):
    """Legt eine Datei ab - standardmaessig eine, die schon eine Weile da ist."""
    pfad = os.path.join(str(ordner), name)
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    with open(pfad, "wb") as handle:
        handle.write(inhalt)
    if clock is not None:
        zeitpunkt = clock.now - alter
        os.utime(pfad, (zeitpunkt, zeitpunkt))
    return pfad


# -- Der Grundfall -------------------------------------------------------
def test_neue_datei_wird_gefunden(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    wache = waechter.paths[0]

    assert waechter.poll_once() == []          # erster Durchgang: anlernen

    _ablegen(wache, "download.txt", clock=clock)
    funde = waechter.poll_once()

    assert len(funde) == 1
    assert funde[0].path.endswith("download.txt")
    assert funde[0].verdict == "schadhaft"
    assert funde[0].action == "gemeldet"


def test_dieselbe_datei_wird_nicht_zweimal_geprueft(tmp_path, scanner, clock):
    """Sonst meldet der Waechter denselben Fund alle paar Sekunden erneut."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    _ablegen(waechter.paths[0], "harmlos.txt", b"nur text", clock=clock)

    waechter.poll_once()
    vorher = waechter.stats.geprueft
    waechter.poll_once()
    assert waechter.stats.geprueft == vorher


def test_geaenderte_datei_wird_erneut_geprueft(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    pfad = _ablegen(waechter.paths[0], "datei.txt", b"harmlos", clock=clock)
    waechter.poll_once()
    waechter.poll_once()

    _ablegen(waechter.paths[0], "datei.txt", EICAR, clock=clock)
    funde = waechter.poll_once()
    assert len(funde) == 1 and funde[0].path == pfad


def test_vollpruefung_findet_was_eine_neue_signatur_kennt(tmp_path, scanner, clock):
    """Der Sinn der Vollpruefung.

    Eine Datei, die gestern sauber war, kann heute als bekannt schadhaft
    gelten - weil eine frisch geholte Signaturliste sie jetzt kennt. Ohne
    Vollpruefung fiele das erst auf, wenn sich die Datei aendert; sie
    aendert sich aber nicht.
    """
    import hashlib

    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         full_rescan_interval=100)
    inhalt = b"war gestern noch harmlos"
    _ablegen(waechter.paths[0], "schlaefer.bin", inhalt, clock=clock)

    # Erster Blick: die Signatur kennt die Datei noch nicht.
    assert waechter.poll_once() == []

    # Jetzt kommt die neue Signatur - die Datei selbst bleibt unveraendert.
    scanner.signatures.add_zeile(
        f"{hashlib.sha256(inhalt).hexdigest()}  Spaet.Erkannt")

    # Ein normaler Durchgang sieht nichts Veraendertes.
    clock.advance(10)
    assert waechter.poll_once() == []

    # Sobald die Vollpruefung faellig ist, faellt sie auf.
    clock.advance(100)
    funde = waechter.poll_once()
    assert len(funde) == 1
    assert funde[0].path.endswith("schlaefer.bin")
    assert waechter.stats.vollscans == 1


def test_ohne_intervall_keine_vollpruefung(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    waechter.poll_once()
    clock.advance(100000)
    waechter.poll_once()
    assert waechter.stats.vollscans == 0


def test_bestand_wird_nur_gemerkt_nicht_geprueft(tmp_path, scanner, clock):
    """Beim Einschalten nicht erst die ganze Platte durchgehen."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    _ablegen(waechter.paths[0], "altlast.txt", clock=clock)

    assert waechter.poll_once() == []
    assert waechter.stats.geprueft == 0


def test_scan_existing_prueft_den_bestand(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         scan_existing=True)
    _ablegen(waechter.paths[0], "altlast.txt", clock=clock)
    assert len(waechter.poll_once()) == 1


# -- Halb geschriebene Dateien -------------------------------------------
def test_frische_datei_wird_zurueckgestellt(tmp_path, scanner, clock):
    """Ein laufender Download darf nicht als "sauber" durchgehen."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=2)
    waechter.poll_once()

    _ablegen(waechter.paths[0], "download.part", alter=0.0, clock=clock)
    assert waechter.poll_once() == []
    assert waechter.stats.zurueckgestellt == 1

    clock.advance(10)
    assert len(waechter.poll_once()) == 1


def test_wachsende_datei_wird_weiter_zurueckgestellt(tmp_path, scanner, clock):
    """Der Zeitstempel allein reicht nicht - die Groesse muss auch ruhen."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=2)
    waechter.poll_once()
    wache = waechter.paths[0]

    _ablegen(wache, "download.part", EICAR[:20], alter=0.0, clock=clock)
    assert waechter.poll_once() == []

    # Der Zeitstempel ist jetzt alt genug, aber die Datei ist gewachsen -
    # der Download laeuft also noch.
    clock.advance(10)
    _ablegen(wache, "download.part", EICAR, alter=5.0, clock=clock)
    assert waechter.poll_once() == []
    assert waechter.stats.geprueft == 0

    # Jetzt ruht sie.
    clock.advance(10)
    assert len(waechter.poll_once()) == 1


# -- Umgang mit einem Fund ------------------------------------------------
def test_quarantaene_statt_loeschen(tmp_path, scanner, clock):
    quarantaene = Quarantine(str(tmp_path / "quarantaene"))
    config = RealtimeConfig(enabled=True, paths=[str(tmp_path / "wache")],
                            settle_seconds=0, action="quarantine")
    os.makedirs(config.paths[0])
    waechter = RealtimeGuard(config, scanner, quarantaene, clock=clock)
    waechter.poll_once()

    pfad = _ablegen(config.paths[0], "boese.txt", clock=clock)
    funde = waechter.poll_once()

    assert funde[0].action == "quarantaene"
    assert not os.path.exists(pfad)              # verschoben
    eintraege = quarantaene.list()
    assert len(eintraege) == 1                   # und wiederherstellbar
    assert quarantaene.restore(eintraege[0]["id"]) == pfad
    assert os.path.exists(pfad)


def test_rueckmeldung_wird_gerufen(tmp_path, scanner, clock):
    gemeldet = []
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    waechter.on_event = gemeldet.append
    waechter.poll_once()

    _ablegen(waechter.paths[0], "boese.txt", clock=clock)
    waechter.poll_once()
    assert len(gemeldet) == 1


def test_fehler_in_der_rueckmeldung_haelt_den_waechter_nicht_auf(
        tmp_path, scanner, clock):
    """Der Waechter haengt an fremdem Code - der darf ihn nicht umbringen."""
    def kaputt(_ereignis):
        raise RuntimeError("Mailserver weg")

    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    waechter.on_event = kaputt
    waechter.poll_once()

    _ablegen(waechter.paths[0], "boese.txt", clock=clock)
    assert len(waechter.poll_once()) == 1        # kein Absturz


# -- Grenzen --------------------------------------------------------------
def test_geloeschte_dateien_werden_vergessen(tmp_path, scanner, clock):
    """Sonst waechst das Verzeichnis mit jeder Datei, die es je gab."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0)
    pfad = _ablegen(waechter.paths[0], "kurzlebig.txt", b"text", clock=clock)
    waechter.poll_once()
    assert len(waechter._bekannt) == 1

    os.unlink(pfad)
    waechter.poll_once()
    assert waechter._bekannt == {}


def test_obergrenze_fuer_gemerkte_dateien(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         max_index=5)
    for i in range(20):
        _ablegen(waechter.paths[0], f"datei{i}.txt", b"text", clock=clock)
    waechter.poll_once()
    assert len(waechter._bekannt) <= 5


def test_hoechstens_so_viele_pruefungen_je_durchgang(tmp_path, scanner, clock):
    """Wer 10.000 Dateien auspackt, soll den Rechner nicht lahmlegen."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         max_files_per_cycle=3, scan_existing=True)
    for i in range(10):
        _ablegen(waechter.paths[0], f"datei{i}.txt", b"text", clock=clock)

    waechter.poll_once()
    assert waechter.stats.geprueft == 3
    waechter.poll_once()
    assert waechter.stats.geprueft == 6          # der Rest kommt spaeter


def test_uebersprungene_verzeichnisse(tmp_path, scanner, clock):
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         scan_existing=True, skip_dirs=["node_modules"])
    _ablegen(waechter.paths[0], "node_modules/boese.txt", clock=clock)
    _ablegen(waechter.paths[0], ".versteckt/boese.txt", clock=clock)
    assert waechter.poll_once() == []


def test_ohne_pfade_laeuft_nichts(tmp_path, scanner, clock):
    waechter = RealtimeGuard(RealtimeConfig(), scanner, clock=clock)
    assert not waechter.enabled
    assert waechter.poll_once() == []


def test_verschwundene_datei_zwischen_zwei_blicken(tmp_path, scanner, clock):
    """Zwischen "gesehen" und "geprueft" kann die Datei weg sein."""
    waechter = _waechter(tmp_path, scanner, clock, settle_seconds=0,
                         scan_existing=True)
    _ablegen(waechter.paths[0], "fluechtig.txt", clock=clock)

    original = scanner.scan_file

    def loeschen_dann_pruefen(p):
        if os.path.exists(p):
            os.unlink(p)
        return original(p)

    scanner.scan_file = loeschen_dann_pruefen
    assert waechter.poll_once() == []            # kein Absturz


# -- Dauerbetrieb ---------------------------------------------------------
def test_start_und_stop(tmp_path, scanner):
    import time as echte_zeit

    waechter = _waechter(tmp_path, scanner, echte_zeit.time,
                         settle_seconds=0, interval=0.05)
    waechter.start()
    try:
        # Erst anlernen lassen: Wer die Datei vorher ablegt, hat sie im
        # Bestand - und der Waechter achtet auf Neues.
        frist = echte_zeit.time() + 5
        while waechter.stats.zyklen < 1 and echte_zeit.time() < frist:
            echte_zeit.sleep(0.01)

        _ablegen(waechter.paths[0], "boese.txt")
        frist = echte_zeit.time() + 5
        while waechter.stats.funde == 0 and echte_zeit.time() < frist:
            echte_zeit.sleep(0.05)
        assert waechter.stats.funde == 1
    finally:
        waechter.stop()
    assert waechter._thread is None
