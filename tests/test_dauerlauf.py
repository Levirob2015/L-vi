"""Dauerlauf: laeuft der Schutz auch nach Stunden noch?

Die uebrigen Tests pruefen einzelne Schritte und sind in Millisekunden
vorbei. Sie finden damit eine ganze Klasse von Fehlern nicht - naemlich
die, die erst mit der Zeit entstehen:

* Ein Verzeichnis im Speicher, das mit jeder Datei weiter waechst.
* Ein Waechter, der nach dem hundertsten Durchgang haengt.
* Ein Selbsttest, der beim ersten Mal anschlaegt und danach nie wieder.
* Eine Datei, die im Gedraenge zwischen zwei Durchgaengen verlorengeht.

Dieser Dauerlauf wirft dem laufenden Waechter deshalb ueber laengere Zeit
einen Strom von Dateien hin - harmlose und schadhafte gemischt - und
sieht nach, ob am Ende alles stimmt.

Er laeuft **nicht** bei jedem Testlauf mit, sondern nur auf Ansage::

    LOGINSHIELD_DAUERTEST=1 python -m pytest tests/test_dauerlauf.py

Sonst wuerde jeder gewoehnliche Testlauf Minuten dauern, und Tests, die
lange dauern, fuehrt am Ende niemand mehr aus.
"""

import os
import time

import pytest

from loginshield.config import MalwareConfig, RealtimeConfig
from loginshield.filescan import FileScanner, Quarantine
from loginshield.realtime import RealtimeGuard
from loginshield.signatures import EICAR

dauertest = pytest.mark.skipif(
    not os.environ.get("LOGINSHIELD_DAUERTEST"),
    reason="Dauerlauf nur mit LOGINSHIELD_DAUERTEST=1",
)

#: Wie viele Dateien der Strom umfasst. Bewusst nicht riesig: Der Test
#: soll Fehler finden, nicht die Bauumgebung blockieren.
DATEIEN = 120

#: Wie lange auf einen Fund gewartet wird, bevor er als verloren gilt.
GEDULD = 20.0


def _warte_auf(bedingung, geduld: float = GEDULD, takt: float = 0.05) -> bool:
    """Wartet, bis etwas eintritt - oder die Geduld zu Ende ist."""
    frist = time.time() + geduld
    while time.time() < frist:
        if bedingung():
            return True
        time.sleep(takt)
    return False


@pytest.fixture
def scanner(tmp_path):
    return FileScanner(MalwareConfig(
        signature_dir=str(tmp_path / "keine-signaturen"), clamav="off"))


@dauertest
def test_dauerlauf_mit_einem_strom_von_dateien(tmp_path, scanner):
    """Der eigentliche Dauerlauf: nichts darf verlorengehen."""
    wache = tmp_path / "wache"
    wache.mkdir()
    quarantaene = Quarantine(str(tmp_path / "quarantaene"))

    waechter = RealtimeGuard(
        RealtimeConfig(
            enabled=True, paths=[str(wache)], interval=0.05,
            settle_seconds=0, action="quarantine",
            # Der Selbsttest laeuft im Dauerlauf oft - er muss jedes Mal
            # bestehen, nicht nur beim ersten Mal.
            selftest_interval=0.5,
        ),
        scanner, quarantaene,
    )
    funde = []
    waechter.on_event = funde.append
    fehlgeschlagene_selbsttests = []
    waechter.on_selftest_failed = fehlgeschlagene_selbsttests.append

    waechter.start()
    try:
        assert _warte_auf(lambda: waechter.stats.zyklen >= 1, 10)

        schadhaft = 0
        for i in range(DATEIEN):
            if i % 3 == 0:
                (wache / f"boese{i}.txt").write_bytes(EICAR)
                schadhaft += 1
            else:
                (wache / f"brav{i}.txt").write_text(
                    f"Zeile eins\nZeile zwei, Datei {i}\n" * 20)
            # Nicht alles auf einmal: So entsteht der Wechsel zwischen
            # ruhigen und vollen Durchgaengen, den es im Betrieb gibt -
            # und der Lauf dauert lange genug, um "Dauer" zu verdienen.
            # Beim ersten Versuch war er nach 1,1 Sekunden vorbei; in der
            # Zeit kann nichts muede werden.
            if i % 2 == 0:
                time.sleep(0.05)

        gefunden = _warte_auf(lambda: len(funde) >= schadhaft)
        assert gefunden, (
            f"nur {len(funde)} von {schadhaft} schadhaften Dateien gefunden - "
            f"im Dauerbetrieb geht etwas verloren"
        )

        # Kein Fehlalarm: Die harmlosen Dateien bleiben unangetastet.
        assert len(funde) == schadhaft
        for i in range(DATEIEN):
            if i % 3 != 0:
                assert (wache / f"brav{i}.txt").exists()

        # Alles Schadhafte liegt in der Quarantaene, nichts wurde geloescht.
        assert len(quarantaene.list()) == schadhaft

        # Der Waechter hat sich waehrenddessen mehrfach selbst geprueft -
        # und jedes Mal bestanden.
        assert waechter.stats.selbsttests >= 2
        assert waechter.stats.selbsttest_ok is True
        assert fehlgeschlagene_selbsttests == []

        # Und er merkt sich nicht mehr, als noch da ist.
        assert len(waechter._bekannt) <= DATEIEN
    finally:
        waechter.stop()

    assert waechter._thread is None


@dauertest
def test_speicher_waechst_nicht_ins_unendliche(tmp_path, scanner):
    """Dateien kommen und gehen - das Gedaechtnis darf nicht mitwachsen.

    Der Fall ist echt: Ein Verzeichnis, in dem staendig Dateien angelegt
    und wieder geloescht werden (Sitzungsdaten, Zwischenablagen), haette
    das Verzeichnis der gemerkten Dateien sonst unbegrenzt aufgeblaeht.
    """
    wache = tmp_path / "durchlauf"
    wache.mkdir()
    waechter = RealtimeGuard(
        RealtimeConfig(enabled=True, paths=[str(wache)], settle_seconds=0,
                       selftest_interval=0),
        scanner,
    )
    waechter.poll_once()

    for runde in range(30):
        datei = wache / f"fluechtig{runde}.txt"
        datei.write_text("kommt und geht\n")
        waechter.poll_once()
        datei.unlink()
        waechter.poll_once()

    assert waechter._bekannt == {}
    assert waechter._wartend == {}


@dauertest
def test_viele_durchgaenge_bleiben_gleich_schnell(tmp_path, scanner):
    """Der tausendste Durchgang darf nicht langsamer sein als der erste.

    Waechst irgendwo eine Liste mit, faellt es hier auf: Die Dauer eines
    Durchgangs waere dann nicht mehr gleichmaessig.
    """
    wache = tmp_path / "gleichmass"
    wache.mkdir()
    for i in range(50):
        (wache / f"datei{i}.txt").write_text(f"Inhalt {i}\n")

    waechter = RealtimeGuard(
        RealtimeConfig(enabled=True, paths=[str(wache)], settle_seconds=0,
                       selftest_interval=0),
        scanner,
    )
    waechter.poll_once()

    def dauer_von(runden: int) -> float:
        start = time.perf_counter()
        for _ in range(runden):
            waechter.poll_once()
        return (time.perf_counter() - start) / runden

    zuerst = dauer_von(50)
    for _ in range(400):
        waechter.poll_once()
    danach = dauer_von(50)

    # Grosszuegig: Es geht nicht um Millisekunden, sondern darum, dass die
    # Dauer nicht *waechst*. Faktor 3 faellt bei einer mitwachsenden
    # Liste sofort durch, bei blossem Rauschen der Maschine nicht.
    assert danach < zuerst * 3 + 0.005, (
        f"Durchgang wurde langsamer: {zuerst * 1000:.2f} ms -> "
        f"{danach * 1000:.2f} ms"
    )


@dauertest
def test_selbsttest_meldet_sich_wenn_der_schutz_ausfaellt(tmp_path, scanner):
    """Der Ausfall mitten im Betrieb - der Fall, fuer den es den
    Selbsttest gibt."""
    wache = tmp_path / "wache"
    wache.mkdir()
    waechter = RealtimeGuard(
        RealtimeConfig(enabled=True, paths=[str(wache)], interval=0.05,
                       settle_seconds=0, selftest_interval=0.2),
        scanner,
    )
    alarme = []
    waechter.on_selftest_failed = alarme.append

    waechter.start()
    try:
        assert _warte_auf(lambda: waechter.stats.selbsttests >= 1, 10)
        assert waechter.stats.selbsttest_ok is True

        # Jetzt faellt der Schutz aus, ohne dass jemand etwas merkt.
        scanner.config.enabled = False

        assert _warte_auf(lambda: alarme, 10), (
            "Der Schutz ist ausgefallen und niemand hat es gemerkt"
        )
        assert waechter.stats.selbsttest_ok is False
    finally:
        waechter.stop()
