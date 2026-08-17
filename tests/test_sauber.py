"""Fremder Text in Protokoll, Datenbank und Benachrichtigung.

Alles, was von aussen kommt - der Name einer hochgeladenen Datei, der
Pfad einer Anfrage - landet in Protokollzeilen und Meldungen. Ungefiltert
kann der Absender damit Protokollzeilen faelschen, das Terminal des
Lesenden umschreiben und die Benachrichtigung ganz verhindern.
"""

import logging

import pytest

from loginshield import Guard
from loginshield.config import NotifyConfig
from loginshield.models import sauber
from loginshield.notify import Meldung


# -- Der Filter selbst ---------------------------------------------------
@pytest.mark.parametrize("hinein,heraus", [
    ("harmlos.php", "harmlos.php"),
    ("x.php\nIP 203.0.113.1 entsperrt", "x.php IP 203.0.113.1 entsperrt"),
    ("x.php\r\nWARNING gefaelscht", "x.php  WARNING gefaelscht"),
    ("x.php\x1b[2J\x1b[H", "x.php [2J [H"),
    ("x.php\x00versteckt", "x.php versteckt"),
    ("x.php\tmit Tabulator", "x.php mit Tabulator"),
    ("\n\n  ", ""),
])
def test_steuerzeichen_verschwinden(hinein, heraus):
    ergebnis = sauber(hinein)
    assert ergebnis == heraus
    assert "\n" not in ergebnis and "\r" not in ergebnis
    assert not any(ord(z) < 32 for z in ergebnis)


def test_laenge_wird_begrenzt():
    assert sauber("A" * 500, 60) == "A" * 57 + "..."
    assert len(sauber("A" * 500, 60)) == 60


def test_nichttext_wird_vertragen():
    assert sauber(None) == "None"
    assert sauber(42) == "42"


# -- Im Zusammenspiel ----------------------------------------------------
def test_dateiname_faelscht_keine_protokollzeile(config, store, clock, caplog):
    """Der Fall, der es wirklich gab.

    Ein Upload namens "harmlos.php\\nIP ... entsperrt" erzeugte im
    Protokoll eine zweite Zeile, die aussah wie eine Meldung dieses
    Programms.
    """
    guard = Guard(config, store, clock=clock)
    try:
        with caplog.at_level(logging.WARNING, logger="loginshield"):
            guard.scan_upload(b"<?php eval($_POST['x']); ?>",
                              filename="harmlos.php\nIP 203.0.113.1 entsperrt",
                              ip="203.0.113.99")
        for eintrag in caplog.records:
            assert "\n" not in eintrag.getMessage()
            assert "\r" not in eintrag.getMessage()
    finally:
        guard.close()


def test_anfragepfad_faelscht_keine_protokollzeile(config, store, clock, caplog):
    """Auch der Pfad kommt von aussen - und er ist schon dekodiert."""
    guard = Guard(config, store, clock=clock)
    try:
        with caplog.at_level(logging.WARNING, logger="loginshield"):
            guard.record_honeypot("203.0.113.98",
                                  route="/.env\nIP 1.2.3.4 entsperrt")
        for eintrag in caplog.records:
            assert "\n" not in eintrag.getMessage()
    finally:
        guard.close()


def test_betreffzeile_bleibt_versandfaehig():
    """Ein Wagenruecklauf im Betreff laesst Python den Versand abweisen.

    Die Meldung wuerde dann ganz ausfallen - ausgerechnet die, die man
    braeuchte.
    """
    from email.message import EmailMessage

    meldung = Meldung(titel="Upload x.php\r\nBcc: fremd@example.com",
                      text="Text", schwere=9)
    nachricht = EmailMessage()
    nachricht["Subject"] = meldung.betreff()      # darf nicht werfen
    assert "Bcc" not in str(nachricht["Subject"]) or "\r" not in nachricht["Subject"]
    assert "\n" not in nachricht["Subject"]


def test_webhook_kopfzeile_bleibt_gueltig():
    import http.client

    meldung = Meldung(titel="x.php\r\nX-Untergeschoben: ja", text="t", schwere=9)
    # putheader lehnt Steuerzeichen ab - hier darf es nicht mehr dazu kommen.
    verbindung = http.client.HTTPConnection("127.0.0.1", 9, timeout=0.1)
    verbindung.putrequest("POST", "/x", skip_host=True, skip_accept_encoding=True)
    verbindung.putheader("Title", meldung.betreff())     # darf nicht werfen
