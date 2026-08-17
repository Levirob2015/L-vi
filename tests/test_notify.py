"""Benachrichtigungen.

Zwei Eigenschaften sind hier wichtiger als die Zustellung selbst:

* Eine Meldung darf **niemals** die Anfrage aufhalten. Ein SMTP-Server,
  der nicht antwortet, wuerde sonst jeden Login blockieren, der eine
  Sperre ausloest.
* Niemand liest 400 Meldungen. Ein Angriff erzeugt viele gleichartige
  Ereignisse - die muessen zusammengefasst werden.
"""

import json
import threading
import time

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError, NotifyConfig
from loginshield.notify import Notifier


class Sammler:
    """Nimmt Meldungen entgegen, statt sie zu verschicken."""

    def __init__(self, verzoegerung=0.0, fehler=None):
        self.meldungen = []
        self.verzoegerung = verzoegerung
        self.fehler = fehler

    def __call__(self, meldung):
        if self.verzoegerung:
            time.sleep(self.verzoegerung)
        if self.fehler:
            raise self.fehler
        self.meldungen.append(meldung)


@pytest.fixture
def sammler():
    return Sammler()


def mach(sammler, **kwargs):
    einstellungen = {"enabled": True, "method": "webhook",
                     "url": "http://127.0.0.1:9/x", "min_interval": 0}
    einstellungen.update(kwargs)
    notifier = Notifier(NotifyConfig(**einstellungen), sender=sammler)
    return notifier


# -- Grundlagen ----------------------------------------------------------
def test_meldung_wird_zugestellt(sammler):
    notifier = mach(sammler)
    assert notifier.notify("Titel", "Text", schwere=9) is True
    notifier.flush()
    notifier.close()

    assert len(sammler.meldungen) == 1
    assert sammler.meldungen[0].titel == "Titel"


def test_abgeschaltet_meldet_nichts(sammler):
    notifier = Notifier(NotifyConfig(enabled=False), sender=sammler)
    assert notifier.notify("Titel", "Text", schwere=10) is False
    assert sammler.meldungen == []


def test_leichte_ereignisse_gehen_nicht_hinaus(sammler):
    """Sonst kommt bei jedem Tippfehler im Passwort eine Mitteilung."""
    notifier = mach(sammler, min_severity=7)
    assert notifier.notify("Kleinigkeit", "x", schwere=5) is False
    notifier.flush()
    notifier.close()
    assert sammler.meldungen == []


# -- Nichts darf die Anfrage aufhalten -----------------------------------
def test_notify_kehrt_sofort_zurueck():
    """Der Kern der Sache: Zugestellt wird in einem eigenen Faden."""
    langsam = Sammler(verzoegerung=1.5)
    notifier = mach(langsam)

    begonnen = time.time()
    notifier.notify("Sperre", "Text", schwere=9)
    gebraucht = time.time() - begonnen

    assert gebraucht < 0.2, f"notify() hat {gebraucht:.2f}s gebraucht"
    notifier.close(timeout=3)


def test_ein_fehler_beim_versand_schlaegt_nicht_durch():
    kaputt = Sammler(fehler=OSError("Verbindung abgelehnt"))
    notifier = mach(kaputt)

    notifier.notify("Sperre", "Text", schwere=9)   # darf nicht werfen
    notifier.flush()
    notifier.close()
    assert notifier.fehler >= 1


def test_der_faden_ueberlebt_einen_fehler():
    """Nach einem gescheiterten Versand muss der naechste noch gehen."""
    zustand = {"erster": True}
    gesehen = []

    def wechselhaft(meldung):
        if zustand["erster"]:
            zustand["erster"] = False
            raise OSError("einmalig kaputt")
        gesehen.append(meldung)

    notifier = mach(wechselhaft)
    notifier.notify("Erste", "x", schwere=9, kennung="a")
    notifier.notify("Zweite", "y", schwere=9, kennung="b")
    notifier.flush()
    notifier.close()

    assert [m.titel for m in gesehen] == ["Zweite"]


def test_volle_warteschlange_verwirft_statt_zu_bremsen():
    from loginshield import notify as modul

    blockierend = threading.Event()

    def haengt(meldung):
        blockierend.wait(2.0)

    notifier = mach(haengt)
    for index in range(modul.MAX_WARTESCHLANGE + 30):
        notifier.notify(f"M{index}", "x", schwere=9, kennung=f"k{index}")
    blockierend.set()
    notifier.close(timeout=0.5)

    assert notifier.verworfen > 0        # verworfen, nicht gewartet


# -- Niemand liest 400 Meldungen -----------------------------------------
def test_gleichartige_meldungen_werden_zusammengefasst(sammler):
    notifier = mach(sammler, min_interval=300)
    for _ in range(50):
        notifier.notify("IP gesperrt", "x", schwere=9, kennung="block:brute")
    notifier.flush()
    notifier.close()

    assert len(sammler.meldungen) == 1


def test_nach_der_sperrfrist_wieder_eine(sammler):
    uhr = {"jetzt": 1000.0}
    notifier = Notifier(
        NotifyConfig(enabled=True, method="webhook", url="http://127.0.0.1:9/x",
                     min_interval=300),
        clock=lambda: uhr["jetzt"], sender=sammler)

    notifier.notify("IP gesperrt", "x", schwere=9, kennung="k")
    for _ in range(9):
        notifier.notify("IP gesperrt", "x", schwere=9, kennung="k")
    uhr["jetzt"] += 301
    notifier.notify("IP gesperrt", "x", schwere=9, kennung="k")
    notifier.flush()
    notifier.close()

    assert len(sammler.meldungen) == 2
    # In der zweiten steht, wie viele dazwischen lagen.
    assert sammler.meldungen[1].unterdrueckt == 9
    assert "+9 weitere" in sammler.meldungen[1].betreff()


def test_verschiedene_arten_haben_eigene_fristen(sammler):
    notifier = mach(sammler, min_interval=300)
    notifier.notify("A", "x", schwere=9, kennung="block")
    notifier.notify("B", "y", schwere=9, kennung="datei")
    notifier.flush()
    notifier.close()
    assert len(sammler.meldungen) == 2


def test_speicher_waechst_nicht_unbegrenzt(sammler):
    notifier = mach(sammler, min_interval=300)
    for index in range(900):
        notifier.notify("X", "y", schwere=9, kennung=f"kennung{index}")
    notifier.close(timeout=0.5)
    assert len(notifier._letzte) <= 512


# -- Die Wege -----------------------------------------------------------
def test_webhook_schickt_text():
    gesehen = {}

    class FakeAntwort:
        def read(self, n=None): return b"ok"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(anfrage, timeout=None):
        gesehen["url"] = anfrage.full_url
        gesehen["daten"] = anfrage.data
        gesehen["kopf"] = dict(anfrage.header_items())
        return FakeAntwort()

    import urllib.request
    echt = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        notifier = Notifier(NotifyConfig(
            enabled=True, method="webhook", url="https://ntfy.sh/mein-thema",
            format="text", min_interval=0))
        notifier.notify("IP gesperrt", "203.0.113.5", schwere=9)
        notifier.flush()
        notifier.close()
    finally:
        urllib.request.urlopen = echt

    assert gesehen["url"] == "https://ntfy.sh/mein-thema"
    assert b"203.0.113.5" in gesehen["daten"]
    # ntfy macht daraus eine Mitteilung mit Titel und Dringlichkeit.
    assert gesehen["kopf"]["Title"].startswith("[LoginShield]")
    assert gesehen["kopf"]["Priority"] == "high"


def test_webhook_als_json():
    gesehen = {}

    class FakeAntwort:
        def read(self, n=None): return b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    import urllib.request
    echt = urllib.request.urlopen
    urllib.request.urlopen = lambda a, timeout=None: (
        gesehen.update(daten=a.data) or FakeAntwort())
    try:
        notifier = Notifier(NotifyConfig(
            enabled=True, method="webhook", url="http://beispiel.test/haken",
            format="json", min_interval=0))
        notifier.notify("Titel", "Text", schwere=8)
        notifier.flush()
        notifier.close()
    finally:
        urllib.request.urlopen = echt

    daten = json.loads(gesehen["daten"])
    assert daten["titel"] == "Titel" and daten["schwere"] == 8


def test_eigenes_programm_wird_aufgerufen(tmp_path):
    ziel = tmp_path / "gemeldet.txt"
    notifier = Notifier(NotifyConfig(
        enabled=True, method="command", min_interval=0,
        command=["sh", "-c", f"printf '%s' \"$1\" > {ziel}", "sh", "{titel}"]))
    notifier.notify("IP gesperrt", "Text", schwere=9)
    notifier.flush()
    notifier.close()

    assert ziel.read_text() == "IP gesperrt"


def test_email_wird_gebaut(monkeypatch):
    gesendet = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            gesendet["host"] = host
            gesendet["port"] = port
        def starttls(self): gesendet["tls"] = True
        def login(self, user, passwort): gesendet["user"] = user
        def send_message(self, nachricht): gesendet["nachricht"] = nachricht
        def quit(self): pass

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    notifier = Notifier(NotifyConfig(
        enabled=True, method="email", min_interval=0,
        smtp_host="mail.beispiel.test", smtp_user="wache",
        smtp_password="geheim", mail_from="wache@beispiel.test",
        mail_to=["admin@beispiel.test"]))
    notifier.notify("IP gesperrt", "203.0.113.5", schwere=9)
    notifier.flush()
    notifier.close()

    assert gesendet["host"] == "mail.beispiel.test"
    assert gesendet["tls"] is True
    assert gesendet["nachricht"]["To"] == "admin@beispiel.test"
    assert "203.0.113.5" in gesendet["nachricht"].get_content()


# -- Zusammenspiel mit dem Guard ----------------------------------------
def test_sperre_wird_gemeldet(config, store, clock):
    sammler = Sammler()
    config.notify = NotifyConfig(enabled=True, method="webhook",
                                 url="http://127.0.0.1:9/x", min_interval=0)
    guard = Guard(config, store, clock=clock)
    guard.notifier._sender = sammler
    try:
        guard.block("203.0.113.9", reason="brute_force_ip", detail="5 Fehlversuche")
        guard.notifier.flush()
    finally:
        guard.close()

    assert len(sammler.meldungen) == 1
    assert "203.0.113.9" in sammler.meldungen[0].titel
    assert "brute_force_ip" in sammler.meldungen[0].text


def test_netzsperre_wiegt_schwerer(config, store, clock):
    sammler = Sammler()
    config.notify = NotifyConfig(enabled=True, method="webhook",
                                 url="http://127.0.0.1:9/x", min_interval=0,
                                 min_severity=9)
    guard = Guard(config, store, clock=clock)
    guard.notifier._sender = sammler
    try:
        # Einzelsperre (Schwere 7) kommt bei min_severity 9 nicht durch ...
        guard.block("203.0.113.9", reason="brute_force_ip")
        # ... eine Netzsperre schon.
        guard.block("198.51.100.0/24", reason="subnet_abuse")
        guard.notifier.flush()
    finally:
        guard.close()

    assert len(sammler.meldungen) == 1
    assert "198.51.100.0/24" in sammler.meldungen[0].titel


def test_schadcode_wird_gemeldet(config, store, clock, tmp_path):
    sammler = Sammler()
    wurzel = tmp_path / "www"
    wurzel.mkdir()
    (wurzel / "index.php").write_text("<?php echo 1; ?>")

    config.integrity.enabled = True
    config.integrity.paths = [str(wurzel)]
    config.integrity.check_interval = 60
    config.notify = NotifyConfig(enabled=True, method="webhook",
                                 url="http://127.0.0.1:9/x", min_interval=0,
                                 min_severity=10)
    guard = Guard(config, store, clock=clock)
    guard.notifier._sender = sammler
    try:
        guard.integrity.learn()
        (wurzel / "shell.php").write_text("<?php eval($_POST['x']); ?>")
        clock.advance(61)
        guard.maintenance()
        guard.notifier.flush()
    finally:
        guard.close()

    assert len(sammler.meldungen) == 1
    assert "Schadcode" in sammler.meldungen[0].titel
    assert "shell.php" in sammler.meldungen[0].text


def test_ohne_einstellung_passiert_nichts(config, store, clock):
    """Voreingestellt aus - wohin gemeldet wird, weiss nur der Betreiber."""
    guard = Guard(config, store, clock=clock)
    try:
        assert guard.notifier.enabled is False
        guard.block("203.0.113.9", reason="brute_force_ip")
        assert guard.notifier._faden is None      # kein Faden gestartet
    finally:
        guard.close()


# -- Konfiguration ------------------------------------------------------
def test_unvollstaendige_einstellungen_werden_abgelehnt():
    with pytest.raises(ConfigError):
        Config.from_dict({"notify": {"enabled": True, "method": "webhook"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"notify": {"enabled": True, "method": "email"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"notify": {"enabled": True, "method": "command"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"notify": {"method": "brieftaube"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"notify": {"enabled": True, "method": "webhook",
                                     "url": "ntfy.sh/thema"}})   # ohne http


def test_gueltige_einstellungen():
    Config.from_dict({"notify": {"enabled": True, "method": "webhook",
                                 "url": "https://ntfy.sh/thema"}}).validate()
    Config.from_dict({"notify": {"enabled": True, "method": "email",
                                 "smtp_host": "mail.test",
                                 "mail_to": ["a@test"]}}).validate()
