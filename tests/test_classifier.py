"""Lernende Dateierkennung: Schaedlinge finden, die niemand kennt.

Bei einer lernenden Erkennung ist die Trefferquote nicht das Schwierige -
es ist die Gegenprobe. Ein Verfahren, das jede zweite eigene Datei meldet,
ist wertlos, auch wenn es jeden Schaedling findet. Der groesste Teil
dieser Tests prueft deshalb, dass **nichts** gemeldet wird.
"""

import base64
import json
import os

import pytest

from loginshield.classifier import (
    GRUNDLINIE_KEY,
    MAX_PUNKTE,
    MIN_DATEIEN,
    Klassifikator,
    dateiklasse,
    merkmale,
)
from loginshield.config import MalwareConfig
from loginshield.filescan import FileScanner


def _quelltext(zeilen: int = 60, breite: int = 70) -> bytes:
    """Etwas, das aussieht wie gewoehnlicher Programmtext."""
    muster = (
        "def berechne_summe(werte, faktor=1):\n"
        "    ergebnis = 0\n"
        "    for wert in werte:\n"
        "        ergebnis += wert * faktor\n"
        "    return ergebnis\n"
    )
    return (muster * zeilen)[: zeilen * breite].encode()


def _lerne(tmp_path, anzahl: int = MIN_DATEIEN + 5, max_punkte=None,
           **kw) -> Klassifikator:
    """Legt gewoehnliche Dateien an und lernt daraus."""
    ordner = tmp_path / "normal"
    ordner.mkdir(exist_ok=True)
    for i in range(anzahl):
        (ordner / f"modul{i}.py").write_bytes(_quelltext(40 + i))
    k = Klassifikator(max_punkte=max_punkte)
    k.lernen([str(ordner)], speichern=False, **kw)
    return k


# -- Messen --------------------------------------------------------------
def test_entropie_unterscheidet_text_von_zufall():
    """Das Grundmass: Zufall ist unordentlich, Text ist es nicht."""
    assert merkmale(os.urandom(8000))["entropie"] > 7.9
    assert merkmale(_quelltext())["entropie"] < 5.5
    assert merkmale(b"aaaaaaaaaaaaaaaa")["entropie"] < 0.1


def test_leere_datei_hat_keine_merkmale():
    assert all(wert == 0.0 for wert in merkmale(b"").values())


def test_lange_zeile_wird_gemessen():
    assert merkmale(b"kurz\n" + b"x" * 5000)["zeile_max"] == 5000


def test_eingebettetes_bild_ist_kein_block():
    """Ein data:-Bild ist ein langer base64-Block mit harmlosem Grund."""
    bild = base64.b64encode(os.urandom(900))
    assert merkmale(b'<img src="data:image/png;base64,' + bild + b'">')[
        "block_max"] == 0
    # Derselbe Block ohne data:-Kennung zaehlt sehr wohl.
    assert merkmale(b"$x='" + bild + b"';")["block_max"] > 1000


@pytest.mark.parametrize("name,daten,klasse", [
    ("foto.jpg", b"\xff\xd8\xff\xe0" + b"\x01" * 100, "gepackt"),
    ("programm", b"\x7fELF\x02\x01" + b"\x00" * 100, "programm"),
    ("modul.py", b"import os\nprint('hallo')\n", "text"),
    # Die Endung sagt Bild, der Inhalt ist Text - die Endung entscheidet
    # nicht allein, aber ein .jpg wird nicht mit Quelltext verglichen.
    ("getarnt.jpg", b"<?php echo 1; ?>", "gepackt"),
])
def test_dateiklassen(name, daten, klasse):
    assert dateiklasse(name, daten) == klasse


# -- Ohne Grundlinie ------------------------------------------------------
def test_gepackter_inhalt_faellt_auch_ohne_lernen_auf():
    """Eine .php-Datei aus reinem Zufall ist keine .php-Datei."""
    befund = Klassifikator().bewerten(os.urandom(5000), "update.php")
    assert befund.punkte == 5
    assert befund.signale[0].name == "entropie_gepackt"


def test_echtes_bild_wird_nicht_gemeldet():
    """Ein Bild *ist* gepackt - das ist kein Verdacht, sondern normal."""
    assert Klassifikator().bewerten(
        b"\xff\xd8\xff\xe0" + os.urandom(5000), "urlaub.jpg").punkte == 0


def test_ohne_grundlinie_wird_das_gesagt():
    befund = Klassifikator().bewerten(_quelltext(), "modul.py")
    assert befund.punkte == 0
    assert "nichts gelernt" in befund.grund


# -- Lernen ---------------------------------------------------------------
def test_lernen_bildet_klassen(tmp_path):
    k = _lerne(tmp_path)
    grundlinie = k.grundlinie()
    assert grundlinie.klassen["text"].dateien >= MIN_DATEIEN
    assert grundlinie.klassen["text"].werte["entropie"]["median"] > 0
    assert k.bereit


def test_zu_wenig_gelernt_heisst_kein_urteil(tmp_path):
    """Ohne genug Daten wird nicht geurteilt, sondern das gesagt."""
    k = _lerne(tmp_path, anzahl=3)
    befund = k.bewerten(b"$x='" + base64.b64encode(os.urandom(3000)) + b"';",
                        "shell.php")
    assert "zu wenig gelernt" in befund.grund


def test_gelerntes_ueberlebt_einen_neustart(tmp_path, store):
    """Die Grundlinie liegt in derselben Ablage wie alles Gelernte."""
    ordner = tmp_path / "code"
    ordner.mkdir()
    for i in range(MIN_DATEIEN + 2):
        (ordner / f"m{i}.py").write_bytes(_quelltext(30 + i))

    Klassifikator(store=store).lernen([str(ordner)])
    # Ein frischer Klassifikator liest sie wieder ein.
    frisch = Klassifikator(store=store)
    assert frisch.bereit
    assert frisch.grundlinie().dateien >= MIN_DATEIEN


def test_unlesbare_grundlinie_wird_uebergangen(store):
    """Kaputte gelernte Daten duerfen die Pruefung nicht umwerfen."""
    store.set_meta(GRUNDLINIE_KEY, "{kein json")
    k = Klassifikator(store=store)
    assert k.grundlinie() is None
    assert k.bewerten(_quelltext(), "m.py").punkte == 0     # kein Absturz


# -- Erkennen -------------------------------------------------------------
def test_verschleierte_webshell_faellt_auf(tmp_path):
    """Der Fall, um den es geht: kein bekannter Hash, kein bekanntes Muster."""
    k = _lerne(tmp_path)
    nutzlast = base64.b64encode(os.urandom(4000))
    befund = k.bewerten(b"<?php $k='" + nutzlast + b"'; ?>", "wartung.php")
    assert befund.auffaellig
    assert {s.name for s in befund.signale} >= {"zeile_max", "block_max"}


def test_jedes_urteil_ist_begruendet(tmp_path):
    k = _lerne(tmp_path)
    befund = k.bewerten(b"$x='" + base64.b64encode(os.urandom(4000)) + b"';",
                        "x.php")
    for signal in befund.signale:
        assert signal.beschreibung
        assert signal.beobachtet != signal.erwartet
    assert befund.grund


def test_statistik_allein_legt_nichts_beiseite(tmp_path):
    """Der wichtigste Grundsatz des Moduls.

    Die Punktzahl ist gedeckelt und bleibt unter der Schwelle, ab der eine
    Datei in Quarantaene wandert. Ein Verdacht ist kein Beweis.
    """
    k = _lerne(tmp_path)
    # Etwas so Auffaelliges wie moeglich: lang, zufaellig, ohne Zeilen.
    befund = k.bewerten(base64.b64encode(os.urandom(20000)), "boese.php")
    assert befund.punkte <= MAX_PUNKTE
    assert befund.punkte < MalwareConfig().block_score


def test_gewoehnliche_dateien_werden_nicht_gemeldet(tmp_path):
    """Die Gegenprobe - und die Lehre aus dem ersten Versuch.

    Gelernt wird an Quelltext, der sehr einheitlich aussieht. Ohne
    Mindestspielraum galt danach jede Datei mit etwas laengeren Zeilen als
    verdaechtig: elf von 59 eigenen Dateien wurden gemeldet.
    """
    k = _lerne(tmp_path)
    for name, inhalt in (
        ("modul.py", _quelltext()),
        ("liesmich.md", b"# Titel\n\n" + b"Ein Satz ueber das Projekt. " * 40),
        ("daten.json", json.dumps({"a": list(range(200))}).encode()),
        ("seite.html", b"<html><body>" + b"<p>Text</p>" * 200 + b"</body>"),
        ("konfig.yaml", b"schluessel: wert\nliste:\n  - eins\n  - zwei\n" * 20),
    ):
        assert k.bewerten(inhalt, name).punkte == 0, f"Fehlalarm bei {name}"


def test_ein_schaedling_im_gelernten_bestand_verdirbt_nichts(tmp_path):
    """Robuste Statistik heisst: ein Ausreisser verschiebt nichts.

    Waere beim Lernen schon eine Webshell dabei, wuerde ein Mittelwert die
    Erwartung so weit aufblaehen, dass hinterher nichts mehr auffaellt.
    Der Median tut das nicht.
    """
    ordner = tmp_path / "mit_schaedling"
    ordner.mkdir()
    for i in range(MIN_DATEIEN + 5):
        (ordner / f"m{i}.py").write_bytes(_quelltext(40 + i))
    (ordner / "schon_da.php").write_bytes(
        b"$x='" + base64.b64encode(os.urandom(9000)) + b"';")

    k = Klassifikator()
    k.lernen([str(ordner)], speichern=False)
    neuer = b"<?php $y='" + base64.b64encode(os.urandom(4000)) + b"'; ?>"
    assert k.bewerten(neuer, "neu.php").auffaellig


# -- Im Zusammenspiel mit dem Scanner ------------------------------------
def test_scanner_nimmt_die_erkennung_auf(tmp_path):
    datei = tmp_path / "getarnt.php"
    datei.write_bytes(os.urandom(4000))
    scanner = FileScanner(MalwareConfig(
        signature_dir=str(tmp_path / "leer"), clamav="off"))
    ergebnis = scanner.scan_file(str(datei))
    assert "unueblich" in {f.name for f in ergebnis.findings}


def test_erkennung_laesst_sich_abschalten(tmp_path):
    datei = tmp_path / "getarnt.php"
    datei.write_bytes(os.urandom(4000))
    scanner = FileScanner(MalwareConfig(
        learning=False, signature_dir=str(tmp_path / "leer"), clamav="off"))
    assert scanner.klassifikator is None
    assert "unueblich" not in {
        f.name for f in scanner.scan_file(str(datei)).findings}


def test_zusammen_mit_einem_merkmal_wird_ein_urteil_daraus(tmp_path):
    """So ist es gedacht: Die Statistik gibt den Ausschlag, nicht den Ton an."""
    inhalt = (b"<?php $k='" + base64.b64encode(os.urandom(4000))
              + b"'; eval(base64_decode($k)); ?>")
    datei = tmp_path / "shell.php"
    datei.write_bytes(inhalt)

    scanner = FileScanner(
        MalwareConfig(signature_dir=str(tmp_path / "leer"), clamav="off"),
        klassifikator=_lerne(tmp_path),
    )
    ergebnis = scanner.scan_file(str(datei))
    assert scanner.is_malicious(ergebnis)
    namen = {f.name for f in ergebnis.findings}
    assert "eval_base64" in namen and "unueblich" in namen


def test_status_ohne_gelerntes():
    status = Klassifikator().status()
    assert status["bereit"] is False
    assert status["dateien"] == 0


# -- Aus der Durchsicht --------------------------------------------------
def test_spaeter_gelerntes_wird_nachgeladen(tmp_path, store, monkeypatch):
    """Der Fall aus der Durchsicht.

    Die Grundlinie wurde einmal geladen und nie wieder. Ein laufender
    Waechter bekam damit nie mit, dass nebenan 'erkennung --learn' etwas
    gelernt hatte - er arbeitete bis zum Neustart ohne Grundlinie weiter.
    """
    import loginshield.classifier as c

    laufend = Klassifikator(store=store)
    assert laufend.grundlinie() is None          # noch nichts da

    # Jemand anderes lernt - in einem anderen Vorgang, dieselbe Ablage.
    ordner = tmp_path / "code"
    ordner.mkdir()
    for i in range(MIN_DATEIEN + 2):
        (ordner / f"m{i}.py").write_bytes(_quelltext(30 + i))
    Klassifikator(store=store).lernen([str(ordner)])

    # Sofort danach gilt noch die gemerkte Antwort - eine Abfrage je
    # gepruefter Datei waere zu teuer.
    assert laufend.grundlinie() is None

    # Nach Ablauf der Frist wird nachgesehen.
    monkeypatch.setattr(c, "NACHLADEN_NACH", 0.0)
    assert laufend.grundlinie() is not None
    assert laufend.bereit


def test_fest_vorgegebene_grundlinie_wird_nicht_ueberschrieben(tmp_path, store):
    """Wer eine Grundlinie mitgibt, meint genau diese."""
    eigene = Klassifikator().lernen(
        [str(tmp_path)], speichern=False)          # leer, aber vorhanden
    k = Klassifikator(store=store, grundlinie=eigene)
    store.set_meta(GRUNDLINIE_KEY, '{"dateien": 999, "klassen": {}}')
    assert k.grundlinie() is eigene


def test_deckel_folgt_der_eingestellten_schwelle(tmp_path):
    """Der Grundsatz 'Statistik allein legt nichts beiseite' galt nur bei
    der Voreinstellung block_score 8 - wer die Schwelle heruntersetzte,
    haette ihn still ausgehebelt."""
    inhalt = base64.b64encode(os.urandom(20000))
    datei = tmp_path / "auffaellig.php"
    datei.write_bytes(inhalt)

    for schwelle in (2, 4, 8, 12):
        scanner = FileScanner(
            MalwareConfig(block_score=schwelle,
                          signature_dir=str(tmp_path / "leer"), clamav="off"),
            klassifikator=_lerne(tmp_path, max_punkte=schwelle - 1),
        )
        befund = scanner.klassifikator.bewerten(inhalt, "auffaellig.php")
        assert befund.punkte < schwelle, (
            f"bei block_score {schwelle} wuerde Statistik allein "
            f"beiseitelegen ({befund.punkte} Punkte)"
        )
