"""Signaturen: Fingerabdruecke bekannter Schadsoftware.

Zwei Dinge muessen stimmen, sonst ist die Pruefung wertlos: Ein Treffer
muss ein Treffer sein (der Fingerabdruck gilt fuer die **ganze** Datei),
und eine kaputte oder leere Liste darf den Schutz nicht abschalten.
"""

import hashlib
import os

import pytest

from loginshield.config import MalwareConfig
from loginshield.filescan import FileScanner
from loginshield.signatures import (
    EICAR,
    SignatureDB,
    aktualisieren,
    hashes_von_bytes,
    hashes_von_datei,
    ist_digest,
    parse_zeile,
)


# -- Zeilen lesen --------------------------------------------------------
@pytest.mark.parametrize("zeile,digest,name,size", [
    ("d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e",
     "unbenannt", -1),
    ("d41d8cd98f00b204e9800998ecf8427e  Trojaner.A",
     "d41d8cd98f00b204e9800998ecf8427e", "Trojaner.A", -1),
    ("d41d8cd98f00b204e9800998ecf8427e:Trojaner.B",
     "d41d8cd98f00b204e9800998ecf8427e", "Trojaner.B", -1),
    # ClamAV: hash:groesse:name
    ("d41d8cd98f00b204e9800998ecf8427e:68:Eicar.Test",
     "d41d8cd98f00b204e9800998ecf8427e", "Eicar.Test", 68),
    ("d41d8cd98f00b204e9800998ecf8427e:*:Beliebig",
     "d41d8cd98f00b204e9800998ecf8427e", "Beliebig", -1),
    # Grossbuchstaben sind dieselben Fingerabdruecke
    ("D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e",
     "unbenannt", -1),
])
def test_zeilenformate(zeile, digest, name, size):
    eintrag = parse_zeile(zeile)
    assert eintrag is not None
    assert (eintrag.digest, eintrag.name, eintrag.size) == (digest, name, size)


@pytest.mark.parametrize("zeile", [
    "", "   ", "# ein Kommentar", "; auch einer",
    "kein-hash", "zzzz8cd98f00b204e9800998ecf8427e",     # kein Hex
    "d41d8cd98f00b204e9800998ecf842",                    # falsche Laenge
])
def test_unbrauchbare_zeilen_werden_uebergangen(zeile):
    """Eine kaputte Zeile darf nicht die ganze Liste unbrauchbar machen."""
    assert parse_zeile(zeile) is None


def test_laenge_bestimmt_das_verfahren():
    assert parse_zeile("a" * 32).algo == "md5"
    assert parse_zeile("a" * 40).algo == "sha1"
    assert parse_zeile("a" * 64).algo == "sha256"
    assert not ist_digest("a" * 50)


# -- Die Liste -----------------------------------------------------------
def test_eicar_ist_eingebaut_und_wird_berechnet():
    """Die eingebaute Signatur ist keine abgeschriebene Zahlenkolonne.

    Sie wird aus der Testdatei selbst berechnet - ein Tippfehler kann sie
    also nicht unbrauchbar machen. Der Vergleich mit dem oeffentlich
    bekannten Wert zeigt, dass die Rechnung stimmt.
    """
    db = SignatureDB()
    treffer = db.match(EICAR)
    assert treffer is not None and treffer.algo == "sha256"
    assert treffer.digest == (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )


def test_ohne_eicar_ist_die_liste_leer():
    assert len(SignatureDB(mit_eicar=False)) == 0


def test_liste_einlesen(tmp_path):
    inhalt = tmp_path / "liste.txt"
    daten = b"schadhafter inhalt"
    digest = hashlib.sha256(daten).hexdigest()
    inhalt.write_text(
        "# Kommentar\n"
        f"{digest}  Boeser.Trojaner\n"
        "kaputte zeile\n"
        "\n"
    )
    db = SignatureDB(mit_eicar=False)
    assert db.load_file(str(inhalt)) == 1
    treffer = db.match(daten)
    assert treffer is not None and treffer.name == "Boeser.Trojaner"
    assert db.match(b"harmlos") is None


def test_verzeichnis_einlesen(tmp_path):
    (tmp_path / "a.txt").write_text("a" * 64 + "  Eins\n")
    (tmp_path / "b.hsb").write_text("b" * 64 + ":*:Zwei\n")
    (tmp_path / "liesmich.md").write_text("c" * 64 + "  Nicht gelesen\n")
    db = SignatureDB(mit_eicar=False)
    assert db.load_dir(str(tmp_path)) == 2
    assert "a" * 64 in db and "c" * 64 not in db


def test_groesse_muss_passen():
    """ClamAV-Signaturen nennen die Dateigroesse - sie zaehlt mit."""
    db = SignatureDB(mit_eicar=False)
    db.add_zeile(f"{hashlib.sha256(b'abc').hexdigest()}:3:Passt")
    assert db.match(b"abc", size=3) is not None
    assert db.match(b"abc", size=99) is None


def test_sha256_schlaegt_md5():
    """Bei zwei Treffern soll der belastbarere die Begruendung liefern."""
    db = SignatureDB(mit_eicar=False)
    daten = b"beides"
    db.add_zeile(f"{hashlib.md5(daten).hexdigest()}  Ueber.MD5")
    db.add_zeile(f"{hashlib.sha256(daten).hexdigest()}  Ueber.SHA256")
    assert db.match(daten).name == "Ueber.SHA256"


def test_nur_gebrauchte_verfahren_werden_gerechnet():
    """Enthaelt die Liste nur SHA-256, muss niemand MD5 rechnen."""
    db = SignatureDB(mit_eicar=False)
    db.add_zeile("a" * 64 + "  Nur SHA-256")
    assert db.algos == ("sha256",)


def test_obergrenze_haelt_den_speicher_klein():
    """Eine fremde Liste darf nicht beliebig viel Speicher belegen."""
    db = SignatureDB(mit_eicar=False, max_signaturen=5)
    for i in range(20):
        db.add_zeile(f"{hashlib.sha256(str(i).encode()).hexdigest()}  Nr{i}")
    assert len(db) == 5
    assert db.uebersprungen == 15


def test_zu_grosse_datei_wird_nicht_eingelesen(tmp_path, monkeypatch):
    import loginshield.signatures as sig
    liste = tmp_path / "riesig.txt"
    liste.write_text("a" * 64 + "  Eins\n")
    monkeypatch.setattr(sig, "MAX_DATEI_BYTES", 10)
    assert SignatureDB(mit_eicar=False).load_file(str(liste)) == 0


# -- Freigabeliste -------------------------------------------------------
def test_freigabe_geht_vor(tmp_path):
    """Der Notausgang fuer einen Fehlalarm: Diese Datei ist in Ordnung."""
    datei = tmp_path / "eigenes_werkzeug.txt"
    datei.write_bytes(EICAR)

    freigabe = tmp_path / "freigabe.txt"
    freigabe.write_text(hashlib.sha256(EICAR).hexdigest() + "  mein Werkzeug\n")

    config = MalwareConfig(signature_dir=str(tmp_path / "leer"),
                           allowlist_files=[str(freigabe)])
    scanner = FileScanner(config)
    assert scanner.scan_file(str(datei)).clean


def test_ohne_freigabe_wird_gefunden(tmp_path):
    datei = tmp_path / "eicar.txt"
    datei.write_bytes(EICAR)
    scanner = FileScanner(MalwareConfig(signature_dir=str(tmp_path / "leer")))
    ergebnis = scanner.scan_file(str(datei))
    assert scanner.is_malicious(ergebnis)
    # Die Testdatei behaelt ihren eigenen Namen: "EICAR-Testdatei" sagt
    # mehr als "bekannte Schadsoftware".
    assert {f.name for f in ergebnis.findings} == {"eicar"}


def test_signatur_zaehlt_auch_neben_anderen_merkmalen(tmp_path):
    """Ein Fingerabdruck darf nicht ausfallen, weil sonst schon etwas
    aufgefallen ist - er ist der belastbarste Befund von allen."""
    datei = tmp_path / "shell.php"
    inhalt = b"<?php eval($_POST['x']); ?>"
    datei.write_bytes(inhalt)

    scanner = FileScanner(MalwareConfig(signature_dir=str(tmp_path / "leer")))
    scanner.signatures.add_zeile(
        f"{hashlib.sha256(inhalt).hexdigest()}  Webshell.Bekannt")

    namen = {f.name for f in scanner.scan_file(str(datei)).findings}
    assert "signatur" in namen and "eval_eingabe" in namen


# -- Fingerabdruck der ganzen Datei --------------------------------------
def test_fingerabdruck_gilt_fuer_die_ganze_datei(tmp_path):
    """Der entscheidende Punkt.

    Die Musterpruefung liest nur den Anfang einer Datei - das reicht ihr.
    Ein Fingerabdruck ueber den Anfang waere dagegen wertlos: Er passt zu
    keiner Signatur. Deshalb wird fuer ihn ueber die ganze Datei gelesen.
    """
    gross = tmp_path / "gross.bin"
    inhalt = b"A" * 300_000 + b"ENDE"
    gross.write_bytes(inhalt)

    config = MalwareConfig(max_scan_bytes=4096,
                           signature_dir=str(tmp_path / "leer"))
    scanner = FileScanner(config)
    scanner.signatures.add_zeile(
        f"{hashlib.sha256(inhalt).hexdigest()}  Gross.Trojaner")

    ergebnis = scanner.scan_file(str(gross))
    assert any(f.name == "signatur" for f in ergebnis.findings)
    # Und der ausgewiesene Wert ist der der Datei, nicht der der ersten
    # 4096 Bytes.
    assert ergebnis.sha256 == hashlib.sha256(inhalt).hexdigest()


def test_hashes_von_datei_bei_zu_grosser_datei(tmp_path):
    datei = tmp_path / "x.bin"
    datei.write_bytes(b"x" * 1000)
    assert hashes_von_datei(str(datei), ("sha256",), max_bytes=100) == {}
    assert hashes_von_datei(str(tmp_path / "gibtsnicht"), ("sha256",)) == {}


def test_hashes_von_bytes_nur_verlangte_verfahren():
    assert set(hashes_von_bytes(b"x", ("sha256",))) == {"sha256"}
    assert set(hashes_von_bytes(b"x")) == {"md5", "sha1", "sha256"}


# -- Aktualisieren -------------------------------------------------------
def test_aktualisieren_aus_datei(tmp_path):
    quelle = tmp_path / "neu.txt"
    quelle.write_text("a" * 64 + "  Eins\n" + "b" * 64 + "  Zwei\n")
    ziel = tmp_path / "unter" / "signaturen.txt"
    anzahl, meldung = aktualisieren(str(quelle), str(ziel))
    assert anzahl == 2 and ziel.exists()
    assert "2" in meldung


def test_aktualisieren_lehnt_ungesicherte_adressen_ab(tmp_path):
    ziel = tmp_path / "s.txt"
    anzahl, meldung = aktualisieren("http://example.invalid/liste.txt", str(ziel))
    assert anzahl == 0
    assert "https" in meldung
    assert not ziel.exists()


def test_leere_antwort_ersetzt_die_alte_liste_nicht(tmp_path):
    """Sonst schaltet eine kaputte Aktualisierung den Schutz still ab."""
    ziel = tmp_path / "signaturen.txt"
    ziel.write_text("a" * 64 + "  Bewaehrt\n")
    leer = tmp_path / "leer.txt"
    leer.write_text("# nur ein Kommentar\n")

    anzahl, meldung = aktualisieren(str(leer), str(ziel))
    assert anzahl == 0
    assert "bisherige" in meldung
    assert "Bewaehrt" in ziel.read_text()


def test_zu_grosse_antwort_wird_abgebrochen(tmp_path):
    ziel = tmp_path / "s.txt"
    quelle = tmp_path / "gross.txt"
    quelle.write_text("a" * 64 + "  Eins\n" + "x" * 5000)
    anzahl, meldung = aktualisieren(str(quelle), str(ziel), max_bytes=100)
    assert anzahl == 0 and not ziel.exists()
    assert "abgebrochen" in meldung


def test_keine_reste_nach_einem_fehlschlag(tmp_path):
    ziel = tmp_path / "s.txt"
    aktualisieren(str(tmp_path / "gibtsnicht"), str(ziel))
    assert [p for p in os.listdir(tmp_path)] == []


def test_fehlende_liste_ist_kein_fehler(tmp_path, caplog):
    """Eine Freigabeliste, in die noch niemand etwas eingetragen hat, ist
    der Normalfall - und keine Warnung wert."""
    import logging

    db = SignatureDB(mit_eicar=False)
    with caplog.at_level(logging.WARNING, logger="loginshield.signatures"):
        assert db.load_file(str(tmp_path / "gibtsnicht.txt")) == 0
    assert caplog.records == []
