"""Zeitung (schreiben, Bilder, veroeffentlichen, drucken) und gesprochener Text."""

import json
import os
import sqlite3

import pytest

from sendestudio import publish, zeitung
from sendestudio.store import Store, zeitung_pruefen
from sendestudio.tresor import ENDUNG, Tresor

from test_sendestudio import Client, wav_bytes
from test_sendestudio_ki import png
from test_sendestudio_sicherheit import Laufend


@pytest.fixture
def lauf(tmp_path):
    l = Laufend(tmp_path)
    yield l
    l.stoppen()


AUSGABE = {
    "name": "Der Dorfbote", "untertitel": "Neues aus dem Tal", "nummer": "Nr. 1",
    "datum": "20. Oktober 2026",
    "artikel": [
        {"rubrik": "Lokales", "ueberschrift": "Brücke wird gebaut", "unterzeile": "Ab Montag",
         "autor": "Lea", "text": "Erster Absatz.\n\nZweiter Absatz."},
        {"ueberschrift": "Wetter", "text": "Sonne satt."},
    ],
}


# ----------------------------------------------------------------------
# Inhalt pruefen und setzen
# ----------------------------------------------------------------------
def test_zeitung_pruefen():
    z = zeitung_pruefen({})
    assert z["name"] == "Die Zeitung" and z["artikel"] == []
    z = zeitung_pruefen(json.dumps({"name": " X ", "artikel": [{"ueberschrift": "A", "fremd": 1}]}))
    assert z["name"] == "X" and set(z["artikel"][0]) == {
        "rubrik", "ueberschrift", "unterzeile", "autor", "text", "bild", "bildtext"}
    with pytest.raises(ValueError):
        zeitung_pruefen({"artikel": [{"bild": "../../etc/passwd"}]})
    with pytest.raises(ValueError):
        zeitung_pruefen({"artikel": [{"bild": "cover-0123456789abcdef0123.png"}]})
    with pytest.raises(ValueError):
        zeitung_pruefen({"artikel": [{}] * 61})
    with pytest.raises(ValueError):
        zeitung_pruefen({"artikel": ["kein Objekt"]})
    with pytest.raises(ValueError):
        zeitung_pruefen("{kaputt")
    assert len(zeitung_pruefen({"artikel": [{"text": "x" * 60000}]})["artikel"][0]["text"]) == 50000


def test_ausgabe_wird_gesetzt_und_maskiert():
    inhalt = zeitung_pruefen(dict(AUSGABE, artikel=AUSGABE["artikel"] + [
        {"ueberschrift": "<script>alert(1)</script>", "text": "a<b>\nzeile",
         "bild": "zeitung-0123456789abcdef0123.png", "bildtext": 'Ein "Bild"'}]))
    html = zeitung.ausgabe(inhalt, bild_pfad="../../medien/")
    assert html.count("<article") == 3 and html.count('class="z-aufmacher"') == 1
    assert '<div class="z-spalten">' in html  # die uebrigen Artikel in Spalten
    assert "<script>" not in html and "&lt;script&gt;" in html and "a&lt;b&gt;<br>zeile" in html
    assert 'src="../../medien/zeitung-0123456789abcdef0123.png"' in html
    assert 'alt="Ein &quot;Bild&quot;"' in html
    assert "<p>Erster Absatz.</p><p>Zweiter Absatz.</p>" in html
    assert "Der Dorfbote" in html and "Nr. 1" in html and "Von Lea" in html
    assert "Noch keine Artikel" in zeitung.ausgabe(zeitung_pruefen({}))


def test_druckansicht_im_stil():
    # Beim Drucken nur die Zeitung: ohne Kopfleiste, Knoepfe und Fusszeile, auf A4
    assert "@page{size:A4" in zeitung.STIL
    assert "@media print" in zeitung.STIL and ".drucken-leiste{display:none" in zeitung.STIL.replace(
        ".nicht-drucken,", "")


# ----------------------------------------------------------------------
# Store: Entwuerfe verschluesselt
# ----------------------------------------------------------------------
def test_store_zeitung_entwurf_verschluesselt(tmp_path):
    tresor = Tresor(str(tmp_path / "tresor.json"), iterationen=1000)
    tresor.anlegen("pw")
    db = str(tmp_path / "db")
    st = Store(db, tresor=tresor)
    z = st.zeitung_anlegen(AUSGABE)
    assert z["inhalt"]["name"] == "Der Dorfbote" and not z["online"] and not z["slug"]
    roh = sqlite3.connect(db).execute("SELECT inhalt FROM zeitungen").fetchone()[0]
    assert "Dorfbote" not in roh and "Brücke" not in roh

    tresor.sperren()
    zu = st.zeitung(z["id"])
    assert zu["verschlossen"] and zu["inhalt"]["artikel"] == []
    with pytest.raises(ValueError):
        st.zeitung_aendern(z["id"], AUSGABE)
    with pytest.raises(ValueError):
        st.zeitung_veroeffentlichen(z["id"])

    tresor.entsperren("pw")
    leer = st.zeitung_anlegen({"name": "Leer"})
    with pytest.raises(ValueError):
        st.zeitung_veroeffentlichen(leer["id"])  # ohne Artikel nichts zu drucken
    online = st.zeitung_veroeffentlichen(z["id"])
    assert online["online"] and online["slug"] == "der-dorfbote-nr-1"
    assert "Dorfbote" in sqlite3.connect(db).execute(
        "SELECT inhalt FROM zeitungen WHERE id = ?", (z["id"],)).fetchone()[0]
    assert st.zeitung_nach_slug("der-dorfbote-nr-1")["id"] == z["id"]
    assert st.zeitung_nach_slug("leer") is None
    liste = st.zeitungen(nur_online=True)
    assert [x["id"] for x in liste] == [z["id"]] and liste[0]["artikel_anzahl"] == 2
    assert liste[0]["kopf"] == {"name": "Der Dorfbote", "nummer": "Nr. 1", "datum": "20. Oktober 2026"}

    # Eine zweite Ausgabe mit gleichem Namen bekommt eine eigene Adresse
    zwei = st.zeitung_anlegen(AUSGABE)
    assert st.zeitung_veroeffentlichen(zwei["id"])["slug"] != online["slug"]

    st.zeitung_zurueckziehen(z["id"])
    roh = sqlite3.connect(db).execute("SELECT inhalt FROM zeitungen WHERE id = ?", (z["id"],)).fetchone()[0]
    assert "Dorfbote" not in roh
    assert st.zeitung_nach_slug("der-dorfbote-nr-1") is None
    # Wieder veroeffentlicht: dieselbe Adresse
    assert st.zeitung_veroeffentlichen(z["id"])["slug"] == "der-dorfbote-nr-1"
    assert st.zeitung_loeschen(z["id"]) == [] and st.zeitung(z["id"]) is None


def test_store_sprechtext_verschluesselt(tmp_path):
    tresor = Tresor(str(tmp_path / "tresor.json"), iterationen=1000)
    tresor.anlegen("pw")
    db = str(tmp_path / "db")
    st = Store(db, tresor=tresor)
    s = st.sendung_anlegen("Sender")
    f = st.folge_anlegen(s["id"], "Folge", sprechtext="Psst, geheimes Skript")
    assert f["sprechtext"] == "Psst, geheimes Skript"
    assert "geheim" not in sqlite3.connect(db).execute("SELECT sprechtext FROM folgen").fetchone()[0]
    tresor.sperren()
    assert st.folge(f["id"])["sprechtext"] == ""
    tresor.entsperren("pw")
    st.folge_aendern(f["id"], datei="a.mp3")
    st.veroeffentlichen(f["id"])
    assert sqlite3.connect(db).execute("SELECT sprechtext FROM folgen").fetchone()[0] == \
        "Psst, geheimes Skript"


# ----------------------------------------------------------------------
# Ueber den Server
# ----------------------------------------------------------------------
def test_zeitung_schreiben_bebildern_drucken(lauf):
    c = lauf.client()
    anonym = Client(lauf.basis)
    assert anonym.json("GET", "/api/zeitungen")[0] == 401

    status, z = c.json("POST", "/api/zeitungen", AUSGABE)
    assert status == 201 and z["inhalt"]["artikel"][0]["ueberschrift"] == "Brücke wird gebaut"

    # Bild hochladen: liegt bis zum Erscheinen im Tresor
    status, inhalt, _ = c("PUT", "/api/zeitungen/bild", roh=png(80, 40))
    assert status == 201, inhalt
    bild = json.loads(inhalt)["bild"]
    assert bild.startswith("zeitung-") and bild.endswith(".png")
    assert lauf.dateien() == [bild + ENDUNG]
    assert c("PUT", "/api/zeitungen/bild", roh=b"kein bild")[0] == 415

    mit_bild = json.loads(json.dumps(AUSGABE))
    mit_bild["artikel"][0].update(bild=bild, bildtext="Die alte Brücke")
    status, z = c.json("PUT", f"/api/zeitungen/{z['id']}", mit_bild)
    assert status == 200 and z["inhalt"]["artikel"][0]["bild"] == bild
    assert c("GET", "/medien/" + bild)[0] == 200  # das Studio sieht es
    assert anonym("GET", "/medien/" + bild)[0] == 404  # sonst niemand
    assert c.json("PUT", f"/api/zeitungen/{z['id']}", {"artikel": [{"bild": "x.png"}]})[0] == 400

    # Vorschau: ungespeichert gesetzt
    status, v = c.json("POST", "/api/zeitungen/vorschau", dict(mit_bild, name="<b>Probe</b>"))
    assert status == 200 and "&lt;b&gt;Probe&lt;/b&gt;" in v["html"]
    assert f'src="/medien/{bild}"' in v["html"]

    # Vor dem Erscheinen: oeffentlich nichts
    assert anonym("GET", "/zeitung/der-dorfbote-nr-1/")[0] == 404
    assert b"Noch keine Ausgabe" in anonym("GET", "/zeitung/")[1]

    status, z = c.json("POST", f"/api/zeitungen/{z['id']}/veroeffentlichen")
    assert status == 200 and z["slug"] == "der-dorfbote-nr-1"
    assert lauf.dateien() == [bild]  # jetzt lesbar
    assert anonym("GET", "/medien/" + bild)[0] == 200

    status, seite, kopf = anonym("GET", "/zeitung/der-dorfbote-nr-1/")
    text = seite.decode()
    assert status == 200 and "script-src 'self'" in kopf["Content-Security-Policy"]
    assert "data-drucken" in text and "Drucken" in text  # der Knopf
    assert 'class="zeitung"' in text and "Brücke wird gebaut" in text
    assert f'src="../../medien/{bild}"' in text and 'href="../../stil.css"' in text
    assert anonym("GET", "/zeitung/der-dorfbote-nr-1")[0] in (200, 301)
    liste = anonym("GET", "/zeitung/")[1].decode()
    assert 'href="der-dorfbote-nr-1/"' in liste and "2 Artikel" in liste
    assert b"window.print()" in anonym("GET", "/seite.js")[1]
    assert b"@media print" in anonym("GET", "/stil.css")[1]
    assert b"@page" in anonym("GET", "/zeitung.css")[1]

    # Bild aus dem Artikel genommen: Datei verschwindet
    ohne = json.loads(json.dumps(mit_bild))
    ohne["artikel"][0]["bild"] = ""
    c.json("PUT", f"/api/zeitungen/{z['id']}", ohne)
    assert lauf.dateien() == []

    # Zurueckziehen und loeschen
    assert c.json("POST", f"/api/zeitungen/{z['id']}/zurueckziehen")[1]["online"] is False
    assert anonym("GET", "/zeitung/der-dorfbote-nr-1/")[0] == 404
    assert c.json("DELETE", f"/api/zeitungen/{z['id']}")[0] == 200
    assert c.json("GET", f"/api/zeitungen/{z['id']}")[0] == 404
    assert c.json("GET", "/api/zeitungen")[1] == []


def test_zeitung_loeschen_raeumt_bilder_weg(lauf):
    c = lauf.client()
    _, inhalt, _ = c("PUT", "/api/zeitungen/bild", roh=png())
    bild = json.loads(inhalt)["bild"]
    _, z = c.json("POST", "/api/zeitungen", {"artikel": [{"ueberschrift": "A", "bild": bild}]})
    assert lauf.dateien() == [bild + ENDUNG]
    c.json("DELETE", f"/api/zeitungen/{z['id']}")
    assert lauf.dateien() == []


def test_entwurf_der_zeitung_liegt_verschluesselt(lauf):
    c = lauf.client()
    c.json("POST", "/api/zeitungen", AUSGABE)
    db = os.path.join(lauf.studio.cfg.datenordner, "sendestudio.db")
    roh = sqlite3.connect(db).execute("SELECT inhalt FROM zeitungen").fetchone()[0]
    assert "Dorfbote" not in roh


def test_website_zeigt_die_zeitung(lauf):
    anonym = Client(lauf.basis)
    start = anonym("GET", "/")[1].decode()
    assert 'href="zeitung/"' in start and "Zeitung lesen" in start
    assert 'href="../zeitung/"' in anonym("GET", "/sendungen/")[1].decode()


def test_export_mit_zeitung_und_sprechtext(lauf, tmp_path):
    c = lauf.client()
    _, inhalt, _ = c("PUT", "/api/zeitungen/bild", roh=png())
    bild = json.loads(inhalt)["bild"]
    _, z = c.json("POST", "/api/zeitungen", {"name": "Blatt", "artikel": [
        {"ueberschrift": "A", "bild": bild}]})
    c.json("POST", f"/api/zeitungen/{z['id']}/veroeffentlichen")
    _, s = c.json("POST", "/api/sendungen", {"titel": "Funk"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Eins", "sprechtext": "Guten Tag."})
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1", roh=wav_bytes(1.0))
    c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")

    status, erg = c.json("POST", "/api/export")
    assert status == 200
    web = tmp_path / "web"
    assert (web / "zeitung" / "index.html").exists()
    seite = (web / "zeitung" / "blatt" / "index.html").read_text()
    assert "data-drucken" in seite and "aria-label=\"Website\"" not in seite
    assert (web / "medien" / bild).exists()
    assert 'href="zeitung/"' in (web / "index.html").read_text()
    assert (web / "s" / "funk" / "eins" / "text.txt").read_text() == "Eins – Funk\n\nGuten Tag.\n"


def test_gesprochener_text(lauf):
    c = lauf.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Funk"})
    status, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen",
                       {"titel": "Eins", "sprechtext": "Hallo <Welt>.\n\nZweiter Teil."})
    assert status == 201 and f["sprechtext"] == "Hallo <Welt>.\n\nZweiter Teil."
    _, f = c.json("PUT", f"/api/folgen/{f['id']}", {"sprechtext": "Hallo <Welt>.\n\nZweiter Teil!"})
    assert f["sprechtext"].endswith("Teil!")
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1", roh=wav_bytes(1.0))
    anonym = Client(lauf.basis)
    assert anonym("GET", "/s/funk/eins/text.txt")[0] == 404  # Entwurf
    c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")

    seite = anonym("GET", "/s/funk/eins/")[1].decode()
    assert "Gesprochener Text" in seite and "Hallo &lt;Welt&gt;." in seite
    status, text, kopf = anonym("GET", "/s/funk/eins/text.txt")
    assert status == 200 and kopf["Content-Type"].startswith("text/plain")
    assert text.decode() == "Eins – Funk\n\nHallo <Welt>.\n\nZweiter Teil!\n"
    feed = anonym("GET", "/s/funk/feed.xml")[1].decode()
    assert ('<podcast:transcript url="https://sender.example/s/funk/eins/text.txt" '
            'type="text/plain"') in feed

    # Ohne Text: kein Abschnitt, keine Datei, kein Eintrag im Feed
    _, g = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Zwei"})
    c("PUT", f"/api/folgen/{g['id']}/medium?dauer=1", roh=wav_bytes(1.0))
    c.json("POST", f"/api/folgen/{g['id']}/veroeffentlichen")
    assert "Gesprochener Text" not in anonym("GET", "/s/funk/zwei/")[1].decode()
    assert anonym("GET", "/s/funk/zwei/text.txt")[0] == 404
    assert anonym("GET", "/s/funk/feed.xml")[1].decode().count("podcast:transcript") == 1


def test_medien_liste_enthaelt_zeitungsbilder(tmp_path):
    st = Store(str(tmp_path / "db"))
    z = st.zeitung_anlegen({"artikel": [{"ueberschrift": "A", "bild": "zeitung-0123456789abcdef0123.jpg"}]})
    assert publish.medien(st) == []
    st.zeitung_veroeffentlichen(z["id"])
    assert publish.medien(st) == ["zeitung-0123456789abcdef0123.jpg"]
    assert st.datei_in_benutzung("zeitung-0123456789abcdef0123.jpg")
    assert not st.datei_in_benutzung("zeitung-ffffffffffffffffffff.jpg")
