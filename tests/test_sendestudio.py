"""Sendestudio: Speicher, Medien, Feed, Radio, Export und der Server von aussen."""

import ftplib
import http.cookiejar
import io
import json
import os
import struct
import threading
import urllib.error
import urllib.request
import wave
import xml.dom.minidom

import pytest

from sendestudio import media, publish, radio
from sendestudio.config import Config, laden, passwort_hash, passwort_pruefen, speichern
from sendestudio.feed import feed
from sendestudio.server import Studio, server_starten
from sendestudio.store import Store, kapitel_pruefen, slugify


def wav_bytes(sekunden=1.0, rate=8000):
    puffer = io.BytesIO()
    with wave.open(puffer, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(struct.pack("<h", 0) * int(rate * sekunden))
    return puffer.getvalue()


# ----------------------------------------------------------------------
# Speicher
# ----------------------------------------------------------------------
def test_slugify():
    assert slugify("Über Bäume & Straßen!") == "ueber-baeume-strassen"
    assert slugify("!!!") == "sendung"


def test_sendung_und_folgen(tmp_path):
    st = Store(str(tmp_path / "db"))
    s = st.sendung_anlegen("Mein Podcast", "podcast", beschreibung="Hallo")
    zweite = st.sendung_anlegen("Mein Podcast", "radio")
    assert (s["slug"], zweite["slug"]) == ("mein-podcast", "mein-podcast-2")
    with pytest.raises(ValueError):
        st.sendung_anlegen("X", "fernsehen")
    with pytest.raises(ValueError):
        st.sendung_anlegen("  ")

    f = st.folge_anlegen(s["id"], "Folge 1", kapitel=[{"zeit": 9, "titel": "B"}, {"zeit": 1, "titel": "A"}])
    assert [k["titel"] for k in f["kapitel"]] == ["A", "B"]
    with pytest.raises(ValueError):
        st.veroeffentlichen(f["id"])  # ohne Datei geht nichts online
    st.folge_aendern(f["id"], datei="a.mp3", mime="audio/mpeg", dauer=10)
    st.veroeffentlichen(f["id"], zeitpunkt=1000)
    assert [x["id"] for x in st.folgen(s["id"], nur_online=True)] == [f["id"]]
    st.zurueckziehen(f["id"])
    assert st.folgen(s["id"], nur_online=True) == []

    assert st.datei_in_benutzung("a.mp3")
    assert st.sendung_loeschen(s["id"]) == ["a.mp3"]
    assert st.folge(f["id"]) is None  # Folgen gehen mit
    assert not st.datei_in_benutzung("a.mp3")


def test_kapitel_pruefen():
    with pytest.raises(ValueError):
        kapitel_pruefen([{"zeit": -1}])
    with pytest.raises(ValueError):
        kapitel_pruefen("kein json")
    assert kapitel_pruefen([{"zeit": "2.5", "titel": ""}]) == [{"zeit": 2.5, "titel": "Kapitel"}]


# ----------------------------------------------------------------------
# Medien
# ----------------------------------------------------------------------
@pytest.mark.parametrize("kopf,erwartet", [
    (b"ID3\x04" + b"\0" * 20, ".mp3"),
    (b"OggS" + b"\0" * 20, ".ogg"),
    (b"\x1a\x45\xdf\xa3" + b"\0" * 20, ".webm"),
    (b"\0\0\0\x20ftypM4A " + b"\0" * 12, ".m4a"),
    (b"\0\0\0\x20ftypisom" + b"\0" * 12, ".mp4"),
    (b"\x89PNG\r\n\x1a\n" + b"\0" * 8, ".png"),
    (b"\xff\xd8\xff\xe0" + b"\0" * 8, ".jpg"),
])
def test_erkennen(kopf, erwartet):
    assert media.erkennen(kopf)[0] == erwartet


def test_erkennen_weist_html_ab():
    assert media.erkennen(b"<script>alert(1)</script>") is None
    assert media.erkennen(b"<?xml version='1.0'?><svg") is None
    assert media.erkennen(wav_bytes())[0] == ".wav"


# ----------------------------------------------------------------------
# Radio und Feed
# ----------------------------------------------------------------------
def _folge(i, dauer, veroeffentlicht):
    return {"id": i, "titel": f"F{i}", "datei": f"f{i}.mp3", "dauer": dauer, "online": True,
            "veroeffentlicht": veroeffentlicht, "mime": "audio/mpeg", "groesse": 100,
            "slug": f"f{i}", "beschreibung": "", "kapitel": []}


def test_radio_nach_der_uhr():
    folgen = [_folge(2, 60, 200), _folge(1, 100, 100), _folge(3, 0, 300)]  # Nr. 3 ohne Dauer
    a = radio.ANKER
    assert radio.jetzt(folgen, a)["folge"]["id"] == 1
    j = radio.jetzt(folgen, a + 130)
    assert j["folge"]["id"] == 2 and j["offset"] == pytest.approx(30)
    assert radio.jetzt(folgen, a + 160 * 5 + 1)["folge"]["id"] == 1  # Schleife
    assert radio.jetzt([], a) is None


def test_feed_ist_gueltiges_rss():
    s = {"slug": "test", "titel": "Test & <Co>", "art": "podcast", "beschreibung": "",
         "autor": "", "sprache": "de", "kategorie": "", "cover": "c.png"}
    f = _folge(1, 3725, 1_700_000_000)
    f["kapitel"] = [{"zeit": 1.5, "titel": 'Ein "Kapitel"'}]
    text = feed(s, [f], "https://radio.example/")
    dom = xml.dom.minidom.parseString(text.encode())
    enc = dom.getElementsByTagName("enclosure")[0]
    assert enc.getAttribute("url") == "https://radio.example/medien/f1.mp3"
    assert dom.getElementsByTagName("itunes:duration")[0].firstChild.data == "01:02:05"
    assert dom.getElementsByTagName("psc:chapter")[0].getAttribute("start") == "00:00:01.500"
    assert dom.getElementsByTagName("title")[0].firstChild.data == "Test & <Co>"


# ----------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------
def test_export_raeumt_zurueckgezogenes_weg(tmp_path):
    medien = tmp_path / "medien"
    medien.mkdir()
    (medien / "a.mp3").write_bytes(b"ID3a")
    (medien / "b.mp3").write_bytes(b"ID3b")
    st = Store(str(tmp_path / "db"))
    s = st.sendung_anlegen("Sender", "radio")
    fa = st.folge_anlegen(s["id"], "A", datei="a.mp3", mime="audio/mpeg", dauer=5)
    fb = st.folge_anlegen(s["id"], "B", datei="b.mp3", mime="audio/mpeg", dauer=5)
    st.veroeffentlichen(fa["id"])
    st.veroeffentlichen(fb["id"])
    ziel = tmp_path / "web"
    ziel.mkdir()
    (ziel / "eigene-datei.txt").write_text("bleibt")

    erg = publish.exportieren(st, str(medien), str(ziel), basis_url="https://x.example")
    for pfad in ("index.html", "stil.css", "seite.js", "s/sender/index.html", "s/sender/feed.xml",
                 "s/sender/a/index.html", "s/sender/radio/index.html", "medien/b.mp3"):
        assert (ziel / pfad).exists(), pfad
    assert not erg["ohne_feed"]

    st.zurueckziehen(fb["id"])
    publish.exportieren(st, str(medien), str(ziel), basis_url="https://x.example")
    assert not (ziel / "medien" / "b.mp3").exists()
    assert not (ziel / "s" / "sender" / "b").exists()
    assert (ziel / "medien" / "a.mp3").exists()
    assert (ziel / "eigene-datei.txt").read_text() == "bleibt"


def test_export_ohne_basis_url_ohne_feed(tmp_path):
    st = Store(str(tmp_path / "db"))
    s = st.sendung_anlegen("P")
    f = st.folge_anlegen(s["id"], "A", datei="a.mp3", mime="audio/mpeg")
    st.veroeffentlichen(f["id"])
    erg = publish.exportieren(st, str(tmp_path), str(tmp_path / "web"))
    assert erg["ohne_feed"]
    assert not (tmp_path / "web" / "s" / "p" / "feed.xml").exists()


class FakeFtp:
    def __init__(self):
        self.dateien, self.ordner = {}, set()

    def mkd(self, p):
        self.ordner.add(p)

    def size(self, p):
        if p not in self.dateien:
            raise ftplib.error_perm("550 gibt es nicht")
        return len(self.dateien[p])

    def storbinary(self, befehl, f):
        self.dateien[befehl[5:]] = f.read()

    def quit(self):
        pass


def test_ftp_laedt_hoch_und_ueberspringt_gleiche_medien(tmp_path):
    (tmp_path / "medien").mkdir()
    (tmp_path / "index.html").write_text("x")
    (tmp_path / "medien" / "a.mp3").write_bytes(b"ID3")
    (tmp_path / publish.MANIFEST).write_text("[]")
    ftp = FakeFtp()
    erg = publish.ftp_hochladen(str(tmp_path), host="", benutzer="", passwort="",
                                pfad="/www", verbindung=ftp)
    assert erg == {"hochgeladen": 2, "uebersprungen": 0}
    assert set(ftp.dateien) == {"/www/index.html", "/www/medien/a.mp3"}
    erg = publish.ftp_hochladen(str(tmp_path), host="", benutzer="", passwort="",
                                pfad="/www", verbindung=ftp)
    assert erg == {"hochgeladen": 1, "uebersprungen": 1}


# ----------------------------------------------------------------------
# Konfiguration
# ----------------------------------------------------------------------
def test_passwort_und_config(tmp_path):
    h = passwort_hash("geheim", iterationen=1000)
    assert passwort_pruefen("geheim", h)
    assert not passwort_pruefen("falsch", h)
    assert not passwort_pruefen("x", "kaputt")

    pfad = str(tmp_path / "s.json")
    speichern(Config(passwort_hash=h, seitentitel="Ä"), pfad)
    assert oct(os.stat(pfad).st_mode & 0o777) == "0o600"
    cfg = laden(pfad)
    assert cfg.seitentitel == "Ä" and cfg.datenordner == str(tmp_path / "sendestudio-daten")
    with open(pfad, "w") as f:
        json.dump({"tippfehler": 1}, f)
    with pytest.raises(ValueError):
        laden(pfad)


# ----------------------------------------------------------------------
# Server von aussen
# ----------------------------------------------------------------------
PASSWORT = "richtig-langes-passwort"


@pytest.fixture
def server(tmp_path):
    cfg = Config(daten=str(tmp_path / "daten"), passwort_hash=passwort_hash(PASSWORT, iterationen=1000),
                 basis_url="https://sender.example", geheimnis="test",
                 export_ziel=str(tmp_path / "web"))
    studio = Studio(cfg, tresor_iterationen=1000)
    srv = server_starten(studio, "127.0.0.1", 0)
    faden = threading.Thread(target=srv.serve_forever, daemon=True)
    faden.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", studio
    srv.shutdown()
    srv.server_close()
    studio.close()


class Client:
    def __init__(self, basis):
        self.basis = basis
        self.oeffner = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def __call__(self, methode, pfad, daten=None, roh=None, kopf=None):
        k = {"X-Studio": "1"}
        k.update(kopf or {})
        body = roh
        if daten is not None:
            body = json.dumps(daten).encode()
            k["Content-Type"] = "application/json"
        req = urllib.request.Request(self.basis + pfad, data=body, method=methode, headers=k)
        try:
            with self.oeffner.open(req) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as f:
            return f.code, f.read(), dict(f.headers)

    def json(self, methode, pfad, daten=None, **kw):
        status, inhalt, _ = self(methode, pfad, daten, **kw)
        return status, json.loads(inhalt or b"{}")


def test_ablauf_aufnehmen_veroeffentlichen(server):
    basis, studio = server
    c = Client(basis)
    assert c.json("GET", "/api/sendungen")[0] == 401
    assert c.json("POST", "/api/login", {"passwort": PASSWORT})[0] == 200

    status, s = c.json("POST", "/api/sendungen", {"titel": "Nachtfunk", "art": "radio"})
    assert status == 201
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen",
                  {"titel": "Erste Stunde", "kapitel": [{"zeit": 0, "titel": "Hallo"}]})
    status, inhalt, _ = c("PUT", f"/api/folgen/{f['id']}/medium?dauer=2", roh=wav_bytes(2.0))
    assert status == 200, inhalt
    f = json.loads(inhalt)
    assert f["dauer"] == pytest.approx(2.0, abs=0.3)
    assert f["mime"] == ("audio/mpeg" if media.ffmpeg_verfuegbar() else "audio/wav")

    # Entwurf: oeffentlich unsichtbar, auch die Datei.
    anonym = Client(basis)
    assert anonym("GET", "/s/nachtfunk/")[0] == 404
    assert anonym("GET", "/medien/" + f["datei"])[0] == 404
    assert c("GET", "/medien/" + f["datei"])[0] == 200  # das Studio darf vorhoeren

    assert c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")[0] == 200
    status, seite, kopf = anonym("GET", "/s/nachtfunk/")
    assert status == 200 and b"Erste Stunde" in seite
    assert "script-src 'self'" in kopf["Content-Security-Policy"]
    assert anonym("GET", "/s/nachtfunk/erste-stunde/")[0] == 200
    assert anonym("GET", "/s/nachtfunk/radio/")[0] == 200
    status, xml_text, _ = anonym("GET", "/s/nachtfunk/feed.xml")
    assert b"https://sender.example/medien/" + f["datei"].encode() in xml_text

    status, teil, kopf = anonym("GET", "/medien/" + f["datei"], kopf={"Range": "bytes=10-19"})
    assert status == 206 and len(teil) == 10
    assert kopf["Content-Range"].startswith("bytes 10-19/")

    status, erg = c.json("POST", "/api/export", {})
    assert status == 200 and erg["dateien"] > 5
    assert os.path.exists(os.path.join(erg["ziel"], "s", "nachtfunk", "feed.xml"))

    # Loeschen raeumt die Datei mit weg.
    assert c.json("DELETE", f"/api/sendungen/{s['id']}")[0] == 200
    assert not [n for n in os.listdir(studio.cfg.medienordner) if n.startswith(f["datei"])]


def test_upload_nur_echte_medien(server):
    basis, _ = server
    c = Client(basis)
    c.json("POST", "/api/login", {"passwort": PASSWORT})
    _, s = c.json("POST", "/api/sendungen", {"titel": "P"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "F"})
    status, antwort = c.json("PUT", f"/api/folgen/{f['id']}/medium",
                             roh=b"<html><script>alert(1)</script></html>")
    assert status == 415
    assert c.json("PUT", f"/api/sendungen/{s['id']}/cover", roh=wav_bytes())[0] == 415
    status, neu = c.json("PUT", f"/api/sendungen/{s['id']}/cover",
                         roh=b"\x89PNG\r\n\x1a\n" + b"\0" * 64)
    assert status == 200 and neu["cover"].endswith(".png")
    # Keine Reste der abgelehnten Uploads
    assert not [n for n in os.listdir(server[1].cfg.medienordner) if n.startswith(".")]


def test_api_ohne_studio_kopf_wird_abgelehnt(server):
    basis, _ = server
    c = Client(basis)
    c.json("POST", "/api/login", {"passwort": PASSWORT})
    req = urllib.request.Request(basis + "/api/sendungen", data=b'{"titel":"x"}', method="POST")
    with pytest.raises(urllib.error.HTTPError) as fehler:
        c.oeffner.open(req)
    assert fehler.value.code == 403


def test_login_sperrt_nach_fehlversuchen(server):
    basis, _ = server
    c = Client(basis)
    codes = [c.json("POST", "/api/login", {"passwort": "falsch"})[0] for _ in range(7)]
    assert codes[0] == 401
    assert 429 in codes
    # Auch das richtige Passwort hilft dann nicht mehr.
    status, _, kopf = c("POST", "/api/login", {"passwort": PASSWORT})
    assert status == 429 and int(kopf["Retry-After"]) > 0


def test_pfad_tricks_bei_medien(server):
    basis, _ = server
    c = Client(basis)
    for pfad in ("/medien/../sendestudio.db", "/medien/%2e%2e%2fsendestudio.db",
                 "/medien/.hochladen-x", "/s/../../etc/passwd"):
        assert c("GET", pfad)[0] == 404, pfad


def test_mp3_dauer_ohne_ffmpeg(tmp_path):
    # MPEG-1 Layer III, 128 kbit/s, 44,1 kHz, ohne Xing-Kopf: Laenge aus der Bitrate
    frame = b"\xff\xfb\x90\x00" + b"\0" * 413
    (tmp_path / "a.mp3").write_bytes(b"ID3\x04\0\0\0\0\0\0" + frame * 100)
    assert media.mp3_dauer_schaetzen(str(tmp_path / "a.mp3")) == pytest.approx(2.61, abs=0.02)
    # Mit Xing-Kopf: die Frame-Zahl gilt
    xing = bytearray(frame)
    xing[36:48] = b"Xing\0\0\0\x01" + (1000).to_bytes(4, "big")
    (tmp_path / "b.mp3").write_bytes(bytes(xing) + frame * 10)
    assert media.mp3_dauer_schaetzen(str(tmp_path / "b.mp3")) == pytest.approx(26.12, abs=0.02)
    (tmp_path / "c.mp3").write_bytes(b"kein mp3")
    assert media.mp3_dauer_schaetzen(str(tmp_path / "c.mp3")) == 0.0
