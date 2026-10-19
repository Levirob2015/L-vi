"""Sendestudio: Tresor, Zwei-Faktor, Sitzungen und Haertung des Servers."""

import http.client
import json
import os
import socket
import sqlite3
import threading
import time

import pytest

from sendestudio import zweifaktor
from sendestudio.cli import main
from sendestudio.config import Config, laden, passwort_hash
from sendestudio.server import Studio, server_starten
from sendestudio.store import Store
from sendestudio.tresor import BLOCK, ENDUNG, Tresor, TresorFehler

from test_sendestudio import Client, wav_bytes

PASSWORT = "richtig-langes-passwort"


# ----------------------------------------------------------------------
# Tresor
# ----------------------------------------------------------------------
@pytest.fixture
def tresor(tmp_path):
    t = Tresor(str(tmp_path / "tresor.json"), iterationen=1000)
    t.wieder = t.anlegen("pw")
    return t


@pytest.mark.parametrize("groesse", [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK + 17])
def test_tresor_hin_und_zurueck(tmp_path, tresor, groesse):
    daten = os.urandom(groesse)
    (tmp_path / "klar").write_bytes(daten)
    tresor.verschluesseln(str(tmp_path / "klar"), str(tmp_path / "geheim"))
    geheim = (tmp_path / "geheim").read_bytes()
    assert groesse < 64 or daten[:64] not in geheim
    assert Tresor.klartext_groesse(str(tmp_path / "geheim")) == groesse
    assert b"".join(tresor.lesen(str(tmp_path / "geheim"))) == daten
    if groesse > 10:
        for start, ende in ((0, 0), (5, groesse - 1), (groesse - 3, groesse + 50),
                            (BLOCK - 2, BLOCK + 2)):
            if start < groesse:
                assert b"".join(tresor.lesen(str(tmp_path / "geheim"), start, ende)) == \
                    daten[start:ende + 1]


def test_tresor_erkennt_manipulation(tmp_path, tresor):
    (tmp_path / "klar").write_bytes(os.urandom(2 * BLOCK + 5))
    tresor.verschluesseln(str(tmp_path / "klar"), str(tmp_path / "g"))
    roh = (tmp_path / "g").read_bytes()
    kaputt = bytearray(roh)
    kaputt[200] ^= 1
    (tmp_path / "x").write_bytes(bytes(kaputt))
    with pytest.raises(TresorFehler):
        b"".join(tresor.lesen(str(tmp_path / "x")))
    # Abgeschnitten genau an einer Blockgrenze - der Ende-Kennzeichner fehlt.
    (tmp_path / "x").write_bytes(roh[:22 + 2 * (BLOCK + 32)])
    with pytest.raises(TresorFehler):
        b"".join(tresor.lesen(str(tmp_path / "x")))


def test_tresor_schluessel(tmp_path, tresor):
    neu = Tresor(tresor.pfad, iterationen=1000)
    assert not neu.offen
    with pytest.raises(TresorFehler):
        neu.text_verschluesseln("x")
    with pytest.raises(TresorFehler):
        neu.entsperren("falsch")
    # Der Wiederherstellungsschluessel verzeiht Gross/Klein und Leerzeichen.
    neu.entsperren(tresor.wieder.lower().replace("-", " "))
    geheim = tresor.text_verschluesseln("Hallo Welt")
    assert "Hallo" not in geheim
    assert neu.text_entschluesseln(geheim) == "Hallo Welt"
    # Neues Passwort: alter Schluessel bleibt (Daten lesbar), altes Passwort nicht.
    wieder2 = neu.neues_passwort("pw2")
    dritter = Tresor(tresor.pfad, iterationen=1000)
    with pytest.raises(TresorFehler):
        dritter.entsperren("pw")
    with pytest.raises(TresorFehler):
        dritter.entsperren(tresor.wieder)
    dritter.entsperren(wieder2)
    assert dritter.text_entschluesseln(geheim) == "Hallo Welt"
    assert oct(os.stat(tresor.pfad).st_mode & 0o777) == "0o600"
    # Der Schluessel steht nirgends im Klartext.
    assert "Hallo" not in open(tresor.pfad).read()


def test_store_verschluesselt_entwuerfe(tmp_path, tresor):
    db = str(tmp_path / "db")
    st = Store(db, tresor=tresor)
    s = st.sendung_anlegen("Sender")
    f = st.folge_anlegen(s["id"], "Geheimer Plan", beschreibung="Streng geheim",
                         kapitel=[{"zeit": 1, "titel": "Teil A"}])
    assert f["titel"] == "Geheimer Plan" and f["slug"].startswith("entwurf-")
    roh = sqlite3.connect(db).execute("SELECT titel, beschreibung, kapitel, slug FROM folgen").fetchone()
    assert not any("Geheim" in w or "Teil A" in w for w in roh)

    # Verschlossen: nur ein Platzhalter.
    tresor.sperren()
    zu = st.folge(f["id"])
    assert zu["verschlossen"] and zu["titel"] == "(verschlossen)"
    with pytest.raises(ValueError):
        st.veroeffentlichen(f["id"])

    tresor.entsperren("pw")
    st.folge_aendern(f["id"], datei="a.mp3")
    online = st.veroeffentlichen(f["id"])
    assert online["slug"] == "geheimer-plan"
    roh = sqlite3.connect(db).execute("SELECT titel FROM folgen").fetchone()
    assert roh[0] == "Geheimer Plan"  # oeffentlich = Klartext

    st.zurueckziehen(f["id"])
    roh = sqlite3.connect(db).execute("SELECT titel FROM folgen").fetchone()
    assert "Geheimer" not in roh[0]


# ----------------------------------------------------------------------
# Server
# ----------------------------------------------------------------------
class Laufend:
    def __init__(self, tmp_path, **einstellungen):
        self.cfg = Config(daten=str(tmp_path / "daten"),
                          passwort_hash=passwort_hash(PASSWORT, iterationen=1000),
                          basis_url="https://sender.example", geheimnis="test",
                          export_ziel=str(tmp_path / "web"), **einstellungen)
        self.uhr = [time.time()]
        self.starten()

    def starten(self):
        self.studio = Studio(self.cfg, tresor_iterationen=1000, clock=lambda: self.uhr[0])
        self.srv = server_starten(self.studio, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.basis = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def stoppen(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.studio.close()

    def client(self, code=None):
        c = Client(self.basis)
        daten = {"passwort": PASSWORT}
        if code is not None:
            daten["code"] = code
        assert c.json("POST", "/api/login", daten)[0] == 200
        return c

    def dateien(self):
        return sorted(os.listdir(self.studio.cfg.medienordner))


@pytest.fixture
def lauf(tmp_path):
    l = Laufend(tmp_path)
    yield l
    l.stoppen()


def test_entwurf_liegt_nur_verschluesselt_auf_der_platte(lauf):
    c = lauf.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Nachtfunk"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Interview mit Anna"})
    wav = wav_bytes(1.5)
    status, inhalt, _ = c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1.5", roh=wav)
    f = json.loads(inhalt)

    # Auf der Platte: nur die Tresor-Datei, mit nichtssagendem Namen.
    assert lauf.dateien() == [f["datei"] + ENDUNG]
    assert "anna" not in f["datei"].lower() and "interview" not in f["datei"].lower()
    roh = open(os.path.join(lauf.studio.cfg.medienordner, f["datei"] + ENDUNG), "rb").read()
    assert b"RIFF" not in roh and b"ID3" not in roh and b"LAME" not in roh

    # Das Studio kann trotzdem vorhoeren und spulen.
    status, teil, kopf = c("GET", "/medien/" + f["datei"], kopf={"Range": "bytes=0-3"})
    assert status == 206 and len(teil) == 4
    assert teil[:3] in (b"RIF", b"ID3") or teil[:1] == b"\xff"
    assert kopf["Cache-Control"] == "private, no-store"

    # Veroeffentlichen: jetzt (und erst jetzt) lesbar.
    c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")
    assert lauf.dateien() == [f["datei"]]
    assert Client(lauf.basis)("GET", "/medien/" + f["datei"])[0] == 200
    assert Client(lauf.basis)("GET", "/s/nachtfunk/interview-mit-anna/")[0] == 200

    # Zurueckziehen: wieder in den Tresor.
    c.json("POST", f"/api/folgen/{f['id']}/zurueckziehen")
    assert lauf.dateien() == [f["datei"] + ENDUNG]
    assert Client(lauf.basis)("GET", "/medien/" + f["datei"])[0] == 404


def test_ohne_anmeldung_bleibt_der_tresor_zu(lauf, tmp_path):
    c = lauf.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "P"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Geheim"})
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1", roh=wav_bytes(1.0))
    assert lauf.studio.tresor.offen

    # Abmelden: Schluessel vergessen.
    c.json("POST", "/api/logout", {})
    assert not lauf.studio.tresor.offen

    # Neustart des Servers: niemand angemeldet, nichts lesbar.
    lauf.stoppen()
    lauf.starten()
    assert not lauf.studio.tresor.offen
    folge = lauf.studio.store.folge(f["id"])
    assert folge["verschlossen"] and folge["titel"] == "(verschlossen)"
    c = lauf.client()
    assert c.json("GET", f"/api/folgen/{f['id']}")[1]["titel"] == "Geheim"


def test_leerlauf_meldet_ab_und_schliesst(lauf):
    c = lauf.client()
    assert lauf.studio.tresor.offen
    lauf.uhr[0] += lauf.cfg.leerlauf_minuten * 60 + 1
    assert c.json("GET", "/api/sendungen")[0] == 401
    assert not lauf.studio.tresor.offen


def test_koerper_wird_immer_ganz_gelesen(lauf):
    """Regression: Ein ungelesener Koerper wurde als naechste Anfrage gedeutet."""
    c = lauf.client()
    cookie = [k for k in c.oeffner.handlers if hasattr(k, "cookiejar")][0].cookiejar
    kopf = {"X-Studio": "1", "Content-Type": "application/json",
            "Cookie": "; ".join(f"{k.name}={k.value}" for k in cookie)}
    verbindung = http.client.HTTPConnection(*lauf.srv.server_address[:2], timeout=5)
    verbindung.request("POST", "/api/logout", body=b'{"x": 1}', headers=kopf)
    assert verbindung.getresponse().read() and True
    verbindung.request("GET", "/")  # dieselbe Verbindung
    antwort = verbindung.getresponse()
    assert antwort.status == 200 and b"<!doctype html>" in antwort.read()
    verbindung.close()


def test_transfer_encoding_wird_abgelehnt(lauf):
    verbindung = http.client.HTTPConnection(*lauf.srv.server_address[:2], timeout=5)
    verbindung.putrequest("POST", "/api/login")
    verbindung.putheader("Transfer-Encoding", "chunked")
    verbindung.putheader("X-Studio", "1")
    verbindung.endheaders()
    verbindung.send(b"0\r\n\r\n")
    assert verbindung.getresponse().status == 400


def test_status_verraet_vor_der_anmeldung_nichts(lauf):
    status, daten = Client(lauf.basis).json("GET", "/api/status")
    assert status == 200 and set(daten) == {"angemeldet", "zweifaktor"}


def test_sicherheitskoepfe(lauf):
    status, _, kopf = Client(lauf.basis)("GET", "/studio")
    assert kopf["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in kopf["Content-Security-Policy"]
    assert kopf["Server"].strip() == "Sendestudio"  # keine Versionsnummern


def test_https_cookie_und_hsts(tmp_path):
    l = Laufend(tmp_path, sicheres_cookie=True)
    try:
        status, _, kopf = Client(l.basis)("POST", "/api/login", {"passwort": PASSWORT})
        assert status == 200
        cookie = kopf["Set-Cookie"]
        assert cookie.startswith("__Host-studio=") and "Secure" in cookie and "HttpOnly" in cookie
        assert "max-age" in kopf["Strict-Transport-Security"]
    finally:
        l.stoppen()


def test_zweifaktor(tmp_path):
    geheimnis = zweifaktor.neues_geheimnis()
    l = Laufend(tmp_path, totp_geheimnis=geheimnis)
    try:
        c = Client(l.basis)
        assert c.json("GET", "/api/status")[1]["zweifaktor"] is True
        assert c.json("POST", "/api/login", {"passwort": PASSWORT})[0] == 401
        assert c.json("POST", "/api/login", {"passwort": PASSWORT, "code": "000000"})[0] in (401, 429)
        code = zweifaktor.code(geheimnis, int(l.uhr[0] // 30))
        assert c.json("POST", "/api/login", {"passwort": "falsch", "code": code})[0] in (401, 429)
        # Der eben verbrauchte Code gilt nicht noch einmal - auch nicht mit Passwort.
        assert c.json("POST", "/api/login", {"passwort": PASSWORT, "code": code})[0] in (401, 429)
        l.uhr[0] += 30
        neu = zweifaktor.code(geheimnis, int(l.uhr[0] // 30))
        assert c.json("POST", "/api/login", {"passwort": PASSWORT, "code": neu})[0] == 200
    finally:
        l.stoppen()


def test_studio_nur_aus_erlaubten_netzen(tmp_path):
    l = Laufend(tmp_path, studio_netze=["10.0.0.0/8"])
    try:
        c = Client(l.basis)
        assert c("GET", "/studio")[0] == 404
        assert c.json("POST", "/api/login", {"passwort": PASSWORT})[0] == 404
        assert c("GET", "/")[0] == 200  # die oeffentliche Seite bleibt erreichbar
    finally:
        l.stoppen()


def test_verbindungsgrenze(tmp_path):
    l = Laufend(tmp_path)
    l.srv.max_verbindungen = 2
    l.srv._plaetze = threading.BoundedSemaphore(2)
    try:
        offen = [socket.create_connection(l.srv.server_address[:2]) for _ in range(2)]
        time.sleep(0.2)
        dritte = socket.create_connection(l.srv.server_address[:2])
        dritte.settimeout(2)
        assert dritte.recv(1) == b""  # sofort geschlossen
        for s in offen + [dritte]:
            s.close()
        time.sleep(0.2)
        assert Client(l.basis)("GET", "/")[0] == 200  # Plaetze wieder frei
    finally:
        l.stoppen()


# ----------------------------------------------------------------------
# Kommandozeile
# ----------------------------------------------------------------------
def test_init_und_passwortwechsel(tmp_path, monkeypatch, capsys):
    pfad = str(tmp_path / "s.json")
    assert main(["-c", pfad, "init", "--titel", "T"]) == 0
    aus = capsys.readouterr().out
    passwort = aus.split("Studio-Passwort: ")[1].split()[0]
    wieder = aus.split("Wiederherstellungsschlüssel: ")[1].split()[0]
    cfg = laden(pfad)
    t = Tresor(os.path.join(cfg.datenordner, "tresor.json"))
    t.entsperren(passwort)
    assert oct(os.stat(cfg.datenordner).st_mode & 0o777) == "0o700"

    # Mit dem Wiederherstellungsschluessel ein neues Passwort setzen.
    antworten = iter([wieder, "ganz-neues-passwort", "ganz-neues-passwort"])
    monkeypatch.setattr("getpass.getpass", lambda *_: next(antworten))
    assert main(["-c", pfad, "passwort"]) == 0
    t = Tresor(os.path.join(cfg.datenordner, "tresor.json"))
    t.entsperren("ganz-neues-passwort")
    with pytest.raises(TresorFehler):
        Tresor(t.pfad).entsperren(passwort)

    # Falsches altes Geheimnis: nichts aendert sich.
    antworten = iter(["falsch"])
    monkeypatch.setattr("getpass.getpass", lambda *_: next(antworten))
    assert main(["-c", pfad, "passwort"]) == 1
