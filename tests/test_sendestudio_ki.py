"""Sendestudio: KI-Werkzeuge - gegen nachgebaute Anthropic- und OpenAI-Server.

Kein Test hier ruft einen echten Anbieter auf und kostet Geld. Die
Attrappen pruefen dafuer genau, was das Studio ihnen schickt.
"""

import base64
import json
import os
import shutil
import struct
import subprocess
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("anthropic")

from sendestudio import ki as ki_modul  # noqa: E402
from sendestudio.config import Config, KiConfig  # noqa: E402
from sendestudio.ki import Ki, KiFehler, teilen  # noqa: E402

from test_sendestudio import Client  # noqa: E402
from test_sendestudio_sicherheit import PASSWORT, Laufend  # noqa: E402

FFMPEG = shutil.which("ffmpeg") is not None


def png(breite=64, hoehe=64):
    """Ein echtes, kleines PNG - nur mit der Standardbibliothek."""
    def block(art, daten):
        return struct.pack(">I", len(daten)) + art + daten + struct.pack(">I", zlib.crc32(art + daten))
    zeilen = b"".join(b"\0" + b"\x80\x40\xc0" * breite for _ in range(hoehe))
    return (b"\x89PNG\r\n\x1a\n" + block(b"IHDR", struct.pack(">IIBBBBB", breite, hoehe, 8, 2, 0, 0, 0))
            + block(b"IDAT", zlib.compress(zeilen)) + block(b"IEND", b""))


def mp3(sekunden=1.0):
    if FFMPEG:
        return subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
                               f"sine=f=440:d={sekunden}", "-f", "mp3", "-"],
                              capture_output=True, check=True).stdout
    return b"ID3\x04\0\0\0\0\0\0" + b"\xff\xfb\x90\x00" * 200


# ----------------------------------------------------------------------
# Attrappen
# ----------------------------------------------------------------------
class Attrappe:
    def __init__(self):
        self.anfragen = []
        self.ablehnen = False
        attrappe = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                koerper = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                attrappe.anfragen.append({"pfad": self.path, "kopf": dict(self.headers),
                                          "koerper": koerper})
                status, typ, antwort = attrappe.antwort(self.path, self.headers, koerper)
                self.send_response(status)
                self.send_header("Content-Type", typ)
                self.send_header("Content-Length", str(len(antwort)))
                self.end_headers()
                self.wfile.write(antwort)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def antwort(self, pfad, kopf, koerper):
        if pfad.startswith("/v1/messages"):
            return self._claude(json.loads(koerper))
        if pfad == "/v1/images/generations":
            return 200, "application/json", json.dumps(
                {"created": 1, "data": [{"b64_json": base64.b64encode(png()).decode()}]}).encode()
        if pfad == "/v1/audio/speech":
            return 200, "audio/mpeg", mp3(1.0)
        if pfad.startswith("/v1/music"):  # ElevenLabs
            return 200, "audio/mpeg", mp3(min(json.loads(koerper)["music_length_ms"] / 1000, 3))
        if pfad == "/v1/audio/transcriptions":
            return 200, "application/json", json.dumps({
                "text": "Hallo und willkommen. Heute geht es um Bienen.",
                "segments": [{"start": 0.0, "end": 0.5, "text": "Hallo und willkommen."},
                             {"start": 0.5, "end": 1.0, "text": "Heute geht es um Bienen."}],
            }).encode()
        return 404, "application/json", b'{"error": {"message": "unbekannt"}}'

    def _claude(self, anfrage):
        if self.ablehnen:
            inhalt, stop = [], "refusal"
        else:
            schema = anfrage.get("output_config", {}).get("format", {}).get("schema", {})
            felder = schema.get("properties", {})
            if "vorschlaege" in felder:
                text = json.dumps({"vorschlaege": ["Bienen im Garten", "Das Summen"]})
            elif "kapitel" in felder:
                text = json.dumps({"kapitel": [{"zeit": 0, "titel": "Begrüßung"},
                                               {"zeit": 0.5, "titel": "Bienen"},
                                               {"zeit": 999, "titel": "Gibt es nicht"}]})
            elif "szenen" in felder:
                text = json.dumps({"titel": "Bienen erklärt", "szenen": [
                    {"sprechtext": "Bienen bestäuben Blumen.", "bild": "Eine Biene auf einer Blüte"},
                    {"sprechtext": "Ohne sie gäbe es weniger Obst.", "bild": "Ein Apfelbaum"}]})
            else:
                text = "Ein KI-Text über Bienen."
            inhalt, stop = [{"type": "text", "text": text}], "end_turn"
        return 200, "application/json", json.dumps({
            "id": "msg_test", "type": "message", "role": "assistant", "model": anfrage["model"],
            "content": inhalt, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 10}}).encode()

    def claude_anfragen(self):
        return [json.loads(a["koerper"]) for a in self.anfragen if a["pfad"].startswith("/v1/messages")]

    def stoppen(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def attrappe(monkeypatch):
    a = Attrappe()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", a.url)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.setenv("ELEVENLABS_API_KEY", "el-test")
    yield a
    a.stoppen()


def ki_cfg(attrappe, **extra):
    return KiConfig(**dict({"openai_url": attrappe.url + "/v1", "musik_url": attrappe.url + "/v1"},
                           **extra))


# ----------------------------------------------------------------------
# Bausteine
# ----------------------------------------------------------------------
def test_teilen_an_satzgrenzen():
    text = "Erster Satz. " * 400 + "\n\n" + "x" * 5000
    stuecke = teilen(text, 1000)
    assert all(len(s) <= 1000 for s in stuecke)
    assert "".join(stuecke).replace(" ", "") == text.replace(" ", "").replace("\n", "")
    assert teilen("   ", 100) == []


def test_claude_anfrage(attrappe):
    k = Ki(ki_cfg(attrappe))
    assert k.schreiben("shownotes", {"titel": "Bienen", "unbekannt": "ignorieren"}) == \
        "Ein KI-Text über Bienen."
    anfrage = attrappe.claude_anfragen()[0]
    kopf = attrappe.anfragen[0]["kopf"]
    assert anfrage["model"] == "claude-opus-5-5"
    assert anfrage["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in kopf.get("anthropic-beta", "")
    assert anfrage["output_config"]["effort"] == "medium"
    assert "thinking" not in anfrage  # Opus 5.5: immer adaptiv, nichts einzustellen
    assert "<titel>\nBienen\n</titel>" in anfrage["messages"][0]["content"]
    assert "unbekannt" not in anfrage["messages"][0]["content"]

    assert k.schreiben("titel", {"titel": "x"}) == {"vorschlaege": ["Bienen im Garten", "Das Summen"]}
    assert attrappe.claude_anfragen()[1]["output_config"]["format"]["type"] == "json_schema"


def test_claude_ablehnung(attrappe):
    attrappe.ablehnen = True
    with pytest.raises(KiFehler, match="abgelehnt"):
        Ki(ki_cfg(attrappe)).schreiben("shownotes", {"titel": "x"})


def test_tageslimit(attrappe):
    zaehler = {"n": 0}

    def zaehlen():
        zaehler["n"] += 1
        return zaehler["n"] <= 2

    k = Ki(ki_cfg(attrappe), zaehlen=zaehlen)
    k.schreiben("social", {"titel": "a"})
    k.bild("Ein Bild")
    with pytest.raises(KiFehler, match="Tageslimit"):
        k.schreiben("social", {"titel": "a"})
    assert len(attrappe.anfragen) == 2  # die dritte Anfrage ging gar nicht erst raus

    aus = Ki(ki_cfg(attrappe, tageslimit=0))
    assert not any(v for k_, v in aus.faehigkeiten().items() if k_ in ("text", "bild"))


def test_openai_bild_stimme_transkript(attrappe, tmp_path):
    k = Ki(ki_cfg(attrappe))
    assert k.bild("Biene")[:8] == b"\x89PNG\r\n\x1a\n"
    anfrage = json.loads(attrappe.anfragen[-1]["koerper"])
    assert anfrage["model"] == "gpt-image-2"
    assert attrappe.anfragen[-1]["kopf"]["Authorization"] == "Bearer sk-openai-test"

    lang = "Ein Satz über Bienen. " * 400  # > 4096 Zeichen: muss geteilt werden
    k.sprechen(lang, str(tmp_path / "stimme.mp3"), "ruhig")
    sprechen = [json.loads(a["koerper"]) for a in attrappe.anfragen if a["pfad"] == "/v1/audio/speech"]
    assert len(sprechen) == 3 and all(len(s["input"]) <= 4096 for s in sprechen)
    assert sprechen[0]["instructions"] == "ruhig" and sprechen[0]["voice"] == "coral"
    assert (tmp_path / "stimme.mp3").stat().st_size > 0

    (tmp_path / "a.mp3").write_bytes(mp3(1.0))
    t = k.transkribieren(str(tmp_path / "a.mp3"))
    assert t["segmente"][1]["text"] == "Heute geht es um Bienen."
    koerper = attrappe.anfragen[-1]["koerper"]
    assert b'name="model"\r\n\r\nwhisper-1' in koerper and b'name="language"\r\n\r\nde' in koerper


def test_openai_fehler_werden_verstaendlich(attrappe):
    k = Ki(ki_cfg(attrappe, openai_url=attrappe.url + "/falsch"))
    with pytest.raises(KiFehler, match="OpenAI-Fehler 404"):
        k.bild("x")


def test_openai_url_nur_https():
    cfg = Config(ki=KiConfig(openai_url="http://beispiel.de/v1"))
    with pytest.raises(ValueError, match="https"):
        cfg.validate()


# ----------------------------------------------------------------------
# Im Studio
# ----------------------------------------------------------------------
@pytest.fixture
def studio(tmp_path, attrappe):
    lauf = Laufend(tmp_path, ki=ki_cfg(attrappe))
    yield lauf
    lauf.stoppen()


def warten(c, auftrag, sekunden=60):
    ende = time.time() + sekunden
    while time.time() < ende:
        status, a = c.json("GET", f"/api/ki/auftraege/{auftrag['id']}")
        assert status == 200
        if a["status"] != "laeuft":
            return a
        time.sleep(0.1)
    raise AssertionError("KI-Auftrag wurde nicht fertig")


def test_ki_stimme_wird_entwurf_und_gekennzeichnet(studio, attrappe):
    c = studio.client()
    assert c.json("GET", "/api/status")[1]["ki"]["text"] is True
    _, s = c.json("POST", "/api/sendungen", {"titel": "Imkerfunk"})
    status, a = c.json("POST", "/api/ki/auftraege", {
        "art": "stimme", "sendung_id": s["id"], "titel": "Bienen-Folge",
        "text": "Bienen sind wichtig.", "text_ki": True})
    assert status == 202
    a = warten(c, a)
    assert a["status"] == "fertig", a
    folge = a["ergebnis"]["folge"]
    assert folge["ki"] == ["text", "stimme"] and not folge["online"]
    assert folge["sprechtext"] == "Bienen sind wichtig."  # was die Stimme spricht

    # Als Entwurf: verschluesselt im Tresor, oeffentlich unsichtbar
    assert os.listdir(studio.studio.cfg.medienordner) == [folge["datei"] + ".tresor"]

    c.json("POST", f"/api/folgen/{folge['id']}/veroeffentlichen")
    anonym = Client(studio.basis)
    _, seite, _ = anonym("GET", "/s/imkerfunk/bienen-folge/")
    assert "KI-generiert: Text, Stimme".encode() in seite
    _, feed, _ = anonym("GET", "/s/imkerfunk/feed.xml")
    assert "enthält KI-generierte Inhalte (Text, Stimme)".encode() in feed

    # Die Kennzeichnung laesst sich im Studio pflegen
    status, neu = c.json("PUT", f"/api/folgen/{folge['id']}", {"ki": ["stimme"]})
    assert status == 200 and neu["ki"] == ["stimme"]
    assert c.json("PUT", f"/api/folgen/{folge['id']}", {"ki": ["zauberei"]})[0] == 400
    assert c.json("GET", "/api/ki")[1]["heute"] == 1


def test_ki_cover(studio):
    c = studio.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Imkerfunk"})
    a = warten(c, c.json("POST", "/api/ki/auftraege", {
        "art": "cover", "sendung_id": s["id"], "beschreibung": "Bienenstock im Abendlicht"})[1])
    assert a["status"] == "fertig", a
    neu = a["ergebnis"]["sendung"]
    assert neu["cover_ki"] == 1 and neu["cover"]
    # Eigenes Cover hochgeladen: nicht mehr KI-generiert
    status, eigen = c.json("PUT", f"/api/sendungen/{s['id']}/cover", roh=png())
    assert status == 200 and eigen["cover_ki"] == 0


def test_aus_der_aufnahme(studio):
    from test_sendestudio import wav_bytes
    c = studio.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Imkerfunk"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Roh"})
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1", roh=wav_bytes(1.0))
    a = warten(c, c.json("POST", "/api/ki/auftraege", {"art": "aus_aufnahme", "folge_id": f["id"]})[1])
    assert a["status"] == "fertig", a
    e = a["ergebnis"]
    assert e["shownotes"] == "Ein KI-Text über Bienen."
    assert [k["titel"] for k in e["kapitel"]] == ["Begrüßung", "Bienen"]  # 999 s gibt es nicht
    assert e["titel"][0] == "Bienen im Garten"


def test_auftraege_pruefen_eingaben_sofort(studio):
    c = studio.client()
    assert c.json("POST", "/api/ki/auftraege", {"art": "zauberei"})[0] == 400
    assert c.json("POST", "/api/ki/auftraege", {"art": "cover", "sendung_id": 999,
                                                "beschreibung": "x"})[0] == 404
    _, s = c.json("POST", "/api/sendungen", {"titel": "P"})
    assert c.json("POST", "/api/ki/auftraege", {"art": "stimme", "sendung_id": s["id"],
                                                "titel": "T", "text": ""})[0] == 400
    assert Client(studio.basis).json("POST", "/api/ki/auftraege", {"art": "text"})[0] == 401


def test_ohne_schluessel_keine_ki(tmp_path, monkeypatch):
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "ELEVENLABS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    lauf = Laufend(tmp_path)
    try:
        c = lauf.client()
        faehig = c.json("GET", "/api/ki")[1]
        assert not faehig["text"] and not faehig["bild"]
        status, antwort = c.json("POST", "/api/ki/auftraege", {
            "art": "text", "aufgabe": "shownotes", "eingaben": {}})
        assert status == 501 and "Nicht eingerichtet" in antwort["fehler"]
    finally:
        lauf.stoppen()


@pytest.mark.skipif(not FFMPEG, reason="braucht ffmpeg")
def test_ki_video_und_video_aus_aufnahme(studio):
    c = studio.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Imkerfunk"})
    a = warten(c, c.json("POST", "/api/ki/auftraege", {
        "art": "video_ki", "sendung_id": s["id"], "thema": "Bienen", "dauer_minuten": 1})[1], 120)
    assert a["status"] == "fertig", a
    video = a["ergebnis"]["folge"]
    assert video["mime"] == "video/mp4" and video["ki"] == ["text", "stimme", "bild", "video"]
    assert video["titel"] == "Bienen erklärt" and video["dauer"] > 1.5
    assert "Bienen bestäuben Blumen." in video["beschreibung"]
    assert "Bienen bestäuben Blumen." in video["sprechtext"]

    # Video aus einer Tonaufnahme: braucht ein Cover
    _, ton = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Ton"})
    c("PUT", f"/api/folgen/{ton['id']}/medium", roh=mp3(1.0))
    assert c.json("POST", "/api/ki/auftraege", {"art": "video_aufnahme",
                                                "folge_id": ton["id"]})[0] == 400
    c("PUT", f"/api/sendungen/{s['id']}/cover", roh=png())
    a = warten(c, c.json("POST", "/api/ki/auftraege", {"art": "video_aufnahme",
                                                       "folge_id": ton["id"]})[1], 120)
    assert a["status"] == "fertig", a
    assert a["ergebnis"]["folge"]["mime"] == "video/mp4"
    assert a["ergebnis"]["folge"]["ki"] == ["video"]
    # Keine Arbeitsdateien liegen geblieben, alles im Tresor
    assert all(n.endswith(".tresor") for n in os.listdir(studio.studio.cfg.medienordner))


def test_ki_modul_ohne_sdk(monkeypatch):
    monkeypatch.setattr(ki_modul, "anthropic", None)
    k = Ki(KiConfig())
    assert k.faehigkeiten()["sdk_fehlt"]
    with pytest.raises(KiFehler, match="pip install anthropic"):
        k.schreiben("shownotes", {})


# ----------------------------------------------------------------------
# Musik
# ----------------------------------------------------------------------
def test_ki_musik_anfrage(attrappe):
    ton = Ki(ki_cfg(attrappe)).musik("ruhiges Klavier", 20, instrumental=True)
    assert media_erkannt(ton) == ".mp3"
    a = attrappe.anfragen[-1]
    assert a["pfad"] == "/v1/music?output_format=mp3_44100_128"
    assert {k.lower(): v for k, v in a["kopf"].items()}["xi-api-key"] == "el-test"
    daten = json.loads(a["koerper"])
    assert daten == {"prompt": "ruhiges Klavier", "music_length_ms": 20000, "force_instrumental": True}
    with pytest.raises(KiFehler, match="zwischen 3 Sekunden"):
        Ki(ki_cfg(attrappe)).musik("x", 1)


def media_erkannt(daten):
    from sendestudio import media
    return media.erkennen(daten[:64])[0]


def test_musikbibliothek(studio):
    import sqlite3
    c = studio.client()
    status, m = c.json("POST", "/api/musik", {"titel": "Abendlied", "kuenstler": "Anna",
                                              "lizenz": "CC BY", "quelle": "https://beispiel.org/abend"})
    assert status == 201
    assert c.json("POST", "/api/musik", {"titel": "X", "quelle": "javascript:alert(1)"})[0] == 400
    status, inhalt, _ = c("PUT", f"/api/musik/{m['id']}/datei", roh=mp3(1.0))
    assert status == 200, inhalt
    m = json.loads(inhalt)
    # Musik der Bibliothek ist nie oeffentlich - sie liegt im Tresor
    assert os.listdir(studio.studio.cfg.medienordner) == [m["datei"] + ".tresor"]
    assert Client(studio.basis)("GET", "/medien/" + m["datei"])[0] == 404
    assert c("GET", "/medien/" + m["datei"])[0] == 200
    liste = c.json("GET", "/api/musik")[1]
    assert [x["titel"] for x in liste["musik"]] == ["Abendlied"] and "CC BY" in liste["lizenzen"]

    # Musik-Angaben einer Folge: im Entwurf verschluesselt, veroeffentlicht oeffentlich
    _, s = c.json("POST", "/api/sendungen", {"titel": "Abendfunk"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {
        "titel": "Folge", "musik": [{"titel": "Abendlied", "kuenstler": "Anna", "lizenz": "CC BY",
                                      "quelle": "https://beispiel.org/abend"}]})
    roh = sqlite3.connect(os.path.join(studio.studio.cfg.datenordner, "sendestudio.db")).execute(
        "SELECT musik FROM folgen").fetchone()[0]
    assert "Abendlied" not in roh
    assert c.json("PUT", f"/api/folgen/{f['id']}", {"musik": [{"titel": "x", "quelle": "ftp://x"}]})[0] == 400
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=1", roh=mp3(1.0))
    c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")
    _, seite, _ = Client(studio.basis)("GET", "/s/abendfunk/folge/")
    assert "Abendlied – Anna".encode() in seite and b"(CC BY)" in seite
    _, feed, _ = Client(studio.basis)("GET", "/s/abendfunk/feed.xml")
    assert "Musik: Abendlied – Anna (CC BY)".encode() in feed

    assert c.json("DELETE", f"/api/musik/{m['id']}")[0] == 200
    assert not [n for n in os.listdir(studio.studio.cfg.medienordner) if n.startswith(m["datei"])]


def test_ki_musik_landet_in_der_bibliothek(studio):
    c = studio.client()
    a = warten(c, c.json("POST", "/api/ki/auftraege", {
        "art": "musik_ki", "beschreibung": "warmes Klavier", "titel": "Intro", "sekunden": 5})[1])
    assert a["status"] == "fertig", a
    m = a["ergebnis"]["musik"]
    assert m["ki"] == 1 and m["titel"] == "Intro" and m["lizenz"] == "KI-generiert"
    assert c.json("POST", "/api/ki/auftraege", {"art": "musik_ki", "beschreibung": "x",
                                                "sekunden": 2})[0] == 400


@pytest.mark.skipif(not FFMPEG, reason="braucht ffmpeg")
def test_musik_unterlegen(studio):
    from test_sendestudio import wav_bytes
    c = studio.client()
    a = warten(c, c.json("POST", "/api/ki/auftraege", {
        "art": "musik_ki", "beschreibung": "Klavier", "titel": "Teppich", "sekunden": 3})[1])
    musik = a["ergebnis"]["musik"]
    _, s = c.json("POST", "/api/sendungen", {"titel": "Abendfunk"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Gespräch",
                                                               "sprechtext": "Hallo zusammen."})
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=2", roh=wav_bytes(2.0))
    assert c.json("POST", "/api/ki/auftraege", {"art": "musikbett", "folge_id": f["id"],
                                                "musik_id": musik["id"], "lautstaerke": 5})[0] == 400
    a = warten(c, c.json("POST", "/api/ki/auftraege", {
        "art": "musikbett", "folge_id": f["id"], "musik_id": musik["id"], "lautstaerke": 0.3})[1], 120)
    assert a["status"] == "fertig", a
    neu = a["ergebnis"]["folge"]
    assert neu["titel"] == "Gespräch (mit Musik)" and neu["ki"] == ["musik"]
    assert neu["sprechtext"] == "Hallo zusammen."
    assert neu["musik"] == [{"titel": "Teppich", "kuenstler": "KI (ElevenLabs)",
                             "lizenz": "KI-generiert", "quelle": ""}]
    assert neu["dauer"] == pytest.approx(2.0, abs=0.3)
    # Das Original bleibt
    assert c.json("GET", f"/api/folgen/{f['id']}")[1]["titel"] == "Gespräch"
