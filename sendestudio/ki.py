"""KI-Werkzeuge: Texte, Bilder, Stimme, Transkription.

* **Texte** - Shownotes, Titelvorschlaege, Kapitel, Skripte, Beschreibungen,
  Social-Media-Posts - schreibt Claude (Anthropic). Dafuer braucht es das
  offizielle SDK: ``pip install "sendestudio[ki]"`` bzw. ``pip install
  anthropic``. Der Rest des Programms kommt weiter ohne fremde Pakete aus.
* **Bilder**, **KI-Stimme** und **Transkription** laufen ueber die
  OpenAI-API (oder einen kompatiblen Dienst, ``ki.openai_url``).
* **Videos** baut das Studio selbst mit ffmpeg aus KI-Bildern und KI-Stimme
  zusammen (siehe :mod:`sendestudio.media`).

Datenschutz: Was hier verarbeitet wird, verlaesst den Server und geht an
den jeweiligen Anbieter. Das passiert nur auf ausdruecklichen Knopfdruck
im Studio - nie automatisch.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import tempfile
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from . import media

try:  # optional - nur fuer die Text-Werkzeuge
    import anthropic
except ImportError:  # pragma: no cover - abhaengig von der Installation
    anthropic = None  # type: ignore[assignment]

#: Server-seitiger Ausweichweg, falls eine Anfrage von einem Sicherheits-
#: filter abgelehnt wird: Die API beantwortet sie dann mit einem anderen Modell.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_MAX_EINGABE = 400_000  # Zeichen - ein langes Transkript passt, ein Buch nicht
_SPRACHEN = {"de": "Deutsch", "en": "Englisch", "fr": "Französisch", "es": "Spanisch",
             "it": "Italienisch", "tr": "Türkisch"}


class KiFehler(Exception):
    def __init__(self, meldung: str, status: int = 502) -> None:
        super().__init__(meldung)
        self.status = status


# ----------------------------------------------------------------------
# Aufgaben fuer Claude
# ----------------------------------------------------------------------
_GRUNDLAGE = (
    "Du arbeitest in der Redaktion eines kleinen Senders, der Podcasts, Radio und "
    "Dokumentationen macht. Schreib in der Sprache, die in <sprache> steht, im Ton der "
    "Sendung. Halte dich an das, was im Material steht; erfinde keine Fakten, Namen, "
    "Zitate oder Zahlen dazu. Gib nur den verlangten Text aus, ohne Vorrede und ohne "
    "Markdown-Überschriften."
)

AUFGABEN: Dict[str, Dict[str, Any]] = {
    "shownotes": {
        "auftrag": "Schreib Shownotes für diese Folge: zwei, drei Sätze, worum es geht, "
                   "dann die wichtigsten Punkte als Liste mit „– “ am Zeilenanfang.",
    },
    "beschreibung": {
        "auftrag": "Schreib eine Beschreibung für die Sendung (für Podcast-Verzeichnisse "
                   "und die Webseite), höchstens 600 Zeichen.",
    },
    "skript": {
        "auftrag": "Schreib ein sprechfertiges Skript für eine Folge zum Thema. Es wird "
                   "von einer KI-Stimme vorgelesen: nur gesprochener Text, keine "
                   "Regieanweisungen, keine Sprecherbezeichnungen, Zahlen und Abkürzungen "
                   "so, wie man sie spricht. Länge passend zu <dauer_minuten> "
                   "(etwa 140 Wörter pro Minute).",
    },
    "social": {
        "auftrag": "Schreib einen kurzen Beitrag für soziale Netzwerke, der auf die Folge "
                   "neugierig macht, höchstens 280 Zeichen, höchstens zwei Hashtags.",
    },
    "bildidee": {
        "auftrag": "Beschreib in zwei, drei Sätzen ein Cover-Bild für diese Sendung, als "
                   "Auftrag für einen Bildgenerator: Motiv, Stil, Farben. Keine Schrift "
                   "im Bild, keine echten Personen.",
    },
    "titel": {
        "auftrag": "Schlag fünf Titel für diese Folge vor: kurz, konkret, neugierig machend.",
        "schema": {
            "type": "object",
            "properties": {"vorschlaege": {"type": "array", "items": {"type": "string"}}},
            "required": ["vorschlaege"],
            "additionalProperties": False,
        },
    },
    "kapitel": {
        "auftrag": "Teile die Folge anhand des Transkripts mit Zeitmarken in Kapitel ein: "
                   "eins bei jedem echten Themenwechsel, meist eins alle paar Minuten, "
                   "das erste bei 0. Die Zeit in Sekunden, wie sie in den Zeitmarken steht.",
        "schema": {
            "type": "object",
            "properties": {"kapitel": {"type": "array", "items": {
                "type": "object",
                "properties": {"zeit": {"type": "number"}, "titel": {"type": "string"}},
                "required": ["zeit", "titel"],
                "additionalProperties": False,
            }}},
            "required": ["kapitel"],
            "additionalProperties": False,
        },
    },
    "szenen": {
        "auftrag": "Plane ein kurzes Erklär- oder Dokumentarvideo zum Thema als Folge von "
                   "Szenen. Jede Szene hat einen Sprechtext (wird von einer KI-Stimme "
                   "gelesen, 2–4 Sätze, sprechfertig) und eine Bildbeschreibung für einen "
                   "Bildgenerator (ein Standbild, Querformat, keine Schrift im Bild, keine "
                   "echten Personen). Anzahl der Szenen passend zu <dauer_minuten>, "
                   "höchstens 12. Dazu ein Titel für das Video.",
        "schema": {
            "type": "object",
            "properties": {
                "titel": {"type": "string"},
                "szenen": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"sprechtext": {"type": "string"}, "bild": {"type": "string"}},
                    "required": ["sprechtext", "bild"],
                    "additionalProperties": False,
                }},
            },
            "required": ["titel", "szenen"],
            "additionalProperties": False,
        },
    },
}

#: Felder, die eine Aufgabe als Material bekommen kann.
EINGABEN = ("sendung", "beschreibung_sendung", "art", "titel", "notizen", "thema",
            "stil", "dauer_minuten", "transkript")


def segmente_als_text(segmente: List[Dict[str, Any]]) -> str:
    """Transkript mit Zeitmarken in Sekunden - so kann Claude Kapitel setzen."""
    return "\n".join(f"[{int(s['start'])}] {s['text'].strip()}" for s in segmente)


class Ki:
    def __init__(self, cfg: Any, *, zaehlen: Optional[Callable[[], bool]] = None) -> None:
        """``cfg`` ist eine :class:`sendestudio.config.KiConfig`.

        ``zaehlen`` wird vor jedem Aufruf eines Anbieters gerufen und gibt
        ``False`` zurueck, wenn das Tageslimit erreicht ist.
        """
        self.cfg = cfg
        self._zaehlen = zaehlen or (lambda: True)

    # -- Was ist eingerichtet? ---------------------------------------------
    def _anthropic_schluessel(self) -> str:
        return self.cfg.anthropic_schluessel or os.environ.get("ANTHROPIC_API_KEY", "")

    def _openai_schluessel(self) -> str:
        return self.cfg.openai_schluessel or os.environ.get("OPENAI_API_KEY", "")

    def faehigkeiten(self) -> Dict[str, bool]:
        aktiv = self.cfg.tageslimit > 0
        text = aktiv and anthropic is not None and bool(
            self._anthropic_schluessel() or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
        openai = aktiv and bool(self._openai_schluessel())
        ffmpeg = media.ffmpeg_verfuegbar()
        return {"text": text, "bild": openai, "stimme": openai, "transkript": openai,
                "video": openai and ffmpeg, "ffmpeg": ffmpeg,
                "sdk_fehlt": anthropic is None}

    def _gezaehlt(self) -> None:
        if self.cfg.tageslimit <= 0:
            raise KiFehler("KI ist ausgeschaltet (ki.tageslimit = 0)", 403)
        if not self._zaehlen():
            raise KiFehler(f"Tageslimit von {self.cfg.tageslimit} KI-Aufträgen erreicht "
                           "(ki.tageslimit)", 429)

    # -- Text mit Claude ------------------------------------------------------
    def schreiben(self, aufgabe: str, eingaben: Dict[str, Any], sprache: str = "de") -> Any:
        """Fuehrt eine Text-Aufgabe aus. Text oder - bei Aufgaben mit Schema - ein dict."""
        if aufgabe not in AUFGABEN:
            raise KiFehler(f"Unbekannte Aufgabe: {aufgabe}", 400)
        if anthropic is None:
            raise KiFehler("Für KI-Texte fehlt das Anthropic-SDK: pip install anthropic", 501)
        if not self.faehigkeiten()["text"]:
            raise KiFehler("Kein Anthropic-API-Schlüssel eingerichtet (ANTHROPIC_API_KEY "
                           "oder ki.anthropic_schluessel)", 501)
        spec = AUFGABEN[aufgabe]
        material = [f"<sprache>{_SPRACHEN.get(sprache, sprache)}</sprache>"]
        for feld in EINGABEN:
            wert = eingaben.get(feld)
            if wert not in (None, ""):
                material.append(f"<{feld}>\n{str(wert)[:_MAX_EINGABE]}\n</{feld}>")
        anfrage: Dict[str, Any] = {
            "model": self.cfg.text_modell,
            "max_tokens": 16000,
            "system": _GRUNDLAGE,
            "messages": [{"role": "user",
                          "content": "\n\n".join(material) + "\n\n" + spec["auftrag"]}],
            "output_config": {"effort": "medium"},
        }
        if "schema" in spec:
            anfrage["output_config"]["format"] = {"type": "json_schema", "schema": spec["schema"]}
        self._gezaehlt()
        client = anthropic.Anthropic(api_key=self.cfg.anthropic_schluessel or None,
                                     max_retries=2, timeout=600.0)
        try:
            antwort = client.beta.messages.create(betas=[_FALLBACK_BETA], fallbacks="default",
                                                  **anfrage)
        except anthropic.AuthenticationError:
            raise KiFehler("Anthropic: API-Schlüssel ungültig", 502)
        except anthropic.PermissionDeniedError:
            raise KiFehler("Anthropic: Schlüssel hat keine Berechtigung für dieses Modell", 502)
        except anthropic.RateLimitError:
            raise KiFehler("Anthropic: Ratenlimit erreicht – bitte gleich noch einmal", 429)
        except anthropic.BadRequestError as f:
            raise KiFehler(f"Anthropic lehnt die Anfrage ab: {f.message}", 502)
        except anthropic.APIStatusError as f:
            raise KiFehler(f"Anthropic-Fehler {f.status_code} – später erneut versuchen", 502)
        except anthropic.APIConnectionError:
            raise KiFehler("Keine Verbindung zu Anthropic", 502)
        if antwort.stop_reason == "refusal":
            raise KiFehler("Die KI hat diese Anfrage abgelehnt.", 422)
        text = "".join(b.text for b in antwort.content if b.type == "text").strip()
        if antwort.stop_reason == "max_tokens":
            raise KiFehler("Die Antwort wurde zu lang und abgeschnitten – bitte kürzer anfragen.",
                           422)
        if "schema" in spec:
            try:
                return json.loads(text)
            except ValueError:
                raise KiFehler("Die KI hat keine verwertbare Antwort geliefert", 502)
        return text

    # -- OpenAI: Bild, Stimme, Transkription -------------------------------
    def _openai(self, pfad: str, *, daten: Optional[dict] = None,
                datei: Optional[tuple] = None, felder: Optional[dict] = None,
                timeout: float = 300.0) -> bytes:
        schluessel = self._openai_schluessel()
        if not schluessel or self.cfg.tageslimit <= 0:
            raise KiFehler("Kein OpenAI-API-Schlüssel eingerichtet (OPENAI_API_KEY oder "
                           "ki.openai_schluessel)", 501)
        self._gezaehlt()
        kopf = {"Authorization": f"Bearer {schluessel}"}
        if datei is not None:
            grenze = "----sendestudio" + secrets.token_hex(12)
            teile = []
            for name, wert in (felder or {}).items():
                teile.append(f'--{grenze}\r\nContent-Disposition: form-data; name="{name}"'
                             f"\r\n\r\n{wert}\r\n".encode())
            dateiname, inhalt, typ = datei
            teile.append(f'--{grenze}\r\nContent-Disposition: form-data; name="file"; '
                         f'filename="{dateiname}"\r\nContent-Type: {typ}\r\n\r\n'.encode()
                         + inhalt + b"\r\n")
            teile.append(f"--{grenze}--\r\n".encode())
            koerper = b"".join(teile)
            kopf["Content-Type"] = f"multipart/form-data; boundary={grenze}"
        else:
            koerper = json.dumps(daten).encode()
            kopf["Content-Type"] = "application/json"
        req = urllib.request.Request(self.cfg.openai_url.rstrip("/") + pfad, data=koerper,
                                     headers=kopf, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as antwort:
                return antwort.read()
        except urllib.error.HTTPError as f:
            try:
                meldung = json.loads(f.read()).get("error", {}).get("message", "")
            except (ValueError, AttributeError):
                meldung = ""
            if f.code == 401:
                raise KiFehler("OpenAI: API-Schlüssel ungültig")
            if f.code == 429:
                raise KiFehler("OpenAI: Ratenlimit oder Guthaben erschöpft", 429)
            raise KiFehler(f"OpenAI-Fehler {f.code}: {meldung[:300] or 'unbekannt'}")
        except (urllib.error.URLError, OSError) as f:
            raise KiFehler(f"Keine Verbindung zu OpenAI ({getattr(f, 'reason', f)})")

    def bild(self, beschreibung: str, groesse: str = "1024x1024") -> bytes:
        """Erzeugt ein Bild und gibt die Bilddatei (PNG/JPEG/WebP) zurueck."""
        if not beschreibung.strip():
            raise KiFehler("Bitte beschreiben, was auf dem Bild sein soll", 400)
        roh = self._openai("/images/generations", daten={
            "model": self.cfg.bild_modell, "prompt": beschreibung[:30000], "n": 1,
            "size": groesse, "output_format": "png"})
        try:
            bild = base64.b64decode(json.loads(roh)["data"][0]["b64_json"])
        except (ValueError, KeyError, IndexError, TypeError):
            raise KiFehler("OpenAI hat kein Bild geliefert")
        erkannt = media.erkennen(bild[:64])
        if not erkannt or erkannt[1] != "bild":
            raise KiFehler("OpenAI hat keine gültige Bilddatei geliefert")
        return bild

    def sprechen(self, text: str, ziel: str, anweisung: str = "") -> None:
        """Liest ``text`` mit KI-Stimme vor und schreibt eine MP3 nach ``ziel``."""
        abschnitte = teilen(text, 3500)
        if not abschnitte:
            raise KiFehler("Kein Text zum Vorlesen", 400)
        if len(abschnitte) > 40:
            raise KiFehler("Der Text ist zu lang (höchstens etwa 140 000 Zeichen)", 400)
        teile = []
        for abschnitt in abschnitte:
            daten = {"model": self.cfg.stimme_modell, "voice": self.cfg.stimme,
                     "input": abschnitt, "response_format": "mp3"}
            if anweisung and not self.cfg.stimme_modell.startswith("tts-1"):
                daten["instructions"] = anweisung[:4000]
            ton = self._openai("/audio/speech", daten=daten)
            erkannt = media.erkennen(ton[:64])
            if not erkannt or erkannt[0] != ".mp3":
                raise KiFehler("OpenAI hat keine MP3-Datei geliefert")
            teile.append(ton)
        media.mp3_verbinden(teile, ziel)

    def transkribieren(self, pfad: str, sprache: str = "de") -> Dict[str, Any]:
        """Text einer Aufnahme, wenn moeglich mit Zeitmarken (``segmente``)."""
        with tempfile.TemporaryDirectory(prefix="sendestudio-") as tmp:
            klein = os.path.join(tmp, "sprache.mp3")
            if media.ffmpeg_verfuegbar():
                # Sprache braucht kein Stereo und keine 44 kHz - so passt
                # auch eine lange Folge unter die 25-MB-Grenze der API.
                media.fuer_transkript(pfad, klein)
            else:
                klein = pfad
            if os.path.getsize(klein) > 24 * 1024 * 1024:
                raise KiFehler("Die Aufnahme ist für die Transkription zu lang "
                               "(höchstens etwa 100 Minuten)", 413)
            with open(klein, "rb") as f:
                inhalt = f.read()
        endung = os.path.splitext(klein)[1] or ".mp3"
        mit_zeiten = self.cfg.transkript_modell == "whisper-1"
        felder = {"model": self.cfg.transkript_modell,
                  "response_format": "verbose_json" if mit_zeiten else "json"}
        if re.fullmatch(r"[a-z]{2}", sprache or ""):
            felder["language"] = sprache
        roh = self._openai("/audio/transcriptions", felder=felder, timeout=900.0,
                           datei=("aufnahme" + endung, inhalt, media.mime_fuer("x" + endung)))
        try:
            daten = json.loads(roh)
        except ValueError:
            raise KiFehler("OpenAI hat kein Transkript geliefert")
        segmente = [{"start": float(s.get("start", 0)), "ende": float(s.get("end", 0)),
                     "text": str(s.get("text", ""))} for s in daten.get("segments") or []]
        return {"text": str(daten.get("text", "")), "segmente": segmente}


def teilen(text: str, laenge: int) -> List[str]:
    """Zerlegt Text an Absatz- bzw. Satzgrenzen in Stuecke von hoechstens ``laenge``."""
    stuecke: List[str] = []
    aktuell = ""
    for satz in re.split(r"(?<=[.!?…])\s+|\n\s*\n", text.strip()):
        satz = satz.strip()
        if not satz:
            continue
        if len(satz) > laenge:  # ein Monstersatz ohne Punkt
            if aktuell:  # erst das Vorherige, sonst stimmt die Reihenfolge nicht
                stuecke.append(aktuell)
                aktuell = ""
            while len(satz) > laenge:
                stuecke.append(satz[:laenge])
                satz = satz[laenge:]
        if aktuell and len(aktuell) + 1 + len(satz) > laenge:
            stuecke.append(aktuell)
            aktuell = satz
        else:
            aktuell = f"{aktuell} {satz}".strip()
    if aktuell:
        stuecke.append(aktuell)
    return stuecke


__all__ = ["AUFGABEN", "Ki", "KiFehler", "segmente_als_text", "teilen"]
