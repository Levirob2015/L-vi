"""Mediendateien: Typ erkennen, umwandeln, Dauer messen.

Der Dateityp wird am Inhalt erkannt, nicht am Namen - eine HTML-Datei, die
sich ``folge.mp3`` nennt, wird abgewiesen. Sonst koennte, wer das Studio
bedient oder dessen Sitzung uebernimmt, ueber die oeffentliche Seite
Skripte ausliefern.

ffmpeg ist optional. Ist es installiert, wird jede Aufnahme in ein Format
gebracht, das jede Podcast-App abspielt (MP3 bzw. MP4), auf Wunsch in der
Lautstaerke angeglichen, und die Dauer exakt gemessen. Ohne ffmpeg bleibt
die Datei, wie sie ist.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Optional, Tuple

#: Endung -> MIME-Typ fuer alles, was ausgeliefert wird.
MIME = {
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".ogg": "audio/ogg",
    ".opus": "audio/ogg",
    ".wav": "audio/wav",
    ".weba": "audio/webm",
    ".webm": "video/webm",
    ".mp4": "video/mp4",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}

#: ffmpeg darf nur die eine lokale Datei lesen - keine Adressen im Netz,
#: keine Wiedergabelisten, die weitere Dateien nachladen. Sonst koennte
#: eine praeparierte Mediendatei den Server Dateien lesen oder Anfragen
#: verschicken lassen.
NUR_DATEI = ["-protocol_whitelist", "file", "-nostdin"]

#: Lautheit nach der Empfehlung fuer Podcasts (-16 LUFS, Stereo).
LOUDNORM = "loudnorm=I=-16:TP=-1.5:LRA=11"


def erkennen(kopf: bytes) -> Optional[Tuple[str, str]]:
    """Erkennt Audio, Video und Bilder an den ersten Bytes.

    Gibt ``(endung, art)`` zurueck, ``art`` ist ``audio``, ``video``,
    ``container`` (WebM/MP4: Audio *oder* Video) oder ``bild``. ``None``
    heisst: kein erlaubter Typ.
    """
    if kopf[:3] == b"ID3" or (len(kopf) > 1 and kopf[0] == 0xFF and kopf[1] & 0xE0 == 0xE0
                              and kopf[1] & 0x06 != 0):
        return ".mp3", "audio"
    if kopf[:4] == b"OggS":
        return ".ogg", "audio"
    if kopf[:4] == b"RIFF" and kopf[8:12] == b"WAVE":
        return ".wav", "audio"
    if kopf[:4] == b"RIFF" and kopf[8:12] == b"WEBP":
        return ".webp", "bild"
    if kopf[:4] == b"\x1a\x45\xdf\xa3":
        return ".webm", "container"
    if kopf[4:8] == b"ftyp":
        marke = kopf[8:12]
        if marke in (b"M4A ", b"M4B ", b"M4P "):
            return ".m4a", "audio"
        return ".mp4", "container"
    if kopf[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png", "bild"
    if kopf[:3] == b"\xff\xd8\xff":
        return ".jpg", "bild"
    return None


def ffmpeg_verfuegbar() -> bool:
    return shutil.which("ffmpeg") is not None and shutil.which("ffprobe") is not None


def pruefen(pfad: str) -> dict:
    """Fragt ffprobe nach Dauer und Spuren. Ohne ffmpeg: leeres Ergebnis."""
    if not ffmpeg_verfuegbar():
        return {}
    try:
        aus = subprocess.run(
            ["ffprobe", "-v", "error", "-protocol_whitelist", "file", "-print_format", "json",
             "-show_format", "-show_streams", pfad],
            capture_output=True, timeout=60, check=True,
        ).stdout
        daten = json.loads(aus or b"{}")
    except (subprocess.SubprocessError, ValueError, OSError):
        return {}
    arten = {s.get("codec_type") for s in daten.get("streams", [])
             if s.get("disposition", {}).get("attached_pic") != 1}
    try:
        dauer = float(daten.get("format", {}).get("duration") or 0)
    except ValueError:
        dauer = 0.0
    return {"dauer": dauer, "video": "video" in arten, "audio": "audio" in arten}


def aufbereiten(quelle: str, zielordner: str, basisname: str, *,
                normalisieren: bool = False, kopf: Optional[bytes] = None) -> dict:
    """Bringt eine hochgeladene Datei in ihre endgueltige Form.

    Gibt ``{"datei", "mime", "groesse", "dauer", "video"}`` zurueck. Die
    Quelldatei wird dabei verbraucht (verschoben oder geloescht).
    """
    if kopf is None:
        with open(quelle, "rb") as f:
            kopf = f.read(64)
    erkannt = erkennen(kopf)
    if erkannt is None or erkannt[1] == "bild":
        raise ValueError("Keine Audio- oder Videodatei (erlaubt: MP3, M4A, MP4, WebM, Ogg, WAV)")
    endung, art = erkannt
    info = pruefen(quelle)
    video = info.get("video", False) if info else art == "video"
    if not info and art == "container":
        # Ohne ffprobe laesst sich WebM/MP4 nicht sicher zuordnen. Video ist
        # die vorsichtige Annahme: ein <video>-Element spielt auch reinen Ton.
        video = True

    if ffmpeg_verfuegbar() and info:
        if video:
            ziel_endung, argumente = ".mp4", [
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
                "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart"]
        else:
            ziel_endung, argumente = ".mp3", ["-vn", "-c:a", "libmp3lame", "-b:a", "128k"]
        if normalisieren and info.get("audio"):
            argumente = ["-af", LOUDNORM] + argumente
        # MP3/M4A und MP4 spielt alles ab - nicht unnoetig neu kodieren.
        bereits_fertig = not normalisieren and (
            (not video and endung in (".mp3", ".m4a")) or (video and endung == ".mp4"))
        if not bereits_fertig:
            ziel = os.path.join(zielordner, basisname + ziel_endung)
            # Erst unter verstecktem Namen fertig schreiben, dann umbenennen:
            # Eine halb geschriebene Datei darf niemand (auch nicht der
            # Tresor-Abgleich) zu sehen bekommen.
            arbeit = os.path.join(zielordner, "." + basisname + ".arbeit" + ziel_endung)
            try:
                subprocess.run(["ffmpeg", "-y", "-v", "error"] + NUR_DATEI + ["-i", quelle]
                               + argumente + [arbeit],
                               capture_output=True, timeout=6 * 3600, check=True)
            except subprocess.CalledProcessError as fehler:
                _weg(arbeit)
                meldung = (fehler.stderr or b"").decode(errors="replace").strip()[-300:]
                raise ValueError(f"Umwandlung fehlgeschlagen: {meldung or 'ffmpeg-Fehler'}")
            except BaseException:
                _weg(arbeit)
                raise
            os.replace(arbeit, ziel)
            _weg(quelle)
            neu = pruefen(ziel)
            return _ergebnis(ziel, neu.get("dauer") or info.get("dauer", 0.0), video)

    if endung == ".webm" and not video:
        endung = ".weba"
    ziel = os.path.join(zielordner, basisname + endung)
    os.replace(quelle, ziel)
    return _ergebnis(ziel, info.get("dauer", 0.0), video)


def bild_speichern(quelle: str, zielordner: str, basisname: str) -> str:
    """Prueft ein Cover-Bild und legt es ab. Gibt den Dateinamen zurueck."""
    with open(quelle, "rb") as f:
        erkannt = erkennen(f.read(64))
    if erkannt is None or erkannt[1] != "bild":
        _weg(quelle)
        raise ValueError("Cover bitte als JPG, PNG oder WebP")
    ziel = os.path.join(zielordner, basisname + erkannt[0])
    os.replace(quelle, ziel)
    return os.path.basename(ziel)


def mime_fuer(name: str) -> str:
    return MIME.get(os.path.splitext(name)[1].lower(), "application/octet-stream")


def _ergebnis(pfad: str, dauer: float, video: bool) -> dict:
    name = os.path.basename(pfad)
    mime = mime_fuer(name)
    if mime == "video/webm" and not video:
        mime = "audio/webm"
    return {"datei": name, "mime": mime, "groesse": os.path.getsize(pfad),
            "dauer": float(dauer or 0.0), "video": video}


def _weg(pfad: str) -> None:
    try:
        os.remove(pfad)
    except OSError:
        pass
