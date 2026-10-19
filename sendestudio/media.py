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
    dauer = info.get("dauer", 0.0)
    if not dauer and endung == ".mp3":
        dauer = mp3_dauer_schaetzen(ziel)
    return _ergebnis(ziel, dauer, video)


#: Bitraten (kbit/s) fuer MPEG-1 bzw. MPEG-2/2.5 Layer III, nach Index im Frame-Kopf.
_MP3_BITRATEN = {
    1: (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    2: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}


def mp3_dauer_schaetzen(pfad: str) -> float:
    """Laenge einer MP3 ohne ffmpeg - aus der Bitrate des ersten Frames.

    Genau fuer Dateien mit fester Bitrate (KI-Stimmen, die meisten
    Podcasts), eine Naeherung fuer variable. Besser als gar keine Laenge:
    Ohne sie fehlt die Folge im Radioprogramm und die Dauer im Feed.
    """
    try:
        groesse = os.path.getsize(pfad)
        with open(pfad, "rb") as f:
            kopf = f.read(10)
            start = 0
            if kopf[:3] == b"ID3" and len(kopf) == 10:
                start = 10 + ((kopf[6] & 0x7F) << 21 | (kopf[7] & 0x7F) << 14
                              | (kopf[8] & 0x7F) << 7 | (kopf[9] & 0x7F))
            f.seek(start)
            daten = f.read(64 * 1024)
    except OSError:
        return 0.0
    for i in range(len(daten) - 3):
        if daten[i] != 0xFF or daten[i + 1] & 0xE0 != 0xE0:
            continue
        version = (daten[i + 1] >> 3) & 0x03   # 3 = MPEG-1, 2 = MPEG-2, 0 = MPEG-2.5
        schicht = (daten[i + 1] >> 1) & 0x03   # 1 = Layer III
        index = daten[i + 2] >> 4
        if version == 1 or schicht != 1 or not 0 < index < 15:
            continue
        raten = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}
        raten_index = (daten[i + 2] >> 2) & 0x03
        if raten_index == 3:
            continue
        abtastrate = raten[version][raten_index]
        # Xing-/Info-Kopf im ersten Frame: dort steht die Zahl der Frames -
        # genau, auch bei variabler Bitrate.
        for marke in (b"Xing", b"Info"):
            pos = daten.find(marke, i + 4, i + 200)
            if pos >= 0 and len(daten) >= pos + 12 and daten[pos + 7] & 0x01:
                frames = int.from_bytes(daten[pos + 8:pos + 12], "big")
                proben = 1152 if version == 3 else 576
                return round(frames * proben / abtastrate, 2)
        kbit = _MP3_BITRATEN[1 if version == 3 else 2][index]
        return round((groesse - start - i) * 8 / (kbit * 1000), 2)
    return 0.0


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


# ----------------------------------------------------------------------
# Fuer die KI-Werkzeuge: Ton verbinden, Videos bauen
# ----------------------------------------------------------------------
#: Farben der Wellenform im Video - passend zur oeffentlichen Seite.
_HINTERGRUND = "0x161412"
_WELLE = "0xfb923c"


def _ffmpeg(argumente: list, timeout: float = 6 * 3600) -> None:
    if not ffmpeg_verfuegbar():
        raise ValueError("Dafür wird ffmpeg gebraucht (z.B. 'sudo apt install ffmpeg')")
    try:
        subprocess.run(["ffmpeg", "-y", "-v", "error", "-nostdin"] + argumente,
                       capture_output=True, timeout=timeout, check=True)
    except subprocess.CalledProcessError as fehler:
        meldung = (fehler.stderr or b"").decode(errors="replace").strip()[-300:]
        raise ValueError(f"ffmpeg: {meldung or 'Fehler'}")


def mp3_verbinden(teile: list, ziel: str) -> None:
    """Haengt MP3-Stuecke (bytes) aneinander."""
    if len(teile) == 1 or not ffmpeg_verfuegbar():
        # MP3 besteht aus unabhaengigen Frames - Aneinanderhaengen spielt
        # jeder Player ab. Mit ffmpeg wird es sauberer (Laenge, Kopfdaten).
        with open(ziel, "wb") as f:
            for t in teile:
                f.write(t)
        return
    ordner = os.path.dirname(os.path.abspath(ziel))
    namen = []
    try:
        liste = os.path.join(ordner, f".liste-{os.getpid()}-{id(teile)}.txt")
        for i, t in enumerate(teile):
            name = os.path.join(ordner, f".teil-{os.getpid()}-{id(teile)}-{i}.mp3")
            with open(name, "wb") as f:
                f.write(t)
            namen.append(name)
        with open(liste, "w") as f:
            f.writelines(f"file '{n}'\n" for n in namen)
        namen.append(liste)
        _ffmpeg(["-f", "concat", "-safe", "0", "-i", liste, "-c", "copy", ziel])
    finally:
        for n in namen:
            _weg(n)


def fuer_transkript(quelle: str, ziel: str) -> None:
    """Mono, 16 kHz, 32 kbit/s - reicht fuer Sprache, eine Stunde sind ~14 MB."""
    _ffmpeg(NUR_DATEI[:2] + ["-i", quelle, "-vn", "-ac", "1", "-ar", "16000",
                             "-c:a", "libmp3lame", "-b:a", "32k", ziel])


def bild_mindestgroesse(pfad: str, kante: int = 1400) -> None:
    """Vergroessert ein quadratisches Cover auf mindestens ``kante`` Pixel.

    Apple Podcasts verlangt 1400 x 1400 bis 3000 x 3000; Bildgeneratoren
    liefern meist 1024 x 1024. Ohne ffmpeg bleibt das Bild, wie es ist.
    """
    if not ffmpeg_verfuegbar():
        return
    ordner, name = os.path.split(pfad)
    tmp = os.path.join(ordner, "." + name.lstrip(".") + ".gross" + os.path.splitext(pfad)[1])
    try:
        _ffmpeg(["-i", pfad, "-vf", f"scale='max({kante},iw)':-1:flags=lanczos", tmp])
        os.replace(tmp, pfad)
    finally:
        _weg(tmp)


def _bild_filter(breite: int, hoehe: int) -> str:
    return (f"scale={breite}:{hoehe}:force_original_aspect_ratio=decrease,"
            f"pad={breite}:{hoehe}:(ow-iw)/2:(oh-ih)/2:color={_HINTERGRUND},setsar=1")


def video_aus_bild(bild: str, ton: str, ziel: str, *, breite: int = 1920,
                   hoehe: int = 1080) -> None:
    """Standbild + Tonspur + bewegte Wellenform -> MP4 (fuer YouTube & Co.)."""
    filter_ = (f"[0:v]{_bild_filter(breite, hoehe)}[bg];"
               f"[1:a]showwaves=s={breite}x{hoehe // 6}:mode=cline:rate=25:draw=full:colors={_WELLE}[w];"
               f"[bg][w]overlay=0:H-h-{hoehe // 12}:shortest=1,format=yuv420p[v]")
    _ffmpeg(["-loop", "1", "-framerate", "25", "-i", bild, "-i", ton,
             "-filter_complex", filter_, "-map", "[v]", "-map", "1:a",
             "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-r", "25",
             "-c:a", "aac", "-b:a", "160k", "-shortest", "-movflags", "+faststart", ziel])


def video_aus_szenen(szenen: list, ziel: str, *, breite: int = 1920, hoehe: int = 1080) -> None:
    """Szenen ``[(bild, ton), ...]`` -> ein MP4: jedes Bild so lange wie sein Ton,
    mit kurzer Ueberblendung von und nach Schwarz."""
    ordner = os.path.dirname(os.path.abspath(ziel))
    stuecke = []
    liste = os.path.join(ordner, f".szenen-{os.getpid()}-{id(szenen)}.txt")
    try:
        for i, (bild, ton) in enumerate(szenen):
            dauer = pruefen(ton).get("dauer") or 0.0
            if dauer <= 0:
                raise ValueError(f"Szene {i + 1}: Tonspur ohne Länge")
            aus = max(0.0, dauer - 0.4)
            stueck = os.path.join(ordner, f".szene-{os.getpid()}-{id(szenen)}-{i}.mp4")
            stuecke.append(stueck)
            _ffmpeg(["-loop", "1", "-framerate", "25", "-i", bild, "-i", ton,
                     "-vf", f"{_bild_filter(breite, hoehe)},fade=t=in:st=0:d=0.4,"
                            f"fade=t=out:st={aus:.2f}:d=0.4,format=yuv420p",
                     "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-r", "25",
                     "-tune", "stillimage", "-c:a", "aac", "-b:a", "160k", "-ar", "44100",
                     "-ac", "2", "-t", f"{dauer:.3f}", stueck])
        with open(liste, "w") as f:
            f.writelines(f"file '{s}'\n" for s in stuecke)
        _ffmpeg(["-f", "concat", "-safe", "0", "-i", liste, "-c", "copy",
                 "-movflags", "+faststart", ziel])
    finally:
        for s in stuecke + [liste]:
            _weg(s)
