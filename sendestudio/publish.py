"""Ins Netz stellen: statischer Export und Hochladen per FTP.

Drei Wege fuehren ins Netz:

1. **Der Studio-Server selbst** - laeuft er auf einem Server mit eigener
   Adresse, ist alles Veroeffentlichte sofort oeffentlich erreichbar.
2. **Statischer Export** - ein Ordner mit fertigen HTML-Seiten, Feeds und
   Mediendateien. Passt auf jeden Webspace, GitHub Pages, Netlify usw.
3. **FTP/FTPS** - der Export wird direkt auf den Webspace geladen.
"""

from __future__ import annotations

import ftplib
import json
import os
import shutil
from typing import Callable, Dict, List, Optional

from . import feed, radio, site, zeitung
from .store import Store

MANIFEST = ".sendestudio-export.json"


def oeffentlich(store: Store) -> List[dict]:
    """Alle Sendungen mit ihren veroeffentlichten Folgen (neueste zuerst)."""
    eintraege = []
    for s in store.sendungen():
        s = dict(s, folgen=store.folgen(s["id"], nur_online=True))
        eintraege.append(s)
    return eintraege


def seiten(store: Store, basis_url: str, seitentitel: str) -> Dict[str, bytes]:
    """Jede oeffentliche Datei ausser den Medien: Pfad -> Inhalt."""
    eintraege = oeffentlich(store)
    ausgaben = store.zeitungen(nur_online=True)
    aus: Dict[str, bytes] = {
        "stil.css": site.STIL.encode(),
        "seite.js": site.SEITE_JS.encode(),
        "index.html": site.startseite(eintraege, seitentitel, zeitung_da=bool(ausgaben)).encode(),
        ".nojekyll": b"",
    }
    if ausgaben:
        aus["zeitung/index.html"] = zeitung.uebersicht(ausgaben, seitentitel).encode()
        for z in store.zeitungen(nur_online=True, mit_inhalt=True):
            aus[f"zeitung/{z['slug']}/index.html"] = zeitung.ausgabe_seite(z, seitentitel).encode()
    for s in eintraege:
        if not s["folgen"]:
            continue
        basis = f"s/{s['slug']}/"
        aus[basis + "index.html"] = site.sendung_seite(s, s["folgen"], seitentitel,
                                                       basis_url).encode()
        if basis_url:
            aus[basis + "feed.xml"] = feed.feed(s, s["folgen"], basis_url).encode()
        for f in s["folgen"]:
            aus[f"{basis}{f['slug']}/index.html"] = site.folge_seite(
                s, f, seitentitel, basis_url).encode()
            if f["sprechtext"].strip():
                aus[f"{basis}{f['slug']}/text.txt"] = sprechtext_datei(s, f)
        if s["art"] == "radio" and radio.programm(s["folgen"]):
            aus[basis + "radio/index.html"] = site.radio_seite(s, s["folgen"], seitentitel).encode()
    return aus


def sprechtext_datei(s: dict, f: dict) -> bytes:
    """Der gesprochene Text einer Folge als Textdatei (Transkript)."""
    return f"{f['titel']} – {s['titel']}\n\n{f['sprechtext'].strip()}\n".encode()


def medien(store: Store) -> List[str]:
    """Dateinamen aller Medien, die oeffentlich gebraucht werden."""
    namen = [a["bild"] for z in store.zeitungen(nur_online=True, mit_inhalt=True)
             for a in z["inhalt"]["artikel"] if a["bild"]]
    for s in oeffentlich(store):
        if not s["folgen"]:
            continue
        if s["cover"]:
            namen.append(s["cover"])
        namen.extend(f["datei"] for f in s["folgen"])
    return namen


def exportieren(store: Store, medienordner: str, ziel: str, *, basis_url: str = "",
                seitentitel: str = "Sendestudio") -> dict:
    """Schreibt die komplette oeffentliche Seite nach ``ziel``.

    Dateien eines frueheren Exports, die nicht mehr gebraucht werden
    (zurueckgezogene Folgen), werden entfernt. Alles andere im Zielordner
    bleibt unangetastet.
    """
    ziel = os.path.abspath(ziel)
    os.makedirs(ziel, exist_ok=True)
    alt = _manifest_lesen(ziel)
    neu: List[str] = []
    geschrieben = kopiert = 0

    for pfad, inhalt in seiten(store, basis_url, seitentitel).items():
        voll = _im_ziel(ziel, pfad)
        os.makedirs(os.path.dirname(voll), exist_ok=True)
        if not _gleich(voll, inhalt):
            with open(voll, "wb") as f:
                f.write(inhalt)
            geschrieben += 1
        neu.append(pfad)

    for name in medien(store):
        quelle = os.path.join(medienordner, name)
        pfad = f"medien/{name}"
        voll = _im_ziel(ziel, pfad)
        os.makedirs(os.path.dirname(voll), exist_ok=True)
        if not os.path.exists(quelle):
            continue
        if not (os.path.exists(voll) and os.path.getsize(voll) == os.path.getsize(quelle)
                and os.path.getmtime(voll) >= os.path.getmtime(quelle)):
            shutil.copy2(quelle, voll)
            kopiert += 1
        neu.append(pfad)

    entfernt = 0
    for pfad in set(alt) - set(neu):
        try:
            os.remove(_im_ziel(ziel, pfad))
            entfernt += 1
        except (OSError, ValueError):
            pass
    _leere_ordner_weg(ziel)
    with open(os.path.join(ziel, MANIFEST), "w") as f:
        json.dump(sorted(neu), f, indent=0)

    return {"ziel": ziel, "dateien": len(neu), "geschrieben": geschrieben,
            "medien_kopiert": kopiert, "entfernt": entfernt, "ohne_feed": not basis_url}


def ftp_hochladen(lokal: str, *, host: str, benutzer: str, passwort: str,
                  pfad: str = "/", port: int = 21, tls: bool = True,
                  fortschritt: Optional[Callable[[str], None]] = None,
                  verbindung: Optional[ftplib.FTP] = None) -> dict:
    """Laedt einen Export per FTP (standardmaessig verschluesselt: FTPS) hoch.

    Mediendateien, die dort schon mit gleicher Groesse liegen, werden
    uebersprungen - Audio ist gross, die Seiten sind klein.
    """
    if verbindung is None:
        ftp: ftplib.FTP = ftplib.FTP_TLS() if tls else ftplib.FTP()
        ftp.connect(host, port, timeout=60)
        ftp.login(benutzer, passwort)
        if tls:
            ftp.prot_p()  # type: ignore[attr-defined]
    else:
        ftp = verbindung
    hoch = uebersprungen = 0
    try:
        _ftp_ordner(ftp, pfad)
        for wurzel, ordner, dateien in os.walk(lokal):
            ordner.sort()
            rel = os.path.relpath(wurzel, lokal)
            entfernt = pfad.rstrip("/") + ("" if rel == "." else "/" + rel.replace(os.sep, "/"))
            _ftp_ordner(ftp, entfernt or "/")
            for name in sorted(dateien):
                if name == MANIFEST:
                    continue
                datei = os.path.join(wurzel, name)
                ziel = f"{entfernt}/{name}"
                if rel.split(os.sep)[0] == "medien":
                    try:
                        if ftp.size(ziel) == os.path.getsize(datei):
                            uebersprungen += 1
                            continue
                    except ftplib.all_errors:
                        pass
                with open(datei, "rb") as f:
                    ftp.storbinary(f"STOR {ziel}", f)
                hoch += 1
                if fortschritt:
                    fortschritt(ziel)
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()
    return {"hochgeladen": hoch, "uebersprungen": uebersprungen}


def _ftp_ordner(ftp: ftplib.FTP, pfad: str) -> None:
    teile = [t for t in pfad.split("/") if t]
    aktuell = ""
    for teil in teile:
        aktuell += "/" + teil
        try:
            ftp.mkd(aktuell)
        except ftplib.error_perm:
            pass  # gibt es schon


def _im_ziel(ziel: str, pfad: str) -> str:
    voll = os.path.abspath(os.path.join(ziel, pfad))
    if not voll.startswith(ziel + os.sep):
        raise ValueError(f"Pfad ausserhalb des Ziels: {pfad}")
    return voll


def _gleich(pfad: str, inhalt: bytes) -> bool:
    try:
        with open(pfad, "rb") as f:
            return f.read() == inhalt
    except OSError:
        return False


def _manifest_lesen(ziel: str) -> List[str]:
    try:
        with open(os.path.join(ziel, MANIFEST)) as f:
            daten = json.load(f)
        return [p for p in daten if isinstance(p, str)]
    except (OSError, ValueError):
        return []


def _leere_ordner_weg(ziel: str) -> None:
    # Nur in den Ordnern, die der Export selbst anlegt.
    for bereich in ("s", "medien"):
        for wurzel, _, _ in os.walk(os.path.join(ziel, bereich), topdown=False):
            try:
                if not os.listdir(wurzel):
                    os.rmdir(wurzel)
            except OSError:
                pass
