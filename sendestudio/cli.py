"""Kommandozeile: ``sendestudio init | passwort | serve | export | ftp``."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import secrets
import sys
import time
from typing import List, Optional

from . import media, publish, zweifaktor
from .config import STANDARD_PFAD, Config, laden, neues_passwort, passwort_hash, speichern
from .tresor import Tresor, TresorFehler
from .version import __version__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="sendestudio",
        description="Podcasts, Radio und Dokumentationen aufnehmen und ins Netz stellen.")
    p.add_argument("--version", action="version", version=f"sendestudio {__version__}")
    p.add_argument("-c", "--config", default=STANDARD_PFAD,
                   help=f"Konfigurationsdatei (Standard: {STANDARD_PFAD})")
    sub = p.add_subparsers(dest="befehl", required=True)

    i = sub.add_parser("init", help="Konfiguration und Passwort anlegen")
    i.add_argument("--titel", default="Mein Sender", help="Name der öffentlichen Seite")
    i.add_argument("--basis-url", default="", help="Öffentliche Adresse, z.B. https://radio.example.de")
    i.add_argument("--force", action="store_true", help="Vorhandene Konfiguration überschreiben")

    pw = sub.add_parser("passwort", help="Neues Studio-Passwort setzen")
    pw.add_argument("--zufall", action="store_true", help="Zufälliges Passwort erzeugen und anzeigen")

    z = sub.add_parser("zweifaktor", help="Zwei-Faktor-Anmeldung (Authenticator-App) einrichten")
    z.add_argument("--aus", action="store_true", help="Zwei-Faktor-Anmeldung abschalten")

    s = sub.add_parser("serve", help="Studio und öffentliche Seite starten")
    s.add_argument("--host", help="Adresse (Standard aus der Konfiguration)")
    s.add_argument("--port", type=int, help="Port (Standard aus der Konfiguration)")

    e = sub.add_parser("export", help="Statische Seite in einen Ordner schreiben")
    e.add_argument("ziel", nargs="?", help="Zielordner (Standard: export_ziel)")

    sub.add_parser("ftp", help="Exportieren und per FTP/FTPS hochladen")

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if a.befehl == "init":
        return _init(a)
    try:
        cfg = laden(a.config)
    except FileNotFoundError:
        print(f"{a.config} fehlt - zuerst 'sendestudio init' ausführen.", file=sys.stderr)
        return 2
    except ValueError as f:
        print(f"Konfiguration fehlerhaft: {f}", file=sys.stderr)
        return 2

    if a.befehl == "passwort":
        tresor = _tresor(cfg)
        if tresor.existiert:
            # Ohne das alte Geheimnis laesst sich der Tresor nicht neu
            # verschliessen - und wer es nicht kennt, soll es nicht koennen.
            alt = getpass.getpass("Aktuelles Passwort oder Wiederherstellungsschlüssel: ")
            try:
                tresor.entsperren(alt)
            except TresorFehler as f:
                print(f, file=sys.stderr)
                return 1
        if a.zufall:
            neu = neues_passwort()
        else:
            neu = getpass.getpass("Neues Passwort: ")
            if len(neu) < 10:
                print("Bitte mindestens 10 Zeichen.", file=sys.stderr)
                return 1
            if getpass.getpass("Wiederholen: ") != neu:
                print("Stimmt nicht überein.", file=sys.stderr)
                return 1
        cfg.passwort_hash = passwort_hash(neu)
        speichern(cfg, a.config)
        os.makedirs(cfg.datenordner, exist_ok=True)
        wieder = tresor.neues_passwort(neu) if tresor.existiert else tresor.anlegen(neu)
        tresor.sperren()
        print(f"Passwort gesetzt{': ' + neu if a.zufall else '.'}")
        _wiederherstellung_zeigen(wieder)
        print("Läuft der Server, bitte neu starten.")
        return 0

    if a.befehl == "zweifaktor":
        return _zweifaktor(cfg, a)

    if a.befehl == "serve":
        return _serve(cfg, a.host, a.port)

    if a.befehl == "export":
        from .server import Studio
        studio = Studio(cfg, guard=None)
        try:
            ziel = a.ziel or cfg.pfad(cfg.export_ziel)
            erg = publish.exportieren(studio.store, cfg.medienordner, ziel,
                                      basis_url=cfg.basis_url, seitentitel=cfg.seitentitel)
        finally:
            studio.close()
        print(f"{erg['dateien']} Dateien in {erg['ziel']} "
              f"({erg['geschrieben']} Seiten neu, {erg['medien_kopiert']} Medien kopiert, "
              f"{erg['entfernt']} entfernt)")
        if erg["ohne_feed"]:
            print("Hinweis: ohne basis_url gibt es keinen Podcast-Feed.")
        return 0

    if a.befehl == "ftp":
        if not cfg.ftp.host:
            print("Kein FTP-Zugang in der Konfiguration (Abschnitt \"ftp\").", file=sys.stderr)
            return 2
        from .server import Studio
        studio = Studio(cfg, guard=None)
        try:
            ziel = cfg.pfad(cfg.export_ziel)
            publish.exportieren(studio.store, cfg.medienordner, ziel,
                                basis_url=cfg.basis_url, seitentitel=cfg.seitentitel)
        finally:
            studio.close()
        erg = publish.ftp_hochladen(ziel, host=cfg.ftp.host, benutzer=cfg.ftp.benutzer,
                                    passwort=cfg.ftp.passwort, pfad=cfg.ftp.pfad,
                                    port=cfg.ftp.port, tls=cfg.ftp.tls, fortschritt=print)
        print(f"{erg['hochgeladen']} hochgeladen, {erg['uebersprungen']} unverändert.")
        return 0
    return 1  # pragma: no cover


def _init(a: argparse.Namespace) -> int:
    if os.path.exists(a.config) and not a.force:
        print(f"{a.config} gibt es schon (--force zum Überschreiben).", file=sys.stderr)
        return 1
    passwort = neues_passwort()
    cfg = Config(seitentitel=a.titel, basis_url=a.basis_url.rstrip("/"),
                 passwort_hash=passwort_hash(passwort), geheimnis=secrets.token_hex(32))
    try:
        cfg.validate()
    except ValueError as f:
        print(f, file=sys.stderr)
        return 1
    speichern(cfg, a.config)
    os.makedirs(cfg.medienordner, mode=0o700, exist_ok=True)
    os.chmod(cfg.datenordner, 0o700)
    tresor = _tresor(cfg)
    if tresor.existiert:
        print(f"In {cfg.datenordner} liegt schon ein Tresor - bitte leeren Datenordner "
              "verwenden oder 'sendestudio passwort' benutzen.", file=sys.stderr)
        return 1
    wieder = tresor.anlegen(passwort)
    tresor.sperren()
    print(f"Konfiguration: {os.path.abspath(a.config)}")
    print(f"Studio-Passwort: {passwort}")
    print("  (gut aufheben - es wird nur gehasht gespeichert; ändern mit 'sendestudio passwort')")
    _wiederherstellung_zeigen(wieder)
    print("Noch sicherer: 'sendestudio zweifaktor' - dann braucht die Anmeldung zusätzlich "
          "einen Code vom Handy.")
    if not media.ffmpeg_verfuegbar():
        print("Tipp: Mit ffmpeg werden Aufnahmen automatisch in MP3/MP4 umgewandelt "
              "und in der Lautstärke angeglichen.")
    print("Starten mit: sendestudio serve")
    return 0


def _serve(cfg: Config, host: Optional[str], port: Optional[int]) -> int:
    from .server import Studio, server_starten
    studio = Studio(cfg)
    server = server_starten(studio, host, port)
    h, p = server.server_address[:2]
    anzeige = "127.0.0.1" if h in ("0.0.0.0", "") else h
    print(f"Studio:            http://{anzeige}:{p}/studio")
    print(f"Öffentliche Seite: http://{anzeige}:{p}/")
    if not cfg.passwort_hash:
        print("Achtung: kein Passwort gesetzt - 'sendestudio passwort' ausführen.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        studio.close()
    return 0


def _tresor(cfg: Config) -> Tresor:
    return Tresor(os.path.join(cfg.datenordner, "tresor.json"))


def _wiederherstellung_zeigen(schluessel: str) -> None:
    print(f"Wiederherstellungsschlüssel: {schluessel}")
    print("  Unveröffentlichte Aufnahmen liegen verschlüsselt. Ohne Passwort UND ohne")
    print("  diesen Schlüssel sind sie verloren - bitte ausdrucken oder offline aufheben.")


def _zweifaktor(cfg: Config, a: argparse.Namespace) -> int:
    if a.aus:
        cfg.totp_geheimnis = ""
        speichern(cfg, a.config)
        print("Zwei-Faktor-Anmeldung ist aus. Läuft der Server, bitte neu starten.")
        return 0
    geheimnis = zweifaktor.neues_geheimnis()
    gruppen = " ".join(geheimnis[i:i + 4] for i in range(0, len(geheimnis), 4))
    print("In der Authenticator-App ein neues Konto anlegen ('Schlüssel manuell eingeben'):")
    print(f"  Schlüssel: {gruppen}")
    print("  Art: zeitbasiert, 6 Stellen")
    print(f"  oder als Link: {zweifaktor.uri(geheimnis, cfg.seitentitel)}")
    # Erst speichern, wenn die App nachweislich richtig rechnet - sonst
    # sperrt man sich selbst aus.
    for _ in range(3):
        try:
            eingabe = input("Code aus der App zur Bestätigung: ")
        except EOFError:
            break
        if zweifaktor.pruefen(geheimnis, eingabe, time.time()) is not None:
            cfg.totp_geheimnis = geheimnis
            speichern(cfg, a.config)
            print("Zwei-Faktor-Anmeldung ist an. Läuft der Server, bitte neu starten.")
            return 0
        print("Der Code passt nicht - stimmt die Uhrzeit auf dem Handy?")
    print("Nicht eingerichtet.", file=sys.stderr)
    return 1
