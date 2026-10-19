"""Konfiguration (JSON) und Passwort."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

STANDARD_PFAD = "sendestudio.json"
_ITERATIONEN = 310_000


@dataclass
class FtpConfig:
    host: str = ""
    benutzer: str = ""
    passwort: str = ""
    pfad: str = "/"
    port: int = 21
    #: FTPS. Unverschluesseltes FTP schickt das Passwort im Klartext.
    tls: bool = True


@dataclass
class Config:
    #: Ordner fuer Datenbank und Mediendateien.
    daten: str = "sendestudio-daten"
    host: str = "127.0.0.1"
    port: int = 8790
    #: Oeffentliche Adresse, z.B. ``https://radio.example.de``. Ohne sie
    #: gibt es keinen Feed - Podcast-Apps brauchen absolute Adressen.
    basis_url: str = ""
    seitentitel: str = "Mein Sender"
    passwort_hash: str = ""
    #: Schluessel fuer den Login-Schutz (LoginShield).
    geheimnis: str = ""
    max_upload_mb: int = 4096
    #: Cookie nur ueber HTTPS senden. Einschalten, sobald HTTPS laeuft.
    sicheres_cookie: bool = False
    export_ziel: str = "oeffentlich"
    #: Proxys, deren X-Forwarded-For geglaubt wird (z.B. ["127.0.0.1"]).
    vertraute_proxys: List[str] = field(default_factory=list)
    #: Nur aus diesen Netzen ist das Studio erreichbar, z.B.
    #: ["192.168.0.0/16"] fuers Heimnetz. Leer = von ueberall (mit Login).
    studio_netze: List[str] = field(default_factory=list)
    #: Geheimnis fuer die Zwei-Faktor-Anmeldung ('sendestudio zweifaktor').
    totp_geheimnis: str = ""
    #: Nach so vielen Minuten ohne Aktivitaet wird abgemeldet - und der
    #: Tresor schliesst sich, sobald niemand mehr angemeldet ist.
    leerlauf_minuten: int = 60
    ftp: FtpConfig = field(default_factory=FtpConfig)
    #: Woher die Datei geladen wurde - relative Pfade gelten von dort aus.
    quelle: str = field(default="", repr=False)

    def pfad(self, wert: str) -> str:
        if os.path.isabs(wert):
            return wert
        return os.path.join(os.path.dirname(os.path.abspath(self.quelle or STANDARD_PFAD)), wert)

    @property
    def datenordner(self) -> str:
        return self.pfad(self.daten)

    @property
    def medienordner(self) -> str:
        return os.path.join(self.datenordner, "medien")

    def validate(self) -> None:
        if not (0 < self.port < 65536):
            raise ValueError("port muss zwischen 1 und 65535 liegen")
        if self.basis_url and not self.basis_url.startswith(("http://", "https://")):
            raise ValueError("basis_url muss mit http:// oder https:// beginnen")
        if self.max_upload_mb <= 0:
            raise ValueError("max_upload_mb muss positiv sein")
        if not 1 <= self.leerlauf_minuten <= 24 * 60:
            raise ValueError("leerlauf_minuten muss zwischen 1 und 1440 liegen")
        for netz in self.studio_netze + self.vertraute_proxys:
            try:
                ipaddress.ip_network(str(netz).strip(), strict=False)
            except ValueError:
                raise ValueError(f"Keine gueltige Adresse bzw. kein gueltiges Netz: {netz!r}")

    def als_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("quelle")
        return d


def laden(pfad: str = STANDARD_PFAD) -> Config:
    with open(pfad, encoding="utf-8") as f:
        roh = json.load(f)
    if not isinstance(roh, dict):
        raise ValueError(f"{pfad}: erwartet ein JSON-Objekt")
    ftp_roh = roh.pop("ftp", {}) or {}
    bekannt = set(Config.__dataclass_fields__) - {"ftp", "quelle"}
    unbekannt = set(roh) - bekannt
    if unbekannt:
        raise ValueError(f"{pfad}: unbekannte Einstellung(en): {', '.join(sorted(unbekannt))}")
    unbekannt = set(ftp_roh) - set(FtpConfig.__dataclass_fields__)
    if unbekannt:
        raise ValueError(f"{pfad}: unbekannte FTP-Einstellung(en): {', '.join(sorted(unbekannt))}")
    cfg = Config(**roh, ftp=FtpConfig(**ftp_roh), quelle=os.path.abspath(pfad))
    cfg.validate()
    return cfg


def speichern(cfg: Config, pfad: str) -> None:
    # Die Datei enthaelt Passwort-Hash und ggf. FTP-Passwort: nur fuer den Besitzer.
    fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg.als_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    cfg.quelle = os.path.abspath(pfad)


def passwort_hash(passwort: str, *, salz: str = "", iterationen: int = _ITERATIONEN) -> str:
    salz = salz or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", passwort.encode(), salz.encode(), iterationen)
    return f"pbkdf2_sha256${iterationen}${salz}${h.hex()}"


def passwort_pruefen(passwort: str, gespeichert: str) -> bool:
    try:
        verfahren, iterationen, salz, soll = gespeichert.split("$")
    except ValueError:
        return False
    if verfahren != "pbkdf2_sha256":
        return False
    ist = passwort_hash(passwort, salz=salz, iterationen=int(iterationen)).split("$")[3]
    return hmac.compare_digest(ist, soll)


def neues_passwort() -> str:
    """Gut merkbar genug zum Abtippen, lang genug gegen Raten."""
    return "-".join(secrets.token_urlsafe(6) for _ in range(3))
