"""Zwei-Faktor-Anmeldung mit Einmalcodes (TOTP, RFC 6238).

Passt zu jeder Authenticator-App (Google/Microsoft Authenticator, Aegis,
2FAS, 1Password ...). Wer das Passwort erbeutet, kommt ohne das Handy
trotzdem nicht ins Studio.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from typing import Optional
from urllib.parse import quote

SCHRITT = 30
STELLEN = 6


def neues_geheimnis() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code(geheimnis: str, zaehler: int) -> str:
    schluessel = base64.b32decode(geheimnis.replace(" ", "").upper())
    h = hmac.new(schluessel, struct.pack(">Q", zaehler), hashlib.sha1).digest()
    versatz = h[-1] & 0x0F
    wert = struct.unpack(">I", h[versatz:versatz + 4])[0] & 0x7FFFFFFF
    return str(wert % 10 ** STELLEN).zfill(STELLEN)


def pruefen(geheimnis: str, eingabe: str, zeit: float, fenster: int = 1) -> Optional[int]:
    """Gibt den Zaehler des passenden Codes zurueck, sonst ``None``.

    ``fenster`` erlaubt eine Abweichung der Uhren um so viele 30-Sekunden-
    Schritte. Den Zaehler braucht der Aufrufer, um einen schon benutzten
    Code abzuweisen.
    """
    eingabe = "".join(z for z in str(eingabe) if z.isdigit())
    if len(eingabe) != STELLEN:
        return None
    jetzt = int(zeit // SCHRITT)
    treffer = None
    for z in range(jetzt - fenster, jetzt + fenster + 1):
        # Alle Kandidaten pruefen, nicht beim ersten Treffer aufhoeren -
        # sonst verraet die Laufzeit, welcher es war.
        if hmac.compare_digest(code(geheimnis, z), eingabe):
            treffer = z
    return treffer


def uri(geheimnis: str, konto: str, aussteller: str = "Sendestudio") -> str:
    return (f"otpauth://totp/{quote(aussteller)}:{quote(konto)}?secret={geheimnis}"
            f"&issuer={quote(aussteller)}&digits={STELLEN}&period={SCHRITT}")
