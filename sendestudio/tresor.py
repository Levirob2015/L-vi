"""Der Tresor: Unveroeffentlichtes liegt nur verschluesselt auf der Platte.

Jede Aufnahme, die (noch) nicht oeffentlich ist - Entwuerfe, zurueckgezogene
Folgen, Cover von Sendungen ohne veroeffentlichte Folge - wird
verschluesselt abgelegt. Erst beim Veroeffentlichen entsteht die lesbare
Datei, beim Zurueckziehen wird sie wieder verschluesselt.

Der Schluessel liegt nirgends im Klartext. Er ist doppelt eingepackt: mit
dem Studio-Passwort und mit einem Wiederherstellungsschluessel, den
``sendestudio init`` einmal anzeigt. Der Server kennt ihn nur, solange
jemand im Studio angemeldet ist - nach einem Neustart, einer Abmeldung oder
wenn die Sitzung ablaeuft, vergisst er ihn. Wer die Platte, ein Backup oder
den Server ohne Passwort in die Haende bekommt, sieht von den Entwuerfen
nur Datenmuell.

Verfahren - nur aus Bausteinen der Standardbibliothek, nichts selbst
Erfundenes an den Primitiven:

* Schluesselableitung: PBKDF2-HMAC-SHA256.
* Verschluesselung: SHAKE-256 als Schluesselstrom (Schluessel, Zufallswert
  und Blocknummer als Eingabe - ein Keccak-PRF, wie bei KMAC), per XOR.
* Integritaet: HMAC-SHA256 ueber jeden Block (Encrypt-then-MAC). Die
  Blocknummer und ein Ende-Kennzeichen sind mit abgesichert - vertauschte,
  veraenderte oder abgeschnittene Bloecke fallen auf.

Die Datei wird in Bloecken von 1 MiB verarbeitet. Dadurch laesst sich auch
eine verschluesselte Aufnahme im Studio vorhoeren und vorspulen, ohne sie
vorher ganz zu entschluesseln.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from typing import Iterator, Optional

ENDUNG = ".tresor"
MAGIC = b"SSTR1\n"
NONCE = 16
TAG = 32
BLOCK = 1 << 20
_KOPF = len(MAGIC) + NONCE
_ITERATIONEN = 310_000


class TresorFehler(Exception):
    """Falscher Schluessel, beschaedigte oder manipulierte Datei."""


def _ableiten(geheimnis: str, salz: bytes, iterationen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", geheimnis.encode(), salz, iterationen, dklen=64)


def _strom(schluessel: bytes, nonce: bytes, nummer: int, laenge: int) -> bytes:
    h = hashlib.shake_256(b"sendestudio-strom\0" + schluessel + nonce + nummer.to_bytes(8, "big"))
    return h.digest(laenge)


def _xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "little") ^ int.from_bytes(b[:len(a)], "little")).to_bytes(len(a), "little")


def _teilschluessel(hauptschluessel: bytes) -> tuple:
    enc = hmac.new(hauptschluessel, b"verschluesseln", hashlib.sha256).digest()
    mac = hmac.new(hauptschluessel, b"absichern", hashlib.sha256).digest()
    return enc, mac


def einpacken(hauptschluessel: bytes, geheimnis: str, iterationen: int = _ITERATIONEN) -> dict:
    salz, nonce = secrets.token_bytes(16), secrets.token_bytes(NONCE)
    kek = _ableiten(geheimnis, salz, iterationen)
    ct = _xor(hauptschluessel, _strom(kek[:32], nonce, 0, len(hauptschluessel)))
    tag = hmac.new(kek[32:], nonce + ct, hashlib.sha256).digest()
    return {"salz": salz.hex(), "iterationen": iterationen, "nonce": nonce.hex(),
            "schluessel": ct.hex(), "tag": tag.hex()}


def auspacken(paket: dict, geheimnis: str) -> bytes:
    try:
        salz, nonce = bytes.fromhex(paket["salz"]), bytes.fromhex(paket["nonce"])
        ct, tag = bytes.fromhex(paket["schluessel"]), bytes.fromhex(paket["tag"])
        iterationen = int(paket["iterationen"])
    except (KeyError, TypeError, ValueError):
        raise TresorFehler("Schluesseldatei beschaedigt")
    kek = _ableiten(geheimnis, salz, iterationen)
    if not hmac.compare_digest(hmac.new(kek[32:], nonce + ct, hashlib.sha256).digest(), tag):
        raise TresorFehler("Falsches Passwort oder falscher Wiederherstellungsschluessel")
    return _xor(ct, _strom(kek[:32], nonce, 0, len(ct)))


def neuer_wiederherstellungsschluessel() -> str:
    roh = base64.b32encode(secrets.token_bytes(20)).decode()
    return "-".join(roh[i:i + 4] for i in range(0, len(roh), 4))


def _normalisieren(schluessel: str) -> str:
    return schluessel.replace("-", "").replace(" ", "").upper()


class Tresor:
    """Haelt den Hauptschluessel - nur im Speicher, nur solange er offen ist."""

    def __init__(self, pfad: str, *, iterationen: int = _ITERATIONEN) -> None:
        self.pfad = pfad
        self.iterationen = iterationen
        self._hs: Optional[bytes] = None
        self._lock = threading.Lock()

    # -- Schluessel -------------------------------------------------------
    @property
    def existiert(self) -> bool:
        return os.path.exists(self.pfad)

    @property
    def offen(self) -> bool:
        return self._hs is not None

    def anlegen(self, passwort: str) -> str:
        """Neuer Tresor. Gibt den Wiederherstellungsschluessel zurueck."""
        if self.existiert:
            raise TresorFehler("Es gibt schon einen Tresor")
        hs = secrets.token_bytes(32)
        wieder = self._schreiben(hs, passwort)
        self._hs = hs
        return wieder

    def entsperren(self, geheimnis: str) -> None:
        """Mit Passwort oder Wiederherstellungsschluessel."""
        daten = self._lesen()
        try:
            hs = auspacken(daten["passwort"], geheimnis)
        except TresorFehler:
            hs = auspacken(daten["wiederherstellung"], _normalisieren(geheimnis))
        with self._lock:
            self._hs = hs

    def sperren(self) -> None:
        with self._lock:
            self._hs = None

    def neues_passwort(self, passwort: str) -> str:
        """Packt den Schluessel neu ein. Neuer Wiederherstellungsschluessel."""
        return self._schreiben(self._schluessel(), passwort)

    def _schreiben(self, hs: bytes, passwort: str) -> str:
        wieder = neuer_wiederherstellungsschluessel()
        daten = {"version": 1,
                 "passwort": einpacken(hs, passwort, self.iterationen),
                 "wiederherstellung": einpacken(hs, _normalisieren(wieder), self.iterationen)}
        tmp = self.pfad + ".neu"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(daten, f, indent=1)
        os.replace(tmp, self.pfad)
        return wieder

    def _lesen(self) -> dict:
        try:
            with open(self.pfad) as f:
                daten = json.load(f)
        except FileNotFoundError:
            raise TresorFehler("Kein Tresor angelegt")
        except ValueError:
            raise TresorFehler("Schluesseldatei beschaedigt")
        if not isinstance(daten, dict) or "passwort" not in daten:
            raise TresorFehler("Schluesseldatei beschaedigt")
        return daten

    def _schluessel(self) -> bytes:
        hs = self._hs
        if hs is None:
            raise TresorFehler("Tresor ist verschlossen")
        return hs

    # -- Kurze Texte (Titel, Beschreibung, Kapitel von Entwuerfen) ---------
    TEXT_PRAEFIX = "tresor:"

    def text_verschluesseln(self, text: str) -> str:
        enc, mac = _teilschluessel(self._schluessel())
        nonce = secrets.token_bytes(NONCE)
        roh = text.encode()
        ct = _xor(roh, _strom(enc, nonce, 1 << 62, len(roh)))
        tag = hmac.new(mac, b"text\0" + nonce + ct, hashlib.sha256).digest()
        return self.TEXT_PRAEFIX + base64.urlsafe_b64encode(nonce + ct + tag).decode()

    def text_entschluesseln(self, wert: str) -> str:
        enc, mac = _teilschluessel(self._schluessel())
        try:
            roh = base64.urlsafe_b64decode(wert[len(self.TEXT_PRAEFIX):].encode())
        except ValueError:
            raise TresorFehler("Text beschaedigt")
        nonce, ct, tag = roh[:NONCE], roh[NONCE:-TAG], roh[-TAG:]
        if len(roh) < NONCE + TAG or not hmac.compare_digest(
                tag, hmac.new(mac, b"text\0" + nonce + ct, hashlib.sha256).digest()):
            raise TresorFehler("Text beschaedigt oder manipuliert")
        return _xor(ct, _strom(enc, nonce, 1 << 62, len(ct))).decode()

    @classmethod
    def ist_verschluesselt(cls, wert: object) -> bool:
        return isinstance(wert, str) and wert.startswith(cls.TEXT_PRAEFIX)

    # -- Dateien ----------------------------------------------------------
    def verschluesseln(self, quelle: str, ziel: str) -> None:
        enc, mac = _teilschluessel(self._schluessel())
        nonce = secrets.token_bytes(NONCE)
        tmp = ziel + ".neu"
        try:
            with open(quelle, "rb") as ein, open(tmp, "wb") as aus:
                aus.write(MAGIC + nonce)
                nummer = 0
                block = ein.read(BLOCK)
                while True:
                    naechster = ein.read(BLOCK) if len(block) == BLOCK else b""
                    letzter = not naechster
                    ct = _xor(block, _strom(enc, nonce, nummer, len(block)))
                    aus.write(ct + self._tag(mac, nonce, nummer, letzter, ct))
                    if letzter:
                        break
                    block, nummer = naechster, nummer + 1
                aus.flush()
                os.fsync(aus.fileno())
            os.replace(tmp, ziel)
        except BaseException:
            _weg(tmp)
            raise

    def entschluesseln(self, quelle: str, ziel: str) -> None:
        tmp = ziel + ".neu"
        try:
            with open(tmp, "wb") as aus:
                for teil in self.lesen(quelle):
                    aus.write(teil)
            os.replace(tmp, ziel)
        except BaseException:
            _weg(tmp)
            raise

    @staticmethod
    def klartext_groesse(pfad: str) -> int:
        n = os.path.getsize(pfad) - _KOPF
        bloecke = max(1, -(-n // (BLOCK + TAG)))
        return max(0, n - bloecke * TAG)

    def lesen(self, pfad: str, start: int = 0, ende: Optional[int] = None) -> Iterator[bytes]:
        """Liefert den Klartext von ``start`` bis einschliesslich ``ende``."""
        enc, mac = _teilschluessel(self._schluessel())
        n = os.path.getsize(pfad) - _KOPF
        if n < TAG:
            raise TresorFehler("Datei beschaedigt")
        bloecke = -(-n // (BLOCK + TAG))
        groesse = n - bloecke * TAG
        if ende is None or ende >= groesse:
            ende = groesse - 1
        with open(pfad, "rb") as f:
            kopf = f.read(_KOPF)
            if kopf[:len(MAGIC)] != MAGIC:
                raise TresorFehler("Keine Tresor-Datei")
            nonce = kopf[len(MAGIC):]
            nummer = start // BLOCK if groesse else 0
            while True:
                f.seek(_KOPF + nummer * (BLOCK + TAG))
                roh = f.read(BLOCK + TAG)
                ct, tag = roh[:-TAG], roh[-TAG:]
                letzter = nummer == bloecke - 1
                if len(roh) < TAG or not hmac.compare_digest(
                        tag, self._tag(mac, nonce, nummer, letzter, ct)):
                    raise TresorFehler("Datei beschaedigt oder manipuliert")
                if groesse == 0 or start > ende:
                    return
                klar = _xor(ct, _strom(enc, nonce, nummer, len(ct)))
                von = max(start - nummer * BLOCK, 0)
                bis = min(ende - nummer * BLOCK + 1, len(klar))
                yield klar[von:bis]
                if letzter or (nummer + 1) * BLOCK > ende:
                    return
                nummer += 1

    @staticmethod
    def _tag(mac: bytes, nonce: bytes, nummer: int, letzter: bool, ct: bytes) -> bytes:
        return hmac.new(mac, nonce + nummer.to_bytes(8, "big") + (b"\1" if letzter else b"\0") + ct,
                        hashlib.sha256).digest()


def _weg(pfad: str) -> None:
    try:
        os.remove(pfad)
    except OSError:
        pass
