"""Signaturen: bekannte Schadsoftware am Fingerabdruck erkennen.

Das Herz eines Virenschutzes ist eine Liste von Fingerabdruecken. Jede
Datei wird durch eine Rechenvorschrift geschickt (MD5, SHA-1, SHA-256),
die aus beliebig vielen Bytes einen kurzen, eindeutigen Wert macht. Steht
dieser Wert in der Liste, ist die Datei genau die bekannte Schadsoftware -
kein Verdacht, kein Punktesystem, sondern ein Treffer.

Der ehrliche Teil
-----------------
Dieses Projekt liefert **keine eigene Signaturliste** mit. Eine solche
Liste zu pflegen ist die eigentliche Arbeit eines Virenschutzherstellers:
taeglich neue Muster, rund um die Uhr. Wer eine selbstgebaute Liste mit
zwanzig Eintraegen "Virenschutz" nennt, taeuscht Schutz vor - und das ist
schlechter als gar kein Schutz, weil man sich darauf verlaesst.

Geliefert wird deshalb der **Mechanismus**, und zwar so, dass eine echte,
gepflegte Liste hineinpasst:

* Gelesen werden die ueblichen Formate, auch das von ClamAV
  (``.hdb``/``.hsb``: ``hash:groesse:name``). Eine dort gepflegte Liste
  laesst sich also einfach ablegen.
* :func:`aktualisieren` holt eine Liste von einer Adresse und tauscht sie
  erst aus, wenn sie sich lesen laesst - eine kaputte Datei darf den
  Schutz nicht abschalten.
* Fest eingebaut ist genau eine Signatur: die EICAR-Testdatei. Sie ist
  voellig harmlos und dient seit jeher dazu, zu pruefen, ob die Pruefkette
  ueberhaupt anschlaegt.

Freigabeliste
-------------
Umgekehrt geht es auch: Ein Fingerabdruck in der Freigabeliste gilt immer
als sauber. Das ist der Notausgang fuer einen Fehlalarm - eine eigene
Datei, die wegen ihrer Merkmale auffaellt, wird einmal freigegeben statt
die Regel fuer alle abzuschalten.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

log = logging.getLogger("loginshield.signatures")

#: Standard-Testdatei der Virenschutzbranche. Voellig harmlos: eine
#: Zeichenkette, auf die sich die Hersteller geeinigt haben, damit sich
#: ein Scanner pruefen laesst, ohne echte Schadsoftware anzufassen.
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    b"ANTIVIRUS-TEST-FILE!$H+H*"
)

#: Laenge des Hexwertes -> Verfahren. Andere Laengen sind keine
#: Fingerabdruecke, die hier etwas zu suchen haetten.
ALGO_NACH_LAENGE = {32: "md5", 40: "sha1", 64: "sha256"}
ALGOS: Tuple[str, ...] = ("md5", "sha1", "sha256")

_HEX = re.compile(r"^[0-9a-f]+$")

#: Obergrenze fuer eine einzelne Signaturdatei. Eine Liste ist Text; was
#: darueber liegt, wird nicht eingelesen, sondern abgelehnt.
MAX_DATEI_BYTES = 64 * 1024 * 1024

#: Obergrenze fuer die Zahl der Signaturen im Speicher. Jeder Eintrag
#: kostet Platz; eine Liste ohne Grenze waere eine Speicherstelle, die
#: von aussen waechst.
MAX_SIGNATUREN = 1_000_000

#: Endungen, die beim Einlesen eines ganzen Verzeichnisses zaehlen.
SIGNATUR_ENDUNGEN = (".txt", ".sig", ".hdb", ".hsb", ".md5", ".sha256")


@dataclass(frozen=True)
class Signature:
    """Ein Fingerabdruck und wofuer er steht."""

    digest: str
    name: str
    algo: str
    #: Dateigroesse in Bytes, die dazugehoert. -1 = beliebig. ClamAV
    #: schreibt sie mit; sie macht einen Zufallstreffer noch
    #: unwahrscheinlicher.
    size: int = -1
    quelle: str = ""

    def as_dict(self) -> dict:
        return {"digest": self.digest, "name": self.name, "algo": self.algo,
                "size": self.size, "quelle": self.quelle}


def ist_digest(wert: str) -> bool:
    """Sieht das wie ein Fingerabdruck aus - und wenn ja, welcher?"""
    wert = (wert or "").strip().lower()
    return len(wert) in ALGO_NACH_LAENGE and bool(_HEX.match(wert))


def parse_zeile(zeile: str, quelle: str = "") -> Optional[Signature]:
    """Liest eine Zeile einer Signaturliste.

    Erlaubt sind:

    * ``<hash>``
    * ``<hash>  <name>``          (durch Leerraum getrennt)
    * ``<hash>:<name>``
    * ``<hash>:<groesse>:<name>`` (ClamAV; ``*`` heisst beliebig)

    Leerzeilen und Zeilen mit ``#`` oder ``;`` am Anfang sind Kommentare.
    Was sich nicht lesen laesst, ergibt ``None`` - eine einzelne kaputte
    Zeile darf nicht die ganze Liste unbrauchbar machen.
    """
    zeile = (zeile or "").strip()
    if not zeile or zeile[0] in "#;":
        return None

    felder = zeile.split(":")
    if len(felder) >= 2 and ist_digest(felder[0]):
        digest = felder[0].strip().lower()
        size = -1
        name = ""
        if len(felder) >= 3:
            roh = felder[1].strip()
            if roh and roh != "*":
                try:
                    size = int(roh)
                except ValueError:
                    size = -1
            name = felder[2].strip()
        else:
            name = felder[1].strip()
    else:
        teile = zeile.split(None, 1)
        digest = teile[0].strip().lower()
        name = teile[1].strip() if len(teile) > 1 else ""
        size = -1

    if not ist_digest(digest):
        return None
    return Signature(digest, name or "unbenannt",
                     ALGO_NACH_LAENGE[len(digest)], size, quelle)


def hashes_von_bytes(data: bytes,
                     algos: Sequence[str] = ALGOS) -> Dict[str, str]:
    """Fingerabdruecke eines Inhalts - nur die verlangten Verfahren."""
    ergebnis: Dict[str, str] = {}
    for algo in algos:
        if algo in ALGOS:
            ergebnis[algo] = hashlib.new(algo, data).hexdigest()
    return ergebnis


def hashes_von_datei(path: str, algos: Sequence[str] = ALGOS,
                     max_bytes: int = 0, chunk: int = 262_144) -> Dict[str, str]:
    """Fingerabdruecke einer Datei, ohne sie ganz in den Speicher zu holen.

    Ein Fingerabdruck gilt nur fuer den **vollstaendigen** Inhalt. Deshalb
    wird hier in Haeppchen ueber die ganze Datei gelesen - anders als bei
    der Musterpruefung, der die ersten Bytes reichen. Ist ``max_bytes``
    gesetzt und die Datei groesser, wird nichts geliefert: ein
    Fingerabdruck ueber die halbe Datei waere keiner.
    """
    verfahren = [a for a in algos if a in ALGOS]
    if not verfahren:
        return {}
    if max_bytes:
        try:
            if os.path.getsize(path) > max_bytes:
                return {}
        except OSError:
            return {}

    hasher = {a: hashlib.new(a) for a in verfahren}
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(chunk)
                if not block:
                    break
                for h in hasher.values():
                    h.update(block)
    except OSError as exc:
        log.debug("Fingerabdruck nicht moeglich fuer %s: %s", path, exc)
        return {}
    return {a: h.hexdigest() for a, h in hasher.items()}


class SignatureDB:
    """Die Liste der Fingerabdruecke - und die Freigabeliste dazu."""

    def __init__(self, *, mit_eicar: bool = True,
                 max_signaturen: int = MAX_SIGNATUREN) -> None:
        self._nach_algo: Dict[str, Dict[str, Signature]] = {a: {} for a in ALGOS}
        self._freigegeben: Set[str] = set()
        self.quellen: List[str] = []
        self.aktualisiert: float = 0.0
        self.max_signaturen = max(1, int(max_signaturen))
        self.uebersprungen = 0
        if mit_eicar:
            self._eicar_aufnehmen()

    # ------------------------------------------------------------------
    def _eicar_aufnehmen(self) -> None:
        """Die einzige fest eingebaute Signatur.

        Ihr Wert steht bewusst nicht als Zahlenkolonne im Quelltext,
        sondern wird aus der Testdatei selbst berechnet. So kann kein
        abgeschriebener Fingerabdruck falsch sein.

        Nur SHA-256, obwohl MD5 und SHA-1 genauso leicht zu haben waeren:
        Jedes zusaetzliche Verfahren in der Liste bedeutet einen weiteren
        Durchlauf ueber **jede** gepruefte Datei. Fuer eine einzige
        Testsignatur waere das die Haelfte der Arbeit fuer nichts - und
        die Testdatei wird ohnehin auch an ihrem Inhalt erkannt.
        """
        digest = hashes_von_bytes(EICAR, ("sha256",))["sha256"]
        self.add(Signature(digest, "EICAR-Testdatei (harmlos)", "sha256",
                           len(EICAR), "eingebaut"))

    def add(self, signature: Signature) -> bool:
        """Nimmt eine Signatur auf. Gibt zurueck, ob sie neu war."""
        if len(self) >= self.max_signaturen:
            self.uebersprungen += 1
            return False
        tabelle = self._nach_algo.get(signature.algo)
        if tabelle is None or signature.digest in tabelle:
            return False
        tabelle[signature.digest] = signature
        return True

    def add_zeile(self, zeile: str, quelle: str = "") -> bool:
        signature = parse_zeile(zeile, quelle)
        return self.add(signature) if signature else False

    def freigeben(self, digest: str) -> bool:
        """Setzt einen Fingerabdruck auf die Freigabeliste."""
        digest = (digest or "").strip().lower()
        if not ist_digest(digest):
            return False
        self._freigegeben.add(digest)
        return True

    # ------------------------------------------------------------------
    # Einlesen
    # ------------------------------------------------------------------
    def load_file(self, path: str, *, freigabe: bool = False) -> int:
        """Liest eine Liste ein und gibt die Zahl der neuen Eintraege zurueck.

        Zeilenweise gelesen, nicht am Stueck: Eine Liste kann sehr gross
        sein, und der Speicher des Servers gehoert nicht ihr.
        """
        try:
            groesse = os.path.getsize(path)
        except FileNotFoundError:
            # Der Normalfall bei einer Freigabeliste, in die noch niemand
            # etwas eingetragen hat - keine Warnung wert.
            log.debug("Signaturliste noch nicht vorhanden: %s", path)
            return 0
        except OSError as exc:
            log.warning("Signaturliste nicht lesbar: %s (%s)", path, exc)
            return 0
        if groesse > MAX_DATEI_BYTES:
            log.warning("Signaturliste %s uebersprungen: %.1f MB ist zu gross",
                        path, groesse / 1e6)
            return 0

        neu = 0
        quelle = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for zeile in handle:
                    if freigabe:
                        eintrag = parse_zeile(zeile, quelle)
                        if eintrag and self.freigeben(eintrag.digest):
                            neu += 1
                    elif self.add_zeile(zeile, quelle):
                        neu += 1
        except OSError as exc:
            log.warning("Signaturliste abgebrochen: %s (%s)", path, exc)
            return neu

        if neu:
            self.quellen.append(path)
            self.aktualisiert = max(self.aktualisiert,
                                    _mtime(path) or time.time())
        if self.uebersprungen:
            log.warning(
                "%s Signaturen nicht aufgenommen: die Obergrenze von %s ist "
                "erreicht", self.uebersprungen, self.max_signaturen,
            )
        return neu

    def load_dir(self, path: str, *, freigabe: bool = False) -> int:
        """Liest alle Signaturdateien eines Verzeichnisses (nicht rekursiv)."""
        if not os.path.isdir(path):
            return 0
        neu = 0
        for name in sorted(os.listdir(path)):
            if name.lower().endswith(SIGNATUR_ENDUNGEN):
                neu += self.load_file(os.path.join(path, name),
                                      freigabe=freigabe)
        return neu

    def load(self, dateien: Iterable[str] = (), verzeichnis: str = "",
             freigabe_dateien: Iterable[str] = ()) -> int:
        """Der uebliche Weg: Verzeichnis, Einzeldateien, Freigaben."""
        neu = 0
        if verzeichnis:
            neu += self.load_dir(verzeichnis)
        for datei in dateien:
            neu += self.load_file(datei)
        for datei in freigabe_dateien:
            self.load_file(datei, freigabe=True)
        return neu

    # ------------------------------------------------------------------
    # Nachschlagen
    # ------------------------------------------------------------------
    @property
    def algos(self) -> Tuple[str, ...]:
        """Welche Verfahren ueberhaupt gebraucht werden.

        Enthaelt die Liste nur SHA-256-Werte, muss niemand zusaetzlich
        MD5 rechnen. Bei grossen Verzeichnissen ist das der Unterschied
        zwischen einem und drei Durchlaeufen ueber jede Datei.
        """
        gebraucht = [a for a in ALGOS if self._nach_algo[a]]
        if self._freigegeben:
            # Fuer die Freigabeliste ist nicht bekannt, welches Verfahren
            # der Eintrag hat - die Laenge sagt es.
            for digest in self._freigegeben:
                algo = ALGO_NACH_LAENGE.get(len(digest))
                if algo and algo not in gebraucht:
                    gebraucht.append(algo)
        return tuple(a for a in ALGOS if a in gebraucht)

    def match_hashes(self, hashes: Dict[str, str],
                     size: int = -1) -> Optional[Signature]:
        """Steht einer dieser Fingerabdruecke in der Liste?

        SHA-256 zuerst: Bei MD5 lassen sich zwei verschiedene Dateien mit
        gleichem Wert erzeugen, bei SHA-256 nicht. Steht beides drin, soll
        der belastbarere Treffer die Begruendung liefern.
        """
        for algo in ("sha256", "sha1", "md5"):
            digest = (hashes or {}).get(algo)
            if not digest:
                continue
            treffer = self._nach_algo[algo].get(digest.lower())
            if treffer is None:
                continue
            if treffer.size >= 0 and size >= 0 and treffer.size != size:
                continue
            return treffer
        return None

    def match(self, data: bytes, size: Optional[int] = None) -> Optional[Signature]:
        """Fingerabdruck eines vollstaendigen Inhalts nachschlagen."""
        algos = self.algos
        if not algos:
            return None
        return self.match_hashes(hashes_von_bytes(data, algos),
                                 len(data) if size is None else size)

    def ist_freigegeben(self, hashes: Dict[str, str]) -> bool:
        if not self._freigegeben:
            return False
        return any(wert and wert.lower() in self._freigegeben
                   for wert in (hashes or {}).values())

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return sum(len(tabelle) for tabelle in self._nach_algo.values())

    def __contains__(self, digest: object) -> bool:
        if not isinstance(digest, str):
            return False
        digest = digest.strip().lower()
        algo = ALGO_NACH_LAENGE.get(len(digest))
        return bool(algo) and digest in self._nach_algo[algo]

    def stats(self) -> dict:
        return {
            "gesamt": len(self),
            "md5": len(self._nach_algo["md5"]),
            "sha1": len(self._nach_algo["sha1"]),
            "sha256": len(self._nach_algo["sha256"]),
            "freigegeben": len(self._freigegeben),
            "quellen": list(self.quellen),
            "aktualisiert": self.aktualisiert,
            "uebersprungen": self.uebersprungen,
        }


# ----------------------------------------------------------------------
# Aktualisieren
# ----------------------------------------------------------------------
def aktualisieren(quelle: str, ziel: str, *, timeout: float = 30.0,
                  max_bytes: int = MAX_DATEI_BYTES,
                  oeffner=None) -> Tuple[int, str]:
    """Holt eine Signaturliste und legt sie unter ``ziel`` ab.

    Rueckgabe ist ``(anzahl, meldung)``; ``anzahl`` ist 0, wenn nichts
    uebernommen wurde. Drei Dinge sind dabei wichtiger als der Komfort:

    * **Nur HTTPS.** Ueber eine ungesicherte Verbindung koennte jeder
      unterwegs bestimmen, was dieser Rechner fuer Schadsoftware haelt -
      und was nicht.
    * **Erst pruefen, dann tauschen.** Die neue Liste wird daneben
      geschrieben und gelesen. Erst wenn brauchbare Eintraege darin
      stehen, ersetzt sie die alte. Eine leere Antwort wuerde den Schutz
      sonst still abschalten.
    * **Eine Obergrenze.** Es wird nie mehr gelesen als ``max_bytes``.
    """
    if not quelle:
        return 0, "keine Quelle angegeben"

    ist_adresse = "://" in quelle
    if ist_adresse and not quelle.lower().startswith("https://"):
        return 0, ("nur https wird geholt - ueber eine ungesicherte "
                   "Verbindung koennte die Liste unterwegs geaendert werden")

    os.makedirs(os.path.dirname(os.path.abspath(ziel)) or ".", exist_ok=True)
    temp_fd, temp_pfad = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(ziel)), suffix=".neu")
    gelesen = 0
    try:
        with os.fdopen(temp_fd, "wb") as ausgabe:
            try:
                for block in _blocks(quelle, ist_adresse, timeout, oeffner):
                    gelesen += len(block)
                    if gelesen > max_bytes:
                        return 0, (f"abgebrochen: mehr als "
                                   f"{max_bytes / 1e6:.0f} MB")
                    ausgabe.write(block)
            except OSError as exc:
                return 0, f"nicht erreichbar: {exc}"
            except Exception as exc:      # urllib wirft viele Fehlerarten
                return 0, f"nicht abrufbar: {type(exc).__name__}: {exc}"

        probe = SignatureDB(mit_eicar=False)
        anzahl = probe.load_file(temp_pfad)
        if anzahl == 0:
            return 0, ("die geholte Datei enthaelt keine lesbaren Signaturen "
                       "- die bisherige Liste bleibt in Kraft")
        os.replace(temp_pfad, ziel)
        temp_pfad = ""
        try:
            os.chmod(ziel, 0o644)
        except OSError:      # pragma: no cover - plattformabhaengig
            pass
        return anzahl, f"{anzahl} Signaturen uebernommen nach {ziel}"
    finally:
        if temp_pfad and os.path.exists(temp_pfad):
            os.unlink(temp_pfad)


def _blocks(quelle: str, ist_adresse: bool, timeout: float, oeffner=None):
    """Liefert den Inhalt der Quelle in Haeppchen."""
    if oeffner is not None:
        strom = oeffner(quelle)
    elif ist_adresse:
        import urllib.request
        anfrage = urllib.request.Request(
            quelle, headers={"User-Agent": "loginshield-signaturen"})
        strom = urllib.request.urlopen(anfrage, timeout=timeout)  # noqa: S310
    else:
        strom = open(quelle, "rb")
    with strom:
        while True:
            block = strom.read(262_144)
            if not block:
                break
            yield block


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0
