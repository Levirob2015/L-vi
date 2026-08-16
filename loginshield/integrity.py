"""Integritaetsueberwachung: bemerken, wenn sich Dateien veraendern.

Das ist die wirksamste Erkennung nach einem erfolgreichen Einbruch - und
sie kommt ohne Signaturen aus. Ein Angreifer, der es auf den Server
geschafft hat, tut fast immer eines von drei Dingen:

* er legt eine neue Datei ab (eine Webshell, ein Skript),
* er aendert eine bestehende Datei (haengt Code an eine Startdatei),
* er loescht etwas (Spuren, Protokolle).

Alle drei fallen auf, wenn man weiss, wie der Zustand vorher war. Genau das
haelt dieses Modul fest: einen Fingerabdruck (SHA-256) je Datei.

Eine **neue Skriptdatei in einem Upload-Verzeichnis** ist dabei der
deutlichste Fall - dort gehoeren Bilder hin, keine ausfuehrbaren Skripte.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .config import IntegrityConfig

log = logging.getLogger("loginshield.integrity")


@dataclass
class Change:
    """Eine festgestellte Veraenderung."""

    kind: str          # neu | geaendert | geloescht
    path: str
    severity: int = 5
    description: str = ""
    sha256: str = ""

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "path": self.path, "severity": self.severity,
            "description": self.description, "sha256": self.sha256,
        }


@dataclass
class IntegrityReport:
    changes: List[Change] = field(default_factory=list)
    checked: int = 0
    baseline_ts: float = 0.0
    error: str = ""

    @property
    def clean(self) -> bool:
        return not self.changes and not self.error

    @property
    def score(self) -> int:
        return sum(change.severity for change in self.changes)

    @property
    def verdict(self) -> str:
        if self.error:
            return "ungeprueft"
        if not self.changes:
            return "unveraendert"
        if self.score >= 9:
            return "kritisch"
        return "auffaellig"

    def as_dict(self) -> dict:
        return {
            "checked": self.checked,
            "baseline_ts": self.baseline_ts,
            "verdict": self.verdict,
            "score": self.score,
            "changes": [c.as_dict() for c in self.changes],
            "error": self.error,
        }


def hash_file(path: str, chunk: int = 262144) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(chunk)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


class IntegrityMonitor:
    """Haelt Fingerabdruecke fest und meldet Abweichungen."""

    def __init__(self, config: Optional[IntegrityConfig] = None, guard=None,
                 store=None) -> None:
        self.config = config or IntegrityConfig()
        self.guard = guard
        self._store = store

    @property
    def store(self):
        return self._store or (self.guard.store if self.guard else None)

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled) and bool(self.config.paths)

    # ------------------------------------------------------------------
    def _dateien(self, wurzeln: Sequence[str]) -> List[str]:
        gefunden: List[str] = []
        for wurzel in wurzeln:
            if os.path.isfile(wurzel):
                gefunden.append(os.path.abspath(wurzel))
                continue
            for ordner, verzeichnisse, dateien in os.walk(wurzel):
                verzeichnisse[:] = [
                    d for d in verzeichnisse if d not in self.config.skip_dirs
                ]
                for datei in dateien:
                    pfad = os.path.join(ordner, datei)
                    if len(gefunden) >= self.config.max_files:
                        log.warning(
                            "Integritaetspruefung bei %s Dateien abgebrochen - "
                            "bitte 'paths' enger fassen", self.config.max_files,
                        )
                        return gefunden
                    gefunden.append(os.path.abspath(pfad))
        return gefunden

    def learn(self, paths: Optional[Sequence[str]] = None,
              now: Optional[float] = None) -> int:
        """Haelt den aktuellen Zustand als Vergleichsgrundlage fest.

        Wichtig: nur auf einem System aufrufen, von dem man glaubt, dass es
        sauber ist. Wird nach einem Einbruch gelernt, gilt die Webshell
        anschliessend als normal.
        """
        store = self.store
        if store is None:
            raise ValueError("Kein Speicher verfuegbar")
        now = time.time() if now is None else now
        wurzeln = list(paths or self.config.paths)

        eintraege = []
        for pfad in self._dateien(wurzeln):
            digest = hash_file(pfad)
            if digest is None:
                continue
            try:
                groesse = os.path.getsize(pfad)
            except OSError:
                continue
            eintraege.append((pfad, digest, groesse, now))

        store.integrity_replace(eintraege, now)
        log.info("Integritaets-Grundlage angelegt: %s Dateien", len(eintraege))
        return len(eintraege)

    def check(self, paths: Optional[Sequence[str]] = None,
              now: Optional[float] = None) -> IntegrityReport:
        """Vergleicht den jetzigen Zustand mit der Grundlage."""
        report = IntegrityReport()
        store = self.store
        if store is None or not self.config.enabled:
            report.error = (
                "Integritaetspruefung ist abgeschaltet - in der "
                "Konfiguration 'integrity.enabled: true' setzen und unter "
                "'integrity.paths' eintragen, was ueberwacht werden soll"
            )
            return report

        bekannt = store.integrity_all()
        if not bekannt:
            report.error = ("Noch keine Vergleichsgrundlage - erst "
                            "'loginshield integrity --learn' auf einem "
                            "sauberen System")
            return report

        now = time.time() if now is None else now
        report.baseline_ts = max((eintrag["seen_ts"] for eintrag in bekannt.values()),
                                 default=0.0)

        wurzeln = list(paths or self.config.paths)
        jetzige = set(self._dateien(wurzeln))
        report.checked = len(jetzige)

        for pfad in sorted(jetzige):
            digest = hash_file(pfad)
            if digest is None:
                continue
            eintrag = bekannt.get(pfad)
            if eintrag is None:
                report.changes.append(self._neue_datei(pfad, digest, wurzeln))
            elif eintrag["sha256"] != digest:
                report.changes.append(Change(
                    "geaendert", pfad, self._schwere_geaendert(pfad),
                    "Inhalt hat sich seit der Grundlage veraendert", digest,
                ))

        for pfad in sorted(bekannt):
            if pfad not in jetzige and self._ueberwacht(pfad, wurzeln):
                report.changes.append(Change(
                    "geloescht", pfad, 6, "Datei ist verschwunden",
                ))

        return report

    def _ueberwacht(self, pfad: str, wurzeln: Sequence[str]) -> bool:
        return any(
            pfad == os.path.abspath(w) or pfad.startswith(os.path.abspath(w) + os.sep)
            for w in wurzeln
        )

    def _in_upload_verzeichnis(self, pfad: str, wurzeln: Sequence[str]) -> bool:
        """Liegt die Datei unterhalb eines Upload-Verzeichnisses?

        Geprueft werden nur die Verzeichnisnamen **unterhalb** des
        ueberwachten Pfades, und zwar vollstaendig. Eine Suche nach
        Teilzeichenketten im ganzen Pfad wuerde sonst /var/www/customer-files
        wegen "files" oder /home/tmpuser wegen "tmp" faelschlich treffen -
        oder, beim Testen, jeden Pfad unter /tmp.

        Liegt die Datei unter keiner der ueberwachten Wurzeln, wird nicht
        ersatzweise der ganze Pfad durchsucht: dann ist die Frage nicht
        beantwortbar und die Antwort lautet nein. Sonst wuerde ein
        Verzeichnisname weit oberhalb - etwa /tmp - die Bewertung anheben,
        obwohl er mit dem Webauftritt nichts zu tun hat.
        """
        namen = {name.strip().lower() for name in self.config.upload_dirs}
        if not namen:
            return False

        # Die laengste passende Wurzel gewinnt: bei /var/www und
        # /var/www/html soll unterhalb von /var/www/html auch nur der Teil
        # darunter zaehlen.
        basen = sorted(
            (os.path.abspath(w) for w in wurzeln), key=len, reverse=True,
        )
        for basis in basen:
            if pfad == basis or pfad.startswith(basis + os.sep):
                rest = pfad[len(basis):]
                teile = [t.lower() for t in rest.split(os.sep)[:-1] if t]
                return any(teil in namen for teil in teile)
        return False

    def _neue_datei(self, pfad: str, digest: str,
                    wurzeln: Sequence[str] = ()) -> Change:
        endung = os.path.splitext(pfad)[1].lower()
        # Der deutlichste Fall ueberhaupt: ein Skript dort, wo Nutzer
        # Dateien ablegen duerfen.
        if endung in self.config.script_extensions:
            if self._in_upload_verzeichnis(pfad, wurzeln):
                return Change(
                    "neu", pfad, 10,
                    f"neue Skriptdatei ({endung}) in einem Upload-Verzeichnis - "
                    f"der typische Weg einer Webshell", digest,
                )
            return Change("neu", pfad, 8,
                          f"neue Skriptdatei ({endung})", digest)
        return Change("neu", pfad, 4, "neue Datei", digest)

    def _schwere_geaendert(self, pfad: str) -> int:
        endung = os.path.splitext(pfad)[1].lower()
        return 9 if endung in self.config.script_extensions else 5

    # ------------------------------------------------------------------
    def status(self) -> dict:
        store = self.store
        if store is None:
            return {"ready": False, "reason": "kein Speicher"}
        anzahl = store.integrity_count()
        if not anzahl:
            return {
                "ready": False,
                "reason": ("Noch keine Vergleichsgrundlage "
                           "('loginshield integrity --learn')"),
                "files": 0,
            }
        return {"ready": True, "files": anzahl, "paths": list(self.config.paths)}
