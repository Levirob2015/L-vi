"""Der Waechter: neue Dateien pruefen, sobald sie da sind.

Ein Scan, den jemand von Hand startet, findet Schadsoftware erst Tage
spaeter. Der Waechter sieht in kurzen Abstaenden in die ueberwachten
Verzeichnisse und prueft, was **neu ist oder sich geaendert hat** - der
Download, der gerade fertig wurde, die Datei, die ein Angreifer eben
abgelegt hat.

Warum nachsehen statt benachrichtigen lassen
--------------------------------------------
Das Betriebssystem kann Bescheid geben, wenn sich etwas aendert (inotify
unter Linux, FSEvents auf dem Mac). Das ist schneller, aber es ist auf
jedem System anders, braucht Zusatzpakete und hat harte Obergrenzen fuer
die Zahl der ueberwachten Verzeichnisse. Dieses Projekt kommt ohne
Fremdpakete aus, also wird nachgesehen. Bei einem Abstand von wenigen
Sekunden ist der Unterschied in der Praxis klein - und diese Loesung
laeuft ueberall gleich.

Was dabei bedacht ist
---------------------
* **Halbe Dateien.** Ein Download ist beim ersten Blick oft noch nicht
  fertig. Eine Datei wird deshalb erst geprueft, wenn sie sich eine
  Weile nicht mehr veraendert hat - sonst prueft man das erste Drittel
  und meldet "sauber".
* **Kein zweites Mal.** Jede Datei wird mit Zeitstempel und Groesse
  gemerkt. Geprueft wird nur, was neu ist oder anders als zuletzt.
* **Begrenzter Speicher.** Das Verzeichnis der gemerkten Dateien waechst
  mit fremden Daten - also hat es eine Obergrenze und wird aufgeraeumt.
* **Nie loeschen.** Ein Fund wandert in die Quarantaene oder wird nur
  gemeldet. Ein Fehlalarm darf keine Urlaubsfotos vernichten.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .config import RealtimeConfig
from .models import sauber

log = logging.getLogger("loginshield.realtime")


@dataclass
class WatchEvent:
    """Ein Fund des Waechters."""

    path: str
    result: object = None
    action: str = "gemeldet"
    quarantine_id: str = ""

    @property
    def verdict(self) -> str:
        return getattr(self.result, "verdict", "unbekannt")

    @property
    def summary(self) -> str:
        return getattr(self.result, "summary", "")

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "action": self.action,
            "quarantine_id": self.quarantine_id,
            "result": self.result.as_dict() if hasattr(self.result, "as_dict")
            else {},
        }


@dataclass
class WatchStats:
    zyklen: int = 0
    gesehen: int = 0
    geprueft: int = 0
    funde: int = 0
    quarantaene: int = 0
    zurueckgestellt: int = 0
    letzter_lauf: float = 0.0

    def as_dict(self) -> dict:
        return {
            "zyklen": self.zyklen, "gesehen": self.gesehen,
            "geprueft": self.geprueft, "funde": self.funde,
            "quarantaene": self.quarantaene,
            "zurueckgestellt": self.zurueckgestellt,
            "letzter_lauf": self.letzter_lauf,
        }


class RealtimeGuard:
    """Sieht in Verzeichnisse und prueft, was neu hinzukommt."""

    def __init__(self, config: Optional[RealtimeConfig] = None,
                 scanner=None, quarantine=None, *,
                 on_event: Optional[Callable[[WatchEvent], None]] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.config = config or RealtimeConfig()
        self.scanner = scanner
        self.quarantine = quarantine
        self.on_event = on_event
        self.clock = clock
        self.stats = WatchStats()
        #: Pfad -> (Zeitstempel, Groesse) beim letzten Blick.
        self._bekannt: Dict[str, Tuple[float, int]] = {}
        #: Dateien, die noch wuchsen, als zuletzt hingesehen wurde.
        self._wartend: Dict[str, Tuple[float, int]] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._angelernt = False

    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled and self.config.paths)

    @property
    def paths(self) -> List[str]:
        return [p for p in self.config.paths if p]

    # ------------------------------------------------------------------
    # Ein Durchgang
    # ------------------------------------------------------------------
    def anlernen(self) -> int:
        """Merkt sich den jetzigen Bestand, ohne ihn zu pruefen.

        Der uebliche Start: Der Waechter soll auf **Neues** achten, nicht
        beim Einschalten erst einmal die ganze Festplatte durchgehen. Wer
        das doch will, setzt ``scan_existing``.
        """
        anzahl = 0
        for pfad, zustand in self._durchgehen():
            self._bekannt[pfad] = zustand
            anzahl += 1
        self._angelernt = True
        self._aufraeumen()
        log.info("Waechter angelernt: %s Dateien gemerkt", anzahl)
        return anzahl

    def poll_once(self) -> List[WatchEvent]:
        """Ein Durchgang. Liefert die Funde dieses Durchgangs."""
        if self.scanner is None:
            return []
        if not self._angelernt:
            # Beim ersten Durchgang entscheidet die Einstellung, ob der
            # vorhandene Bestand geprueft oder nur gemerkt wird.
            self._angelernt = True
            if not self.config.scan_existing:
                self.anlernen()
                return []

        jetzt = self.clock()
        self.stats.zyklen += 1
        self.stats.letzter_lauf = jetzt

        funde: List[WatchEvent] = []
        gesehen: Dict[str, Tuple[float, int]] = {}
        #: Alles, was in diesem Durchgang ueberhaupt dalag - auch das
        #: Zurueckgestellte. Nicht dasselbe wie ``gesehen``: dort steht
        #: nur, was abgehakt ist.
        vorhanden: set = set()
        geprueft = 0

        for pfad, zustand in self._durchgehen():
            vorhanden.add(pfad)
            gesehen[pfad] = zustand
            self.stats.gesehen += 1
            if self._bekannt.get(pfad) == zustand:
                continue                      # unveraendert
            if geprueft >= self.config.max_files_per_cycle:
                # Nicht als bekannt merken: beim naechsten Durchgang dran.
                gesehen.pop(pfad, None)
                continue

            if not self._ruht(pfad, zustand, jetzt):
                gesehen.pop(pfad, None)       # beim naechsten Mal erneut
                self.stats.zurueckgestellt += 1
                continue

            self._wartend.pop(pfad, None)
            geprueft += 1
            self.stats.geprueft += 1
            ereignis = self._pruefen(pfad)
            if ereignis is not None:
                funde.append(ereignis)
                if ereignis.action == "quarantaene":
                    # Die Datei liegt nicht mehr dort - nicht merken.
                    gesehen.pop(pfad, None)

        # Verschwundene Dateien vergessen. Ohne das waechst das
        # Verzeichnis mit jeder Datei, die es je gab.
        #
        # Der Merkzettel der zurueckgestellten Dateien wird gegen
        # ``vorhanden`` aufgeraeumt, nicht gegen ``gesehen``: Eine
        # zurueckgestellte Datei steht mit Absicht nicht in ``gesehen``
        # (sie soll ja noch geprueft werden). Gegen ``gesehen``
        # aufgeraeumt, waere ihr Merkzettel am Ende jedes Durchgangs weg -
        # und beim naechsten Mal gaebe es keinen Vergleichswert fuer die
        # Groesse mehr. Ein laufender Download waere dann sofort
        # "fertig", genau der Fall, den das Zurueckstellen verhindern soll.
        self._bekannt = gesehen
        self._wartend = {p: z for p, z in self._wartend.items()
                         if p in vorhanden}
        self._aufraeumen()
        return funde

    def _ruht(self, pfad: str, zustand: Tuple[float, int],
              jetzt: float) -> bool:
        """Ist die Datei fertig geschrieben?

        Zwei Bedingungen, weil eine allein nicht reicht: Der Zeitstempel
        muss alt genug sein, **und** die Groesse darf sich seit dem
        letzten Blick nicht geaendert haben. Eine langsame Leitung
        aktualisiert den Zeitstempel staendig; eine Datei, die zufaellig
        gerade nicht waechst, hat einen frischen Zeitstempel.
        """
        ruhe = self.config.settle_seconds
        if ruhe <= 0:
            return True
        mtime, groesse = zustand
        if jetzt - mtime < ruhe:
            self._wartend[pfad] = zustand
            return False
        vorher = self._wartend.get(pfad)
        if vorher is not None and vorher[1] != groesse:
            self._wartend[pfad] = zustand
            return False
        return True

    def _pruefen(self, pfad: str) -> Optional[WatchEvent]:
        """Prueft eine einzelne Datei und handelt nach der Einstellung."""
        try:
            ergebnis = self.scanner.scan_file(pfad)
        except OSError as exc:      # pragma: no cover - defensiv
            log.debug("Waechter: %s nicht pruefbar (%s)", sauber(pfad, 200), exc)
            return None
        if ergebnis.clean or not self.scanner.is_malicious(ergebnis):
            return None

        self.stats.funde += 1
        ereignis = WatchEvent(path=pfad, result=ergebnis)

        if self.config.action == "quarantine" and self.quarantine is not None:
            ziel = self.quarantine.store(pfad, ergebnis)
            if ziel:
                ereignis.action = "quarantaene"
                ereignis.quarantine_id = os.path.basename(ziel)
                self.stats.quarantaene += 1

        log.error("Waechter: %s in %s (%s)%s",
                  ergebnis.verdict, sauber(pfad, 200),
                  sauber(ergebnis.summary, 120),
                  " - in Quarantaene" if ereignis.action == "quarantaene" else "")

        if self.on_event is not None:
            try:
                self.on_event(ereignis)
            except Exception as exc:    # pragma: no cover - fremder Code
                log.warning("Waechter: Rueckmeldung fehlgeschlagen: %s", exc)
        return ereignis

    # ------------------------------------------------------------------
    def _durchgehen(self):
        """Liefert (Pfad, (Zeitstempel, Groesse)) fuer alle Dateien."""
        ueberspringen = set(self.config.skip_dirs)
        for wurzel in self.paths:
            if not os.path.isdir(wurzel):
                if os.path.isfile(wurzel):
                    zustand = _zustand(wurzel)
                    if zustand:
                        yield wurzel, zustand
                continue
            for ordner, unterordner, dateien in os.walk(wurzel):
                unterordner[:] = [
                    d for d in unterordner
                    if d not in ueberspringen
                    and not (d.startswith(".") and self.config.skip_hidden)
                ]
                for name in dateien:
                    pfad = os.path.join(ordner, name)
                    zustand = _zustand(pfad)
                    if zustand:
                        yield pfad, zustand

    def _aufraeumen(self) -> None:
        """Haelt das Verzeichnis der gemerkten Dateien in Grenzen.

        Sonst waere es eine Speicherstelle, die von aussen waechst: Wer
        eine Million Dateien anlegt, treibt den Verbrauch nach oben.
        """
        grenze = self.config.max_index
        if grenze > 0 and len(self._bekannt) > grenze:
            uebrig = sorted(self._bekannt.items(), key=lambda p: -p[1][0])
            entfernt = len(self._bekannt) - grenze
            self._bekannt = dict(uebrig[:grenze])
            log.warning(
                "Waechter: %s Eintraege vergessen, mehr als %s Dateien im "
                "Blick - die aeltesten fallen heraus", entfernt, grenze,
            )
        if grenze > 0 and len(self._wartend) > grenze:
            self._wartend.clear()

    # ------------------------------------------------------------------
    # Dauerbetrieb
    # ------------------------------------------------------------------
    def run(self, stop: Optional[threading.Event] = None) -> None:
        """Laeuft, bis angehalten wird. Blockiert."""
        halt = stop or self._stop
        halt.clear()
        if not self.config.scan_existing and not self._angelernt:
            self.anlernen()
        log.info("Waechter laeuft: %s (alle %.0fs)",
                 ", ".join(self.paths) or "-", self.config.interval)
        while not halt.is_set():
            try:
                self.poll_once()
            except Exception as exc:    # pragma: no cover - der Waechter
                # soll nicht aussteigen, nur weil eine Datei zickt.
                log.error("Waechter: Durchgang fehlgeschlagen: %s", exc)
            halt.wait(self.config.interval)

    def start(self) -> None:
        """Startet den Waechter im Hintergrund."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="loginshield-waechter",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None


def _zustand(pfad: str) -> Optional[Tuple[float, int]]:
    try:
        info = os.stat(pfad)
    except OSError:
        return None
    if not os.path.isfile(pfad):
        return None
    return (info.st_mtime, info.st_size)
