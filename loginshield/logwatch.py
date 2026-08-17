"""Logdateien mitlesen und Angriffe daraus melden.

Damit schuetzt LoginShield auch Dienste, die es nicht selbst einbindet -
allen voran SSH (``/var/log/auth.log``) und Webserver-Zugriffslogs.
Logrotation wird erkannt (Inode-Wechsel bzw. schrumpfende Datei).
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence

from .config import LogSourceConfig
from .engine import Guard
from .netutils import normalize_ip

log = logging.getLogger("loginshield.logwatch")

#: Hoechstens so viel wird je Durchgang aus einer Logdatei gelesen. Nach
#: einer Rotation wuerde sonst der ganze Inhalt der neuen Datei in einem
#: Zug im Speicher landen.
MAX_BLOCK = 4 * 1024 * 1024

#: Laenger darf eine einzelne Zeile nicht sein. Zum Vergleich: nginx
#: begrenzt die Anfragezeile auf 8 KiB, sshd kuerzt Benutzernamen. Was
#: darueber liegt, ist keine Protokollzeile.
MAX_ZEILE = 64 * 1024


@dataclass
class ParsedEvent:
    ip: str
    success: bool
    identity: str = ""
    route: str = ""
    detail: str = ""
    #: "login" = normaler Anmeldeversuch, "honeypot" = Zugriff auf einen Koeder
    kind: str = "login"


# -- Muster --------------------------------------------------------------
SSHD_FAILURE = [
    re.compile(
        r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<identity>\S+) "
        r"from (?P<ip>[0-9a-fA-F:.]+)"
    ),
    re.compile(r"Invalid user (?P<identity>\S*)\s*from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(
        r"(?:error: )?maximum authentication attempts exceeded for "
        r"(?:invalid user )?(?P<identity>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
    ),
    re.compile(
        r"Connection closed by authenticating user (?P<identity>\S+) "
        r"(?P<ip>[0-9a-fA-F:.]+)"
    ),
]

SSHD_SUCCESS = [
    re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for "
        r"(?P<identity>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
    ),
]

# Common/Combined Log Format
NGINX_LINE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<identity>\S+)\s+\[[^\]]+\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<route>\S+)[^"]*"\s+(?P<status>\d{3})'
)


def parse_line(line: str, source: LogSourceConfig,
               honeypot=None) -> Optional[ParsedEvent]:
    """Wertet eine Logzeile aus. ``None`` = keine relevante Zeile.

    Mit ``honeypot`` werden Webserver-Zeilen zusaetzlich gegen die
    Koederpfade geprueft - unabhaengig vom Status. Ein Scanner, der
    ``/.env`` abruft, bekommt vom Webserver ein 404 und wuerde sonst
    durchrutschen.
    """
    line = line.rstrip("\n")
    if not line:
        return None

    if source.format == "sshd":
        return _parse_sshd(line)
    if source.format == "nginx":
        return _parse_nginx(line, source, honeypot)
    return _parse_custom(line, source)


def _parse_sshd(line: str) -> Optional[ParsedEvent]:
    for pattern in SSHD_SUCCESS:
        match = pattern.search(line)
        if match:
            ip = normalize_ip(match.group("ip"))
            if ip:
                return ParsedEvent(ip, True, match.group("identity"), "ssh")
    for pattern in SSHD_FAILURE:
        match = pattern.search(line)
        if match:
            ip = normalize_ip(match.group("ip"))
            if ip:
                identity = (match.groupdict().get("identity") or "").strip()
                return ParsedEvent(ip, False, identity, "ssh", detail="sshd")
    return None


def _parse_nginx(line: str, source: LogSourceConfig,
                 honeypot=None) -> Optional[ParsedEvent]:
    match = NGINX_LINE.match(line)
    if not match:
        return None
    ip = normalize_ip(match.group("ip"))
    if not ip:
        return None
    route = match.group("route")
    status = int(match.group("status"))

    # Koederpfad geht vor: hier zaehlt der Aufruf, nicht der Status.
    if honeypot is not None and honeypot.enabled:
        trap = honeypot.match(route)
        if trap is not None:
            return ParsedEvent(ip, False, "", route, detail=trap.kind, kind="honeypot")

    if source.path_filter and not route.startswith(source.path_filter):
        return None
    identity = match.group("identity")
    if identity == "-":
        identity = ""
    if status in set(source.failure_statuses):
        return ParsedEvent(ip, False, identity, route, detail=f"HTTP {status}")
    if 200 <= status < 300 and source.path_filter:
        # Nur bei gesetztem Pfadfilter ist ein 200 wirklich ein Login-Erfolg.
        return ParsedEvent(ip, True, identity, route, detail=f"HTTP {status}")
    return None


def _parse_custom(line: str, source: LogSourceConfig) -> Optional[ParsedEvent]:
    if source.success_pattern:
        match = re.search(source.success_pattern, line)
        if match:
            ip = normalize_ip(match.groupdict().get("ip"))
            if ip:
                return ParsedEvent(ip, True, match.groupdict().get("identity") or "")
    match = re.search(source.pattern, line)
    if not match:
        return None
    ip = normalize_ip(match.groupdict().get("ip"))
    if not ip:
        return None
    return ParsedEvent(ip, False, match.groupdict().get("identity") or "", detail="custom")


# -- Datei mitlesen ------------------------------------------------------
class Tailer:
    """Liest neue Zeilen einer Datei, robust gegen Logrotation."""

    def __init__(self, path: str, *, from_start: bool = False) -> None:
        self.path = path
        self.from_start = from_start
        self._handle = None
        self._inode: Optional[int] = None
        self._buffer = ""
        #: True, solange eine zu lange Zeile noch nicht zu Ende ist.
        self._ueberlang = False

    def _open(self) -> bool:
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return False
        stat = os.fstat(handle.fileno())
        if not self.from_start and self._handle is None:
            handle.seek(0, os.SEEK_END)  # beim ersten Oeffnen nur Neues lesen
        self._close()
        self._handle = handle
        self._inode = stat.st_ino
        self._buffer = ""
        self._ueberlang = False
        return True

    def _close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:  # pragma: no cover
                pass
            self._handle = None

    def _rotated(self) -> bool:
        if self._handle is None:
            return True
        try:
            on_disk = os.stat(self.path)
        except OSError:
            return False  # Datei kurzzeitig weg - beim naechsten Mal erneut pruefen
        if on_disk.st_ino != self._inode:
            return True
        return on_disk.st_size < self._handle.tell()

    def read_new(self) -> List[str]:
        if self._handle is None or self._rotated():
            was_first = self._handle is None
            if not self._open():
                return []
            if not was_first:
                log.info("Logrotation erkannt: %s", self.path)

        lines: List[str] = []
        # Hoechstens ein Block je Durchgang. Ohne diese Grenze wuerde nach
        # einer Logrotation der ganze Inhalt der neuen Datei in einem Zug
        # in den Speicher gelesen - bei einer grossen Datei bis zum
        # Stillstand des Rechners. Der Rest kommt beim naechsten Durchgang,
        # zwei Sekunden spaeter.
        chunk = self._handle.read(MAX_BLOCK)
        if not chunk:
            return lines
        self._buffer += chunk
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if self._ueberlang:
                # Wir haben den Anfang dieser Zeile bereits verworfen -
                # jetzt ist sie zu Ende, es geht normal weiter.
                self._ueberlang = False
                continue
            if len(line) > MAX_ZEILE:
                # Auch eine *vollstaendige* Zeile kann jedes Mass
                # ueberschreiten, wenn sie ganz in einen Block passt. Sonst
                # bekaeme die Auswertung eine 4 MB lange "Zeile" vorgesetzt.
                self._zu_lang_melden()
                continue
            lines.append(line)

        # Eine Zeile ohne Ende: Wenn sie jedes Mass ueberschreitet, ist sie
        # keine Protokollzeile mehr. Sie wird verworfen, statt den Speicher
        # zu fuellen, bis irgendwann ein Zeilenumbruch kommt.
        if len(self._buffer) > MAX_ZEILE:
            # Eine Zeile ohne Ende: Sie wird verworfen, statt den Speicher
            # zu fuellen, bis irgendwann ein Zeilenumbruch kommt.
            self._zu_lang_melden()
            self._ueberlang = True
            self._buffer = ""
        return lines

    def _zu_lang_melden(self) -> None:
        """Warnt genau einmal je ueberlanger Zeile, nicht bei jedem Block."""
        if self._ueberlang:
            return
        log.warning(
            "Zeile in %s laenger als %s Zeichen - sie wird uebersprungen. "
            "Ist das wirklich eine Logdatei?", self.path, MAX_ZEILE,
        )

    def close(self) -> None:
        self._close()


class LogWatcher:
    """Verbindet mehrere Logquellen mit dem :class:`Guard`."""

    def __init__(self, guard: Guard, sources: Sequence[LogSourceConfig], *,
                 from_start: bool = False, honeypot=None) -> None:
        self.guard = guard
        self.sources = list(sources)
        #: None = der Honeypot des Guards, False = abgeschaltet.
        self.honeypot = guard.honeypot if honeypot is None else (honeypot or None)
        self._tailers: Dict[str, Tailer] = {
            source.path: Tailer(source.path, from_start=from_start)
            for source in self.sources
        }
        self._stop = threading.Event()

    def poll_once(self) -> int:
        """Einmal alle Quellen lesen. Gibt die Zahl gemeldeter Ereignisse zurueck."""
        handled = 0
        for source in self.sources:
            tailer = self._tailers[source.path]
            for line in tailer.read_new():
                event = parse_line(line, source, self.honeypot)
                if event is None:
                    continue
                handled += 1
                if event.kind == "honeypot":
                    self.guard.record_honeypot(
                        event.ip,
                        route=event.route,
                        source=source.format,
                        detail=event.detail,
                    )
                elif event.success:
                    self.guard.record_success(
                        event.ip,
                        identity=event.identity or None,
                        route=event.route,
                        source=source.format,
                    )
                else:
                    self.guard.record_failure(
                        event.ip,
                        identity=event.identity or None,
                        route=event.route,
                        source=source.format,
                        detail=event.detail,
                    )
        return handled

    def run(self, interval: float = 2.0, maintenance_interval: float = 300.0) -> None:
        """Dauerschleife. Bricht bei ``stop()`` oder KeyboardInterrupt ab."""
        last_maintenance = time.time()
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # pragma: no cover - Watcher darf nie sterben
                log.exception("Fehler beim Lesen der Logs")
            now = time.time()
            if now - last_maintenance >= maintenance_interval:
                last_maintenance = now
                try:
                    self.guard.maintenance()
                except Exception:  # pragma: no cover
                    log.exception("Fehler bei der Wartung")
            self._stop.wait(interval)

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        for tailer in self._tailers.values():
            tailer.close()

    def missing_sources(self) -> Iterator[str]:
        for source in self.sources:
            if not os.path.exists(source.path):
                yield source.path
