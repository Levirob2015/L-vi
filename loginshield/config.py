"""Konfiguration von LoginShield.

Quelle ist eine YAML- oder JSON-Datei (YAML nur, wenn PyYAML installiert ist).
Einzelne Werte lassen sich per Umgebungsvariable ueberschreiben - praktisch,
um Geheimnisse aus der Datei herauszuhalten:

    LOGINSHIELD_DB          Pfad zur SQLite-Datei
    LOGINSHIELD_TOKEN       Dashboard-Token
    LOGINSHIELD_HMAC_KEY    Schluessel zum Hashen von Benutzernamen
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_NAMES = (
    "loginshield.yaml",
    "loginshield.yml",
    "loginshield.json",
)

DEFAULT_DB_PATH = "loginshield.db"


class ConfigError(ValueError):
    """Fehlerhafte Konfiguration."""


@dataclass
class RuleConfig:
    """Schwellwerte der Erkennung. Alle Zeiten in Sekunden."""

    #: Fehlversuche einer IP im Fenster, bevor gesperrt wird.
    ip_failure_threshold: int = 5
    ip_failure_window: int = 300

    #: Fehlversuche gegen EIN Konto (ueber beliebig viele IPs).
    identity_failure_threshold: int = 10
    identity_failure_window: int = 900
    #: "throttle" bremst nur, "lock" sperrt das Konto bis zum Fensterende.
    #: Achtung: "lock" ist ein DoS-Vektor - Fremde koennen ein Konto absichtlich
    #: aussperren. Default ist deshalb bewusst "throttle".
    identity_action: str = "throttle"
    identity_throttle_seconds: int = 30

    #: Password-Spraying: eine IP probiert viele verschiedene Konten.
    spray_identity_threshold: int = 5
    spray_window: int = 600

    #: Allgemeines Rate-Limit pro IP ueber alle Requests.
    request_limit: int = 60
    request_window: int = 60
    #: Wie oft das Rate-Limit reissen darf, bevor die IP gesperrt wird.
    #: 0 = nie sperren, nur ausbremsen.
    rate_limit_strikes: int = 20

    #: Netzsperre: Weicht ein Angreifer nach der Sperre auf die Nachbar-IP
    #: aus, wird das ganze Netz gesperrt. Greift erst, wenn so viele
    #: verschiedene IPs aus demselben Block gesperrt werden mussten.
    subnet_enabled: bool = True
    subnet_threshold: int = 4
    subnet_window: int = 3600
    subnet_prefix_v4: int = 24
    subnet_prefix_v6: int = 64
    subnet_block_seconds: int = 21600  # 6 Stunden

    #: Sperrdauer: base * factor**(fruehere Sperren), gedeckelt auf max.
    block_base_seconds: int = 900
    block_max_seconds: int = 86400
    block_escalation_factor: float = 2.0
    #: Wie lange fruehere Sperren fuer die Eskalation mitzaehlen.
    strike_memory: int = 604800  # 7 Tage

    def validate(self) -> None:
        for name in (
            "ip_failure_threshold",
            "ip_failure_window",
            "identity_failure_threshold",
            "identity_failure_window",
            "spray_identity_threshold",
            "spray_window",
            "request_limit",
            "request_window",
            "block_base_seconds",
            "block_max_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ConfigError(f"rules.{name} muss groesser als 0 sein")
        if self.block_max_seconds < self.block_base_seconds:
            raise ConfigError("rules.block_max_seconds < rules.block_base_seconds")
        if self.block_escalation_factor < 1:
            raise ConfigError("rules.block_escalation_factor muss >= 1 sein")
        if self.identity_action not in ("throttle", "lock", "off"):
            raise ConfigError("rules.identity_action muss throttle, lock oder off sein")
        if self.subnet_threshold < 2:
            raise ConfigError(
                "rules.subnet_threshold muss mindestens 2 sein - bei 1 wuerde "
                "schon eine einzelne IP ein ganzes Netz sperren"
            )
        if not 8 <= self.subnet_prefix_v4 <= 32:
            raise ConfigError("rules.subnet_prefix_v4 muss zwischen 8 und 32 liegen")
        if not 16 <= self.subnet_prefix_v6 <= 128:
            raise ConfigError("rules.subnet_prefix_v6 muss zwischen 16 und 128 liegen")
        if self.subnet_window <= 0 or self.subnet_block_seconds <= 0:
            raise ConfigError("rules.subnet_window/-block_seconds muessen > 0 sein")


@dataclass
class DashboardConfig:
    """Web-Oberflaeche."""

    host: str = "127.0.0.1"
    port: int = 8787
    #: Pflicht, sobald nicht nur auf localhost gelauscht wird.
    token: str = ""
    refresh_seconds: int = 10
    #: Sperren/Entsperren ueber das Dashboard erlauben.
    allow_mutations: bool = True

    def validate(self) -> None:
        # 0 bedeutet: einen freien Port vom Betriebssystem waehlen lassen.
        if not (0 <= self.port < 65536):
            raise ConfigError("dashboard.port ausserhalb des gueltigen Bereichs")
        if self.host not in ("127.0.0.1", "::1", "localhost") and not self.token:
            raise ConfigError(
                "dashboard.token ist Pflicht, wenn das Dashboard nicht nur auf "
                "localhost lauscht (sonst kann jeder Sperren aufheben)"
            )


@dataclass
class FirewallConfig:
    """Optionale Anbindung an die System-Firewall.

    Standardmaessig aus: ohne Firewall gilt die Sperre nur in der Anwendung,
    mit Firewall auf Netzwerkebene fuer alle Dienste.
    """

    enabled: bool = False
    #: auto | nftables | iptables | ufw | command | none.
    #: Auch eine Liste ist erlaubt - dann werden mehrere Firewalls
    #: gleichzeitig bespielt: ["nftables", "iptables"].
    backend: Any = "auto"
    #: Nach jeder Sperre nachsehen, ob sie wirklich angekommen ist. Kostet
    #: einen zusaetzlichen Aufruf, deckt aber Kommandos auf, die Erfolg
    #: melden ohne zu wirken.
    verify: bool = False
    #: Nur die Kommandos anzeigen, nichts ausfuehren. Zum gefahrlosen Testen.
    dry_run: bool = False
    #: Kommandos mit 'sudo -n' ausfuehren (nie interaktiv nachfragen).
    sudo: bool = False
    #: Beim Start die aktiven Sperren in die Firewall schreiben. Nach einem
    #: Neustart sind die Regeln weg, die Sperren aber noch gueltig.
    sync_on_start: bool = True
    #: Name der eigenen nft-Tabelle bzw. der iptables-Kette.
    table: str = "loginshield"
    #: Nur fuer backend=command. ``{ip}`` und ``{seconds}`` werden ersetzt.
    block_command: List[str] = field(default_factory=list)
    unblock_command: List[str] = field(default_factory=list)
    timeout: int = 10

    # -- Verbindungsbremse ---------------------------------------------
    #: Neue Verbindungen je Absender-IP schon im Netzwerk begrenzen.
    #:
    #: Das ist die eine Sache, die die Anwendung selbst nicht kann: Wer
    #: 10.000 Verbindungen pro Sekunde aufmacht, hat den Server schon
    #: beschaeftigt, bevor auch nur eine Zeile Python laeuft. Diese Bremse
    #: greift davor - im Kern des Betriebssystems.
    #:
    #: Bewusst abgeschaltet voreingestellt: Der Wert muss zum eigenen
    #: Verkehr passen. Zu niedrig, und echte Besucher fliegen raus.
    #: Erst mit 'loginshield firewall --limit-probe' ansehen, was der
    #: normale Betrieb braucht.
    conn_limit_enabled: bool = False
    #: Auf welchen Ports (leer = alle TCP-Ports).
    conn_limit_ports: List[int] = field(default_factory=lambda: [80, 443])
    #: Erlaubte neue Verbindungen je IP und Minute.
    conn_limit_rate: int = 120
    #: Wie viele auf einen Schlag durchgehen duerfen. Ein normaler
    #: Seitenaufruf oeffnet mehrere Verbindungen gleichzeitig - ohne
    #: Spielraum wuerde die Startseite selbst zum Fund.
    conn_limit_burst: int = 40
    #: Die Allowlist auch in die Firewall schreiben. Damit kann die
    #: Verbindungsbremse das eigene Buero nicht aussperren.
    sync_allowlist: bool = True

    @property
    def backends(self) -> List[str]:
        """Die Backend-Namen als Liste, egal wie sie angegeben wurden."""
        if isinstance(self.backend, (list, tuple)):
            return [str(name).strip() for name in self.backend if str(name).strip()]
        return [str(self.backend).strip()]

    def validate(self) -> None:
        known = ("auto", "nftables", "iptables", "ufw", "command", "none")
        namen = self.backends
        if not namen:
            raise ConfigError("firewall.backend darf nicht leer sein")
        for name in namen:
            if name not in known:
                raise ConfigError(
                    "firewall.backend muss eines von " + ", ".join(known)
                    + f" sein (bekam {name!r})"
                )
        if len(namen) > 1 and "auto" in namen:
            raise ConfigError(
                "firewall.backend: 'auto' laesst sich nicht mit anderen "
                "Backends kombinieren - nenne sie einzeln"
            )
        if self.enabled and "command" in namen and not self.block_command:
            raise ConfigError(
                "firewall.backend=command gesetzt, aber kein block_command"
            )
        if self.timeout <= 0:
            raise ConfigError("firewall.timeout muss groesser als 0 sein")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,28}", self.table):
            # Der Name landet in Firewall-Kommandos - nur harmlose Zeichen.
            raise ConfigError(
                "firewall.table darf nur Buchstaben, Ziffern und _ enthalten"
            )
        if self.conn_limit_rate < 1:
            raise ConfigError("firewall.conn_limit_rate muss mindestens 1 sein")
        if self.conn_limit_burst < 1:
            raise ConfigError("firewall.conn_limit_burst muss mindestens 1 sein")
        for port in self.conn_limit_ports:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ConfigError(
                    f"firewall.conn_limit_ports: {port!r} ist kein Port"
                )
        if len(self.conn_limit_ports) > 15:
            # multiport in iptables nimmt hoechstens 15 Ports.
            raise ConfigError(
                "firewall.conn_limit_ports: hoechstens 15 Ports - fuer mehr "
                "die Liste leer lassen (gilt dann fuer alle Ports)"
            )
        if self.conn_limit_enabled and not self.enabled:
            raise ConfigError(
                "firewall.conn_limit_enabled braucht firewall.enabled = true"
            )


@dataclass
class RequestFilterConfig:
    """Die zweite Firewall: filtert Anfragen nach Inhalt.

    Falschmeldungen sind hier gefaehrlicher als Luecken - wer zu scharf
    filtert, sperrt echte Nutzer aus. Deshalb wird nicht bei jedem Treffer
    gesperrt, sondern erst ab einer Summe aus Regelschweren.
    """

    enabled: bool = True
    #: block = sperren, log = nur mitschreiben (zum gefahrlosen Einfahren)
    action: str = "block"
    #: Ab dieser Punktsumme wird gesperrt. Eine einzelne schwache Regel
    #: (Schwere 4-5) reicht damit nie aus.
    block_score: int = 8
    block_seconds: int = 21600  # 6 Stunden
    max_url_length: int = 2000
    #: Auch den Anfragekoerper pruefen. Ohne das bleibt eine SQL-Injection
    #: aus einem Formular unsichtbar.
    inspect_body: bool = True
    #: So viele Bytes des Koerpers werden geprueft.
    max_body_bytes: int = 65536
    #: Wie oft Prozentkodierung aufgeloest wird (%252e versteckt %2e).
    decode_rounds: int = 2
    #: Eigene Routen, die von der Pruefung ausgenommen sind.
    exempt_paths: List[str] = field(default_factory=list)
    #: Namen eingebauter Regeln, die nicht greifen sollen.
    disabled_rules: List[str] = field(default_factory=list)
    #: Eigene Regeln: {name, pattern, severity, target, description}
    extra_rules: List[dict] = field(default_factory=list)
    #: True = eingebaute Regeln komplett ersetzen statt ergaenzen.
    replace_default_rules: bool = False

    def validate(self) -> None:
        if self.action not in ("block", "log"):
            raise ConfigError("requestfilter.action muss block oder log sein")
        if self.block_score < 1:
            raise ConfigError("requestfilter.block_score muss mindestens 1 sein")
        if self.block_seconds <= 0:
            raise ConfigError("requestfilter.block_seconds muss groesser als 0 sein")
        if self.max_url_length < 100:
            raise ConfigError("requestfilter.max_url_length ist unrealistisch klein")
        if self.max_body_bytes < 1024:
            raise ConfigError("requestfilter.max_body_bytes ist unrealistisch klein")
        for raw in self.extra_rules:
            if not isinstance(raw, dict) or not raw.get("pattern"):
                raise ConfigError("requestfilter.extra_rules: 'pattern' fehlt")
            try:
                re.compile(str(raw["pattern"]))
            except re.error as exc:
                raise ConfigError(
                    f"requestfilter.extra_rules: ungueltiger Ausdruck "
                    f"{raw.get('name', '?')}: {exc}"
                ) from exc


@dataclass
class MalwareConfig:
    """Dateipruefung: Webshells und getarnte Dateien finden.

    Es wird kein eigener Virenscanner gebaut - siehe
    :mod:`loginshield.filescan`. Ist ClamAV installiert, wird es genutzt.
    """

    enabled: bool = True
    #: report = nur melden, quarantine = zusaetzlich beiseitelegen
    action: str = "report"
    quarantine_dir: str = "quarantine"
    #: Ab dieser Punktsumme gilt eine Datei als schadhaft.
    block_score: int = 8
    #: So viele Bytes je Datei werden geprueft (Anfang reicht).
    max_scan_bytes: int = 1_048_576
    #: Groessere Dateien werden uebersprungen statt eingelesen.
    max_file_bytes: int = 104_857_600
    #: auto = nutzen, wenn vorhanden | on = erwarten | off = nie
    clamav: str = "auto"
    timeout: int = 30
    #: Hochgeladene Dateien schon in der Middleware pruefen - bevor die
    #: Anwendung sie zu Gesicht bekommt und irgendwo ablegt. Eine Webshell,
    #: die nie auf der Platte landet, muss auch nicht gefunden werden.
    scan_uploads: bool = True
    #: So viel einer hochgeladenen Datei wird dabei angesehen. Webshells
    #: sind klein; fuer die Erkennung reicht der Anfang.
    max_upload_bytes: int = 262_144
    #: In ZIP-Archive hineinsehen. Ein Archiv ist sonst ein blinder Fleck:
    #: die Webshell darin faellt erst nach dem Auspacken auf.
    inspect_archives: bool = True
    #: Obergrenzen gegen "Zip-Bomben" - ein kleines Archiv kann sich zu
    #: vielen Gigabyte entpacken.
    max_archive_entries: int = 256
    max_archive_bytes: int = 33_554_432
    disabled_rules: List[str] = field(default_factory=list)
    script_extensions: List[str] = field(default_factory=lambda: [
        ".php", ".phtml", ".php3", ".php4", ".php5", ".phar",
        ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh", ".exe",
    ])
    skip_dirs: List[str] = field(default_factory=lambda: [
        ".git", "node_modules", "__pycache__", "venv", ".venv", "vendor",
    ])

    def validate(self) -> None:
        if self.action not in ("report", "quarantine"):
            raise ConfigError("malware.action muss report oder quarantine sein")
        if self.clamav not in ("auto", "on", "off"):
            raise ConfigError("malware.clamav muss auto, on oder off sein")
        if self.block_score < 1:
            raise ConfigError("malware.block_score muss mindestens 1 sein")
        if self.max_scan_bytes < 1024:
            raise ConfigError("malware.max_scan_bytes ist unrealistisch klein")
        if self.timeout <= 0:
            raise ConfigError("malware.timeout muss groesser als 0 sein")
        if self.max_archive_entries < 1:
            raise ConfigError("malware.max_archive_entries muss mindestens 1 sein")
        if self.max_archive_bytes < 1024:
            raise ConfigError("malware.max_archive_bytes ist unrealistisch klein")


@dataclass
class IntegrityConfig:
    """Ueberwachung von Dateiveraenderungen."""

    enabled: bool = False
    #: Welche Verzeichnisse ueberwacht werden. Leer = abgeschaltet.
    paths: List[str] = field(default_factory=list)
    #: Teile eines Pfades, die auf ein Upload-Verzeichnis hindeuten.
    upload_dirs: List[str] = field(default_factory=lambda: [
        "upload", "uploads", "media", "files", "attachments", "tmp",
    ])
    script_extensions: List[str] = field(default_factory=lambda: [
        ".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx",
        ".cgi", ".pl", ".py", ".sh", ".exe",
    ])
    skip_dirs: List[str] = field(default_factory=lambda: [
        ".git", "node_modules", "__pycache__", "venv", ".venv", "cache",
    ])
    #: Obergrenze, damit ein zu weit gefasster Pfad nicht den Server bindet.
    max_files: int = 50_000

    def validate(self) -> None:
        if self.enabled and not self.paths:
            raise ConfigError(
                "integrity.enabled gesetzt, aber keine 'paths' angegeben"
            )
        if self.max_files < 1:
            raise ConfigError("integrity.max_files muss groesser als 0 sein")


@dataclass
class AnomalyConfig:
    """Anomalie-Erkennung: lernt den Normalzustand, meldet Abweichungen.

    Standardmaessig wird nur gemeldet, nicht gesperrt. Eine statistische
    Abweichung ist ein Verdacht, kein Beweis - ein Werbeschub sieht einem
    Angriff zunaechst aehnlich.
    """

    enabled: bool = True
    #: report = nur vermerken, block = ab block_score auch sperren
    action: str = "report"
    #: Aus wie vielen Tagen der Normalzustand gelernt wird.
    learn_days: float = 7.0
    #: Zeitfenster, das bei einer Pruefung betrachtet wird.
    window: float = 3600.0
    #: Ab diesem Punktwert taucht eine Adresse im Bericht auf.
    report_score: int = 40
    #: Ab diesem Punktwert wird gesperrt (nur bei action: block).
    block_score: int = 70
    block_seconds: int = 3600
    #: Wie oft im laufenden Betrieb geprueft wird (0 = nur auf Zuruf).
    evaluate_interval: float = 300.0
    #: Wie oft der Normalzustand neu gelernt wird. Ohne das veraltet die
    #: Grundlinie, sobald sich die Seite aendert. 0 = nie automatisch.
    relearn_hours: float = 24.0
    #: Wie lange ein Pruefergebnis wiederverwendet wird. Das Dashboard
    #: aktualisiert alle 10s - ohne Zwischenspeicher waere das auf einem
    #: belebten Server dauerhafte Rechenlast.
    cache_seconds: float = 60.0
    #: Unterhalb dieser Datenmenge wird gar nicht geurteilt - lieber gar
    #: keine Aussage als eine geratene.
    min_events: int = 200
    min_addresses: int = 20
    #: So viele Ereignisse braucht eine Adresse fuer ein volles Urteil.
    #: Darunter wird der Punktwert anteilig gedaempft - drei Zugriffe
    #: reichen nicht fuer "kritisch", egal wie ungewoehnlich sie sind.
    min_evidence: int = 15
    #: Gewichtung der Einzelsignale (Punkte-Obergrenze je Signal).
    weights: dict = field(default_factory=lambda: {
        "volumen": 25, "pfadvielfalt": 25, "neue_pfade": 20,
        "fehlerquote": 20, "kontenvielfalt": 20, "kennung": 10,
        "uhrzeit": 10, "takt": 15, "regelmaessigkeit": 20,
        "pfadstreuung": 15,
    })

    def validate(self) -> None:
        if self.action not in ("report", "block"):
            raise ConfigError("anomaly.action muss report oder block sein")
        if self.learn_days <= 0:
            raise ConfigError("anomaly.learn_days muss groesser als 0 sein")
        if self.window <= 0:
            raise ConfigError("anomaly.window muss groesser als 0 sein")
        if not 1 <= self.report_score <= 100:
            raise ConfigError("anomaly.report_score muss zwischen 1 und 100 liegen")
        if not 1 <= self.block_score <= 100:
            raise ConfigError("anomaly.block_score muss zwischen 1 und 100 liegen")
        if self.block_score < self.report_score:
            raise ConfigError("anomaly.block_score darf nicht unter report_score liegen")
        if self.min_events < 1 or self.min_addresses < 1:
            raise ConfigError("anomaly.min_events/min_addresses muessen > 0 sein")
        if self.min_evidence < 1:
            raise ConfigError("anomaly.min_evidence muss mindestens 1 sein")
        if self.evaluate_interval < 0 or self.relearn_hours < 0:
            raise ConfigError(
                "anomaly.evaluate_interval/relearn_hours duerfen nicht negativ sein"
            )


@dataclass
class HoneypotConfig:
    """Die Falle: vorgetaeuschte Schwachstellen.

    Wer diese Pfade aufruft, sucht gezielt nach Luecken - dafuer gibt es
    keinen harmlosen Grund. Deshalb reicht ein einziger Treffer fuer eine
    Sperre, ohne Schwellwert.
    """

    enabled: bool = True
    #: Sperrdauer nach einem Treffer. Deutlich laenger als bei Fehlversuchen,
    #: weil hier kein Vertipper moeglich ist.
    block_seconds: int = 86400
    #: Leer = eingebaute Liste (siehe honeypot.DEFAULT_TRAPS).
    paths: List[str] = field(default_factory=list)
    #: Zusaetzliche eigene Koeder, z.B. ["/api/v1/debug*"].
    extra_paths: List[str] = field(default_factory=list)
    #: Pfade, die trotz Trefferliste harmlos bleiben sollen.
    exclude_paths: List[str] = field(default_factory=list)
    #: Antwort kuenstlich verzoegern, um Scanner auszubremsen (0 = aus).
    tarpit_seconds: float = 0.0
    #: Name des unsichtbaren Formularfelds. Menschen sehen es nicht,
    #: Bots fuellen es aus.
    hidden_field: str = "website"
    #: Untergeschobene Zugangsdaten. Wer sie benutzt, hat sie aus einer
    #: Koederdatei - ein Beweis, kein Zufall.
    decoy_user: str = "svc_backup"
    #: Leer = stabil aus dem Schluessel abgeleitet.
    decoy_password: str = ""

    def validate(self) -> None:
        if self.block_seconds <= 0:
            raise ConfigError("honeypot.block_seconds muss groesser als 0 sein")
        if self.tarpit_seconds < 0 or self.tarpit_seconds > 30:
            raise ConfigError("honeypot.tarpit_seconds muss zwischen 0 und 30 liegen")
        if not self.decoy_user:
            raise ConfigError("honeypot.decoy_user darf nicht leer sein")


@dataclass
class LogSourceConfig:
    """Eine zu ueberwachende Logdatei."""

    path: str
    #: sshd | nginx | custom
    format: str = "sshd"
    #: Nur fuer format=custom: Regex mit den Gruppen (?P<ip>) und optional
    #: (?P<identity>). Treffer gelten als Fehlversuch.
    pattern: str = ""
    success_pattern: str = ""
    #: HTTP-Status, die bei format=nginx als Fehlversuch zaehlen.
    failure_statuses: List[int] = field(default_factory=lambda: [401, 403])
    #: Nur Zeilen mit passendem Pfad auswerten (leer = alle).
    path_filter: str = ""

    def validate(self) -> None:
        if not self.path:
            raise ConfigError("logwatch: 'path' fehlt")
        if self.format not in ("sshd", "nginx", "custom"):
            raise ConfigError(f"logwatch: unbekanntes Format {self.format!r}")
        if self.format == "custom" and not self.pattern:
            raise ConfigError("logwatch: format=custom braucht 'pattern'")


@dataclass
class Config:
    db_path: str = DEFAULT_DB_PATH
    #: IPs/CIDRs, die nie gesperrt werden (Buero, VPN, Monitoring).
    allowlist: List[str] = field(default_factory=list)
    #: Nur diesen Proxys wird X-Forwarded-For geglaubt.
    trusted_proxies: List[str] = field(default_factory=list)
    #: hashed | plain | none - wie Benutzernamen gespeichert werden.
    identity_mode: str = "hashed"
    identity_hmac_key: str = ""
    #: Aufbewahrungsdauer der Ereignisse in Tagen.
    retention_days: int = 30
    rules: RuleConfig = field(default_factory=RuleConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    requestfilter: RequestFilterConfig = field(default_factory=RequestFilterConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    malware: MalwareConfig = field(default_factory=MalwareConfig)
    integrity: IntegrityConfig = field(default_factory=IntegrityConfig)
    logwatch: List[LogSourceConfig] = field(default_factory=list)

    def validate(self) -> "Config":
        if self.identity_mode not in ("hashed", "plain", "none"):
            raise ConfigError("identity_mode muss hashed, plain oder none sein")
        if self.retention_days <= 0:
            raise ConfigError("retention_days muss groesser als 0 sein")
        self.rules.validate()
        self.dashboard.validate()
        self.firewall.validate()
        self.honeypot.validate()
        self.requestfilter.validate()
        self.anomaly.validate()
        self.malware.validate()
        self.integrity.validate()
        for source in self.logwatch:
            source.validate()
        return self

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Config":
        data = dict(data or {})
        kwargs: Dict[str, Any] = {}

        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(
                "Unbekannte Konfigurationsfelder: " + ", ".join(sorted(unknown))
            )

        for name, sub_cls in (
            ("rules", RuleConfig),
            ("dashboard", DashboardConfig),
            ("firewall", FirewallConfig),
            ("honeypot", HoneypotConfig),
            ("requestfilter", RequestFilterConfig),
            ("anomaly", AnomalyConfig),
            ("malware", MalwareConfig),
            ("integrity", IntegrityConfig),
        ):
            if name in data:
                kwargs[name] = _build(sub_cls, data.pop(name), name)

        if "logwatch" in data:
            raw_sources = data.pop("logwatch") or []
            if not isinstance(raw_sources, list):
                raise ConfigError("logwatch muss eine Liste sein")
            kwargs["logwatch"] = [
                _build(LogSourceConfig, item, "logwatch") for item in raw_sources
            ]

        for key, value in data.items():
            kwargs[key] = value

        try:
            config = cls(**kwargs)
        except TypeError as exc:  # pragma: no cover - defensiv
            raise ConfigError(str(exc)) from exc
        return config.apply_env().validate()

    def apply_env(self, env: Optional[Dict[str, str]] = None) -> "Config":
        env = os.environ if env is None else env
        if env.get("LOGINSHIELD_DB"):
            self.db_path = env["LOGINSHIELD_DB"]
        if env.get("LOGINSHIELD_TOKEN"):
            self.dashboard.token = env["LOGINSHIELD_TOKEN"]
        if env.get("LOGINSHIELD_HMAC_KEY"):
            self.identity_hmac_key = env["LOGINSHIELD_HMAC_KEY"]
        return self


def _build(cls, data: Any, label: str):
    if data is None:
        return cls() if label != "logwatch" else cls(path="")
    if is_dataclass(data):
        return data
    if not isinstance(data, dict):
        raise ConfigError(f"{label} muss ein Objekt sein")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"Unbekannte Felder in {label}: " + ", ".join(sorted(unknown)))
    try:
        return cls(**data)
    except TypeError as exc:
        raise ConfigError(f"{label}: {exc}") from exc


def find_config(start: Optional[str] = None) -> Optional[str]:
    """Sucht eine Konfigurationsdatei im angegebenen Verzeichnis."""
    base = start or os.getcwd()
    for name in DEFAULT_CONFIG_NAMES:
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_config(path: Optional[str] = None) -> Config:
    """Laedt die Konfiguration. Ohne Datei gelten die Defaults."""
    if path is None:
        path = find_config()
    if path is None:
        return Config().apply_env().validate()
    if not os.path.isfile(path):
        raise ConfigError(f"Konfigurationsdatei nicht gefunden: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()

    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - umgebungsabhaengig
            raise ConfigError(
                "YAML-Konfiguration gefunden, aber PyYAML fehlt. "
                "Installiere 'PyYAML' oder nutze eine .json-Datei."
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")

    if not isinstance(data, dict):
        raise ConfigError("Die Konfiguration muss ein Objekt/Mapping sein")
    return Config.from_dict(data)
