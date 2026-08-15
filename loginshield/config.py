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

    Standardmaessig aus. Die Kommandos werden ohne Shell ausgefuehrt;
    ``{ip}`` und ``{seconds}`` werden ersetzt.
    """

    enabled: bool = False
    block_command: List[str] = field(default_factory=list)
    unblock_command: List[str] = field(default_factory=list)
    timeout: int = 10

    def validate(self) -> None:
        if self.enabled and not self.block_command:
            raise ConfigError("firewall.enabled gesetzt, aber kein block_command")


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
    logwatch: List[LogSourceConfig] = field(default_factory=list)

    def validate(self) -> "Config":
        if self.identity_mode not in ("hashed", "plain", "none"):
            raise ConfigError("identity_mode muss hashed, plain oder none sein")
        if self.retention_days <= 0:
            raise ConfigError("retention_days muss groesser als 0 sein")
        self.rules.validate()
        self.dashboard.validate()
        self.firewall.validate()
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
