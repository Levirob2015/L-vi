"""Datentypen von LoginShield."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class Event:
    """Ereignistypen, die im Store landen."""

    LOGIN_FAILURE = "login_failure"
    LOGIN_SUCCESS = "login_success"
    REQUEST = "request"
    DENIED = "denied"
    HONEYPOT = "honeypot"
    SUSPICIOUS = "suspicious"   # auffaellige Anfrage, noch keine Sperre


class Reason:
    """Begruendung einer Entscheidung. Wird auch im Dashboard angezeigt."""

    OK = "ok"
    ALLOWLISTED = "allowlisted"
    IP_BLOCKED = "ip_blocked"
    RATE_LIMITED = "rate_limited"
    IDENTITY_THROTTLED = "identity_throttled"
    IDENTITY_LOCKED = "identity_locked"

    # Ausloeser fuer eine neue Sperre
    BRUTE_FORCE_IP = "brute_force_ip"
    CREDENTIAL_SPRAY = "credential_spray"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    SUBNET_ABUSE = "subnet_abuse"      # ganzes Netz statt Einzel-IP
    MALICIOUS_REQUEST = "malicious_request"  # Anfrage-Firewall
    ANOMALY = "anomaly"                # Abweichung vom Normalzustand
    MALICIOUS_UPLOAD = "malicious_upload"    # hochgeladene Datei mit Schadcode
    MANUAL = "manual"

    # Honeypot: kein Schwellwert noetig, ein einziger Treffer genuegt
    HONEYPOT_PATH = "honeypot_path"        # gefaelschte Schwachstelle aufgerufen
    HONEYPOT_TOKEN = "honeypot_token"      # untergeschobene Zugangsdaten benutzt
    HONEYPOT_FIELD = "honeypot_field"      # unsichtbares Formularfeld ausgefuellt


#: Entscheidungen, bei denen der Aufrufer den Request abweisen soll.
DENY_REASONS = frozenset(
    {
        Reason.IP_BLOCKED,
        Reason.RATE_LIMITED,
        Reason.IDENTITY_THROTTLED,
        Reason.IDENTITY_LOCKED,
    }
)


@dataclass(frozen=True)
class Decision:
    """Ergebnis einer Pruefung.

    ``allowed`` ist das Einzige, was der Aufrufer zwingend auswerten muss.
    ``retry_after`` ist in Sekunden und eignet sich direkt fuer den
    HTTP-Header ``Retry-After``.
    """

    allowed: bool
    reason: str = Reason.OK
    retry_after: int = 0
    blocked_until: Optional[float] = None
    detail: str = ""

    @property
    def status_code(self) -> int:
        """Passender HTTP-Status fuer diese Entscheidung."""
        if self.allowed:
            return 200
        # 403 heisst "abgelehnt, ein spaeterer Versuch aendert daran
        # nichts" - richtig fuer eine Sperre und fuer eine abgewiesene
        # Datei. 429 waere eine Einladung, es gleich noch einmal zu
        # versuchen, und das trifft nur die Bremse.
        if self.reason in (Reason.IP_BLOCKED, Reason.MALICIOUS_REQUEST,
                           Reason.MALICIOUS_UPLOAD):
            return 403
        return 429

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "retry_after": self.retry_after,
            "blocked_until": self.blocked_until,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Attempt:
    """Ein protokollierter Zugriff."""

    id: int
    ts: float
    ip: str
    event: str
    identity: str = ""
    route: str = ""
    user_agent: str = ""
    source: str = "app"
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "ip": self.ip,
            "event": self.event,
            "identity": self.identity,
            "route": self.route,
            "user_agent": self.user_agent,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class Block:
    """Eine aktive oder abgelaufene IP-Sperre."""

    id: int
    ip: str
    created_ts: float
    expires_ts: float
    reason: str
    strikes: int = 0
    active: bool = True
    detail: str = ""
    #: True = die Sperre gilt fuer ein ganzes Netz (CIDR), nicht eine Adresse.
    is_network: bool = False
    meta: dict = field(default_factory=dict)

    def remaining(self, now: float) -> int:
        return max(0, int(self.expires_ts - now))

    def as_dict(self, now: Optional[float] = None) -> dict:
        data = {
            "id": self.id,
            "ip": self.ip,
            "created_ts": self.created_ts,
            "expires_ts": self.expires_ts,
            "reason": self.reason,
            "strikes": self.strikes,
            "active": self.active,
            "detail": self.detail,
            "is_network": self.is_network,
        }
        if now is not None:
            data["remaining"] = self.remaining(now)
        return data
