"""LoginShield - Schutz gegen Brute-Force- und automatisierte Angriffe.

Kurzform::

    from loginshield import Guard, load_config

    guard = Guard(load_config("loginshield.yaml"))

    decision = guard.check(ip)
    if not decision.allowed:
        return http_429(retry_after=decision.retry_after)

    if password_ok:
        guard.record_success(ip, identity=username)
    else:
        guard.record_failure(ip, identity=username)
"""

from .anomaly import AnomalyDetector, AnomalyReport
from .config import (
    AnomalyConfig,
    Config,
    DashboardConfig,
    FirewallConfig,
    HoneypotConfig,
    LogSourceConfig,
    RealtimeConfig,
    RequestFilterConfig,
    RuleConfig,
    load_config,
)
from .filescan import FileScanner, Quarantine, ScanResult
from .firewall import Firewall
from .honeypot import Honeypot
from .realtime import RealtimeGuard, WatchEvent
from .requestfilter import FilterVerdict, RequestFilter
from .signatures import SignatureDB, Signature
from .engine import Guard
from .models import Attempt, Block, Decision, Event, Reason
from .store import Store
from .version import __version__

__all__ = [
    "__version__",
    "AnomalyConfig",
    "AnomalyDetector",
    "AnomalyReport",
    "Attempt",
    "Block",
    "Config",
    "DashboardConfig",
    "Decision",
    "Event",
    "FileScanner",
    "FilterVerdict",
    "Firewall",
    "FirewallConfig",
    "Guard",
    "Honeypot",
    "HoneypotConfig",
    "load_config",
    "LogSourceConfig",
    "Quarantine",
    "RealtimeConfig",
    "RealtimeGuard",
    "Reason",
    "RequestFilter",
    "RequestFilterConfig",
    "RuleConfig",
    "ScanResult",
    "Signature",
    "SignatureDB",
    "Store",
    "WatchEvent",
]
