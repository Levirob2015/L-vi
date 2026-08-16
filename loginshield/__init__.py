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
    RequestFilterConfig,
    RuleConfig,
    load_config,
)
from .firewall import Firewall
from .honeypot import Honeypot
from .requestfilter import FilterVerdict, RequestFilter
from .engine import Guard
from .models import Attempt, Block, Decision, Event, Reason
from .store import Store
from .version import __version__

__all__ = [
    "AnomalyConfig",
    "AnomalyDetector",
    "AnomalyReport",
    "Attempt",
    "Block",
    "Config",
    "DashboardConfig",
    "Decision",
    "Event",
    "Firewall",
    "FirewallConfig",
    "FilterVerdict",
    "Guard",
    "Honeypot",
    "HoneypotConfig",
    "LogSourceConfig",
    "Reason",
    "RequestFilter",
    "RequestFilterConfig",
    "RuleConfig",
    "Store",
    "__version__",
    "load_config",
]
