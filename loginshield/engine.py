"""Die Erkennungs- und Entscheidungslogik.

:class:`Guard` ist der einzige Einstiegspunkt, den eine Anwendung braucht:

* :meth:`Guard.check`          - darf diese IP gerade rein?
* :meth:`Guard.record_failure` - Login fehlgeschlagen
* :meth:`Guard.record_success` - Login erfolgreich

Erkannt werden drei Muster:

1. **Brute Force** - viele Fehlversuche einer IP in kurzer Zeit.
2. **Password Spraying** - eine IP probiert viele verschiedene Konten
   (faellt bei Regel 1 durch, weil pro Konto nur ein, zwei Versuche kommen).
3. **Gezielter Angriff auf ein Konto** - viele Fehlversuche gegen dasselbe
   Konto, verteilt ueber viele IPs.

Dazu ein allgemeines Rate-Limit pro IP als Grundschutz.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional

from .config import Config
from .firewall import Firewall
from .honeypot import Honeypot
from .models import Block, Decision, Event, Reason
from .netutils import client_ip, ip_in_networks, normalize_ip, parse_networks
from .ratelimit import SlidingWindow
from .store import Store

log = logging.getLogger("loginshield")

#: Wie oft eine abgewiesene IP hoechstens einen DENIED-Eintrag erzeugt.
#: Ohne diese Bremse schreibt ein Angreifer die Datenbank voll.
_DENY_LOG_INTERVAL = 60.0

#: Cache-Dauer der Allowlist aus der Datenbank.
_ALLOWLIST_TTL = 5.0


class Guard:
    def __init__(
        self,
        config: Optional[Config] = None,
        store: Optional[Store] = None,
        *,
        clock=time.time,
        firewall: Optional[Firewall] = None,
    ) -> None:
        self.config = config or Config()
        self.clock = clock
        self.store = store or Store(
            self.config.db_path,
            identity_mode=self.config.identity_mode,
            identity_hmac_key=self.config.identity_hmac_key,
        )
        self.firewall = firewall if firewall is not None else Firewall(self.config.firewall)
        #: Die Falle. Siehe :mod:`loginshield.honeypot`.
        self.honeypot = Honeypot(
            self.config.honeypot, self, secret=self.config.identity_hmac_key
        )

        rules = self.config.rules
        self._limiter = SlidingWindow(rules.request_limit, rules.request_window)
        self._trusted_proxies = parse_networks(self.config.trusted_proxies)
        self._static_allow = parse_networks(self.config.allowlist)

        self._lock = threading.Lock()
        self._deny_log_at: Dict[str, float] = {}
        self._rate_strikes: Dict[str, int] = {}
        self._allow_cache: List = []
        self._allow_cache_at = 0.0

        if self.firewall.enabled and self.config.firewall.sync_on_start:
            # Nach einem Neustart sind die Firewall-Regeln weg, die Sperren
            # in der Datenbank aber noch gueltig. Fehler hier duerfen den
            # Start nicht verhindern - die Sperre in der App gilt ohnehin.
            try:
                self.sync_firewall()
            except Exception:  # pragma: no cover - systemabhaengig
                log.exception("Firewall-Abgleich beim Start fehlgeschlagen")

    # ------------------------------------------------------------------
    # Adressen
    # ------------------------------------------------------------------
    def resolve_ip(self, peer_ip: Optional[str],
                   forwarded_for: Optional[str] = None) -> Optional[str]:
        """Client-IP unter Beruecksichtigung vertrauenswuerdiger Proxys."""
        return client_ip(peer_ip, forwarded_for, self._trusted_proxies)

    def is_allowlisted(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        if ip_in_networks(ip, self._static_allow):
            return True
        return ip_in_networks(ip, self._dynamic_allow())

    def _dynamic_allow(self) -> List:
        now = self.clock()
        with self._lock:
            if now - self._allow_cache_at < _ALLOWLIST_TTL:
                return self._allow_cache
        entries = parse_networks(row["cidr"] for row in self.store.allow_list())
        with self._lock:
            self._allow_cache = entries
            self._allow_cache_at = now
        return entries

    def allow(self, cidr: str, note: str = "") -> None:
        if not parse_networks([cidr]):
            raise ValueError(f"Keine gueltige IP oder CIDR: {cidr!r}")
        self.store.allow_add(cidr, note, now=self.clock())
        with self._lock:
            self._allow_cache_at = 0.0

    def disallow(self, cidr: str) -> bool:
        removed = self.store.allow_remove(cidr)
        with self._lock:
            self._allow_cache_at = 0.0
        return removed

    # ------------------------------------------------------------------
    # Pruefung
    # ------------------------------------------------------------------
    def check(
        self,
        ip: Optional[str],
        *,
        identity: Optional[str] = None,
        route: str = "",
        count_request: bool = True,
    ) -> Decision:
        """Darf dieser Zugriff durch?

        ``count_request=False`` prueft nur, ohne das Rate-Limit zu belasten -
        etwa fuer eine Status-Anzeige.
        """
        ip = normalize_ip(ip)
        if ip is None:
            # Ohne Absenderadresse kann nichts zugeordnet werden.
            return Decision(True, Reason.OK, detail="keine IP ermittelbar")

        if self.is_allowlisted(ip):
            return Decision(True, Reason.ALLOWLISTED)

        now = self.clock()

        block = self.store.active_block(ip, now=now)
        if block is not None:
            remaining = block.remaining(now)
            self._log_denied(ip, Reason.IP_BLOCKED, route, now, detail=block.reason)
            return Decision(
                False,
                Reason.IP_BLOCKED,
                retry_after=remaining,
                blocked_until=block.expires_ts,
                detail=block.reason,
            )

        if count_request:
            allowed, retry_after, count = self._limiter.hit(ip, now)
            if not allowed:
                decision = self._handle_rate_limit(ip, route, retry_after, count, now)
                if decision is not None:
                    return decision

        if identity:
            decision = self._check_identity(identity, now)
            if decision is not None:
                self._log_denied(ip, decision.reason, route, now, detail="")
                return decision

        return Decision(True, Reason.OK)

    def _handle_rate_limit(self, ip: str, route: str, retry_after: int,
                           count: int, now: float) -> Optional[Decision]:
        rules = self.config.rules
        self._log_denied(ip, Reason.RATE_LIMITED, route, now,
                         detail=f"{count} Requests / {rules.request_window}s")

        if rules.rate_limit_strikes > 0:
            with self._lock:
                strikes = self._rate_strikes.get(ip, 0) + 1
                self._rate_strikes[ip] = strikes
                if len(self._rate_strikes) > 50_000:  # Speicher deckeln
                    self._rate_strikes.clear()
            if strikes >= rules.rate_limit_strikes:
                with self._lock:
                    self._rate_strikes.pop(ip, None)
                block = self.block(
                    ip,
                    reason=Reason.RATE_LIMIT_ABUSE,
                    detail=f"{strikes}x Rate-Limit ueberschritten",
                )
                return Decision(
                    False,
                    Reason.IP_BLOCKED,
                    retry_after=block.remaining(now),
                    blocked_until=block.expires_ts,
                    detail=Reason.RATE_LIMIT_ABUSE,
                )

        return Decision(False, Reason.RATE_LIMITED, retry_after=retry_after)

    def _check_identity(self, identity: str, now: float) -> Optional[Decision]:
        rules = self.config.rules
        if rules.identity_action == "off":
            return None
        key = self.store.identity_key(identity)
        if not key:
            return None
        failures = self.store.count_failures_by_identity(
            key, now - rules.identity_failure_window
        )
        if failures < rules.identity_failure_threshold:
            return None

        if rules.identity_action == "lock":
            return Decision(
                False,
                Reason.IDENTITY_LOCKED,
                retry_after=rules.identity_failure_window,
                detail=f"{failures} Fehlversuche gegen dieses Konto",
            )
        return Decision(
            False,
            Reason.IDENTITY_THROTTLED,
            retry_after=rules.identity_throttle_seconds,
            detail=f"{failures} Fehlversuche gegen dieses Konto",
        )

    # ------------------------------------------------------------------
    # Ereignisse melden
    # ------------------------------------------------------------------
    def record_failure(
        self,
        ip: Optional[str],
        *,
        identity: Optional[str] = None,
        route: str = "",
        user_agent: str = "",
        source: str = "app",
        detail: str = "",
    ) -> Decision:
        """Meldet einen fehlgeschlagenen Login und bewertet die Lage neu."""
        ip = normalize_ip(ip)
        now = self.clock()
        if ip is None:
            return Decision(True, Reason.OK, detail="keine IP ermittelbar")

        self.store.record_attempt(
            ip,
            Event.LOGIN_FAILURE,
            identity=identity,
            route=route,
            user_agent=user_agent,
            source=source,
            detail=detail,
            ts=now,
        )

        if self.is_allowlisted(ip):
            return Decision(True, Reason.ALLOWLISTED)

        rules = self.config.rules

        failures = self.store.count_failures_by_ip(ip, now - rules.ip_failure_window)
        if failures >= rules.ip_failure_threshold:
            block = self.block(
                ip,
                reason=Reason.BRUTE_FORCE_IP,
                detail=f"{failures} Fehlversuche in {rules.ip_failure_window}s",
            )
            return self._blocked_decision(block, now)

        identities = self.store.distinct_identities_by_ip(ip, now - rules.spray_window)
        if identities >= rules.spray_identity_threshold:
            block = self.block(
                ip,
                reason=Reason.CREDENTIAL_SPRAY,
                detail=f"{identities} verschiedene Konten in {rules.spray_window}s",
            )
            return self._blocked_decision(block, now)

        if identity:
            decision = self._check_identity(identity, now)
            if decision is not None:
                return decision

        return Decision(True, Reason.OK)

    def record_success(
        self,
        ip: Optional[str],
        *,
        identity: Optional[str] = None,
        route: str = "",
        user_agent: str = "",
        source: str = "app",
    ) -> None:
        """Meldet einen erfolgreichen Login.

        Setzt die Fehlerzaehler fuer diese IP und dieses Konto zurueck: die
        Zaehlung laeuft immer ab dem letzten Erfolg.
        """
        ip = normalize_ip(ip)
        if ip is None:
            return
        self.store.record_attempt(
            ip,
            Event.LOGIN_SUCCESS,
            identity=identity,
            route=route,
            user_agent=user_agent,
            source=source,
            ts=self.clock(),
        )

    def record_honeypot(
        self,
        ip: Optional[str],
        *,
        route: str = "",
        reason: str = Reason.HONEYPOT_PATH,
        user_agent: str = "",
        source: str = "app",
        detail: str = "",
        seconds: Optional[float] = None,
    ) -> Optional[Block]:
        """Meldet einen Honeypot-Treffer und sperrt sofort.

        Kein Schwellwert: Wer in die Falle tappt, hat gezielt nach einer
        Luecke gesucht. Ein Vertipper sieht anders aus.

        Die Allowlist gilt weiterhin - auch der eigene Sicherheitsscanner
        soll den Betrieb nicht lahmlegen.
        """
        ip = normalize_ip(ip)
        if ip is None:
            return None

        now = self.clock()
        self.store.record_attempt(
            ip,
            Event.HONEYPOT,
            route=route,
            user_agent=user_agent,
            source=source,
            detail=f"{reason} {detail}".strip(),
            ts=now,
        )

        if self.is_allowlisted(ip):
            log.info("Honeypot-Treffer von %s (%s) - Allowlist, keine Sperre", ip, route)
            return None

        log.warning("Honeypot ausgeloest von %s: %s (%s)", ip, route or "-", reason)
        return self.block(
            ip,
            seconds=seconds if seconds is not None else self.config.honeypot.block_seconds,
            reason=reason,
            detail=detail or route,
        )

    def record_request(self, ip: Optional[str], *, route: str = "",
                       user_agent: str = "", source: str = "app") -> None:
        """Optionales Protokollieren normaler Requests (standardmaessig ungenutzt)."""
        ip = normalize_ip(ip)
        if ip is None:
            return
        self.store.record_attempt(
            ip, Event.REQUEST, route=route, user_agent=user_agent,
            source=source, ts=self.clock(),
        )

    # ------------------------------------------------------------------
    # Sperren
    # ------------------------------------------------------------------
    def block(
        self,
        ip: str,
        *,
        seconds: Optional[float] = None,
        reason: str = Reason.MANUAL,
        detail: str = "",
        force: bool = False,
    ) -> Block:
        """Sperrt eine IP. Ohne ``seconds`` greift die eskalierende Dauer."""
        normalized = normalize_ip(ip)
        if normalized is None:
            raise ValueError(f"Keine gueltige IP: {ip!r}")
        if not force and self.is_allowlisted(normalized):
            raise ValueError(
                f"{normalized} steht auf der Allowlist und wird nicht gesperrt"
            )

        now = self.clock()
        rules = self.config.rules
        strikes = self.store.prior_block_count(normalized, now - rules.strike_memory)
        if seconds is None:
            seconds = min(
                rules.block_max_seconds,
                rules.block_base_seconds * (rules.block_escalation_factor ** strikes),
            )

        block = self.store.add_block(
            normalized,
            seconds=seconds,
            reason=reason,
            strikes=strikes,
            detail=detail,
            now=now,
        )
        log.warning(
            "IP %s gesperrt fuer %ss (%s: %s)",
            normalized, int(seconds), reason, detail or "-",
        )
        if self.firewall.enabled:
            self.firewall.block(normalized, int(seconds))
        return block

    def unblock(self, ip: str) -> bool:
        normalized = normalize_ip(ip)
        if normalized is None:
            return False
        removed = self.store.unblock(normalized) > 0
        with self._lock:
            self._rate_strikes.pop(normalized, None)
        self._limiter.reset(normalized)
        if removed and self.firewall.enabled:
            self.firewall.unblock(normalized)
        return removed

    def _blocked_decision(self, block: Block, now: float) -> Decision:
        return Decision(
            False,
            Reason.IP_BLOCKED,
            retry_after=block.remaining(now),
            blocked_until=block.expires_ts,
            detail=block.reason,
        )

    def _log_denied(self, ip: str, reason: str, route: str, now: float,
                    detail: str = "") -> None:
        with self._lock:
            last = self._deny_log_at.get(ip, 0.0)
            if now - last < _DENY_LOG_INTERVAL:
                return
            self._deny_log_at[ip] = now
            if len(self._deny_log_at) > 50_000:
                self._deny_log_at.clear()
        self.store.record_attempt(
            ip, Event.DENIED, route=route, detail=f"{reason} {detail}".strip(), ts=now
        )

    # ------------------------------------------------------------------
    # Betrieb
    # ------------------------------------------------------------------
    def sync_firewall(self) -> Dict[str, int]:
        """Schreibt die aktiven Sperren in die Firewall und raeumt dort auf."""
        now = self.clock()
        self.store.expire_blocks(now)
        active = self.store.list_blocks(active_only=True, limit=10_000, now=now)
        return self.firewall.sync(active, now)

    def maintenance(self) -> Dict[str, int]:
        """Abgelaufene Sperren aufheben und alte Daten loeschen."""
        now = self.clock()
        expired = self.store.expire_blocks(now)
        for ip in expired:
            self._limiter.reset(ip)
            if self.firewall.enabled:
                self.firewall.unblock(ip)
        cutoff = now - self.config.retention_days * 86400
        attempts, blocks = self.store.prune(cutoff)
        return {
            "expired_blocks": len(expired),
            "pruned_attempts": attempts,
            "pruned_blocks": blocks,
        }

    def status(self, hours: float = 24.0) -> Dict[str, object]:
        now = self.clock()
        since = now - hours * 3600
        stats = self.store.stats(since, now=now)
        stats["top_offenders"] = self.store.top_offenders(since, limit=10)
        stats["hours"] = hours
        return stats

    def close(self) -> None:
        self.store.close()
