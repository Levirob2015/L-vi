"""Die zweite Firewall: Anfragen nach Inhalt filtern.

Die System-Firewall (siehe :mod:`loginshield.firewall`) kennt nur Absender-
adressen. Sie sieht nicht, **was** jemand anfragt. Ein Angreifer mit frischer
IP kommt dort ungehindert durch und darf es beim ersten Mal versuchen.

Diese Ebene liest den angefragten Pfad, die Parameter und die Kennung des
Programms und erkennt daran den Angriffsversuch selbst:

* ``/etc/passwd`` ueber ``../../..`` erreichen wollen (Path Traversal)
* ``' OR '1'='1`` oder ``UNION SELECT`` in einem Parameter (SQL-Injection)
* ``${jndi:ldap://...}`` (Log4Shell)
* ``; cat /etc/shadow`` (Kommando-Einschleusung)
* Programmkennungen wie ``sqlmap`` oder ``nikto``

Wichtigste Entwurfsentscheidung: **Falschmeldungen sind hier gefaehrlicher
als Luecken.** Wer zu scharf filtert, sperrt echte Nutzer aus. Deshalb:

* Jede Regel hat eine Schwere. Gesperrt wird erst ab einer Summe - eine
  einzelne schwache Uebereinstimmung genuegt nie.
* Nur Muster, die in normalem Verkehr praktisch nicht vorkommen.
* ``action: log`` schreibt nur mit, ohne zu sperren. So laesst sich vor dem
  Scharfschalten pruefen, was passieren wuerde.
* Die Allowlist gilt immer zuerst.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from urllib.parse import unquote_plus

from .config import RequestFilterConfig
from .models import Block, Reason

log = logging.getLogger("loginshield.requestfilter")

#: Obergrenze der geprueften Zeichen. Schuetzt davor, dass jemand mit sehr
#: langen URLs Rechenzeit bindet.
_MAX_INSPECT = 8192


@dataclass(frozen=True)
class FilterRule:
    """Ein Erkennungsmuster.

    ``severity`` von 1 (schwacher Hinweis) bis 10 (eindeutiger Angriff).
    """

    name: str
    pattern: str
    severity: int
    target: str = "url"          # url | user_agent | method
    description: str = ""

    def compiled(self) -> "re.Pattern":
        return re.compile(self.pattern, re.IGNORECASE)


#: Eingebaute Regeln. Bewusst knapp gehalten: jedes Muster hier muss in
#: normalem Verkehr praktisch ausgeschlossen sein.
DEFAULT_RULES: Sequence[FilterRule] = (
    # -- Eindeutige Angriffe (Schwere 8-10) ---------------------------
    FilterRule(
        "log4shell", r"\$\{jndi:(ldap|rmi|dns|iiop)", 10, "url",
        "Log4Shell-Versuch",
    ),
    FilterRule(
        "path_traversal", r"(\.\./){2,}|(\.\.\\){2,}|/etc/(passwd|shadow)\b",
        9, "url", "Zugriff auf Systemdateien ueber Verzeichniswechsel",
    ),
    FilterRule(
        "kommando_einschleusung",
        r";\s*(cat|wget|curl|nc|ncat|bash|sh|python|perl)\s|\|\s*(nc|bash|sh)\s|`[^`]+`",
        9, "url", "Kommando-Einschleusung",
    ),
    FilterRule(
        "scanner", r"\b(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|"
                   r"wpscan|havij|acunetix|nessus|arachni|w3af)\b",
        9, "user_agent", "Bekanntes Angriffswerkzeug",
    ),
    FilterRule(
        "nullbyte", r"%00|\x00", 8, "url",
        "Nullbyte - Versuch, eine Pruefung abzuschneiden",
    ),
    FilterRule(
        "php_wrapper", r"\b(php|data|expect|file|phar)://", 8, "url",
        "PHP-Stream-Wrapper",
    ),
    FilterRule(
        "sql_union", r"\bunion\s+(all\s+)?select\b", 8, "url",
        "SQL-Injection (UNION SELECT)",
    ),
    FilterRule(
        # Faengt 1' OR '1'='1 ebenso wie ' or 1=1 -- : nach dem Anfuehrungs-
        # zeichen folgt ein Vergleich, dessen Seiten wieder in Anfuehrungs-
        # zeichen stehen duerfen.
        "sql_tautologie",
        r"('|%27)\s*(or|and)\s+('?[\w%]+'?\s*(=|%3d)\s*'?[\w%]+)",
        8, "url", "SQL-Injection (immer-wahr-Bedingung)",
    ),
    FilterRule(
        # Angehaengte, zerstoerende Anweisung - dafuer gibt es keinen
        # harmlosen Grund in einer URL.
        "sql_destruktiv",
        r";\s*(drop|delete|truncate|alter)\s+(table|database|from)\b",
        9, "url", "Angehaengte zerstoerende SQL-Anweisung",
    ),
    FilterRule(
        "sql_kommentar", r"(--|%2d%2d)\s*$|/\*.*?\*/", 5, "url",
        "Abgeschnittene SQL-Anweisung",
    ),
    FilterRule(
        "sql_zeitbasiert", r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
        8, "url", "Zeitbasierte SQL-Injection",
    ),

    # -- Starke Hinweise (Schwere 4-7) --------------------------------
    FilterRule(
        "sql_schema", r"\b(information_schema|sysobjects|pg_catalog)\b", 6, "url",
        "Zugriff auf Datenbank-Metadaten",
    ),
    FilterRule(
        "xss_script", r"<\s*script|javascript:|on(error|load|click)\s*=", 5, "url",
        "Script-Einschleusung",
    ),
    FilterRule(
        "template_einschleusung", r"\{\{.*?\}\}|\$\{.*?\}", 4, "url",
        "Template-Einschleusung",
    ),
    FilterRule(
        "serialisierung", r"\bO:\d+:\"|rO0AB|__proto__", 5, "url",
        "Manipulierte Objektdaten",
    ),
    FilterRule(
        "ungewoehnliche_methode", r"^(TRACE|TRACK|DEBUG|CONNECT)$", 6, "method",
        "Ungewoehnliche HTTP-Methode",
    ),
)


@dataclass
class FilterVerdict:
    """Ergebnis der Pruefung einer Anfrage."""

    score: int = 0
    matched: List[FilterRule] = field(default_factory=list)
    blocked: bool = False

    @property
    def clean(self) -> bool:
        return not self.matched

    @property
    def summary(self) -> str:
        if not self.matched:
            return "unauffaellig"
        return ", ".join(rule.name for rule in self.matched[:4])

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "blocked": self.blocked,
            "rules": [
                {"name": r.name, "severity": r.severity, "description": r.description}
                for r in self.matched
            ],
        }


class RequestFilter:
    """Prueft Anfragen auf Angriffsmuster."""

    def __init__(self, config: Optional[RequestFilterConfig] = None, guard=None) -> None:
        self.config = config or RequestFilterConfig()
        self.guard = guard

        rules: List[FilterRule] = (
            [] if self.config.replace_default_rules else list(DEFAULT_RULES)
        )
        for raw in self.config.extra_rules:
            rules.append(
                FilterRule(
                    name=str(raw.get("name", "eigen")),
                    pattern=str(raw.get("pattern", "")),
                    severity=int(raw.get("severity", 5)),
                    target=str(raw.get("target", "url")),
                    description=str(raw.get("description", "")),
                )
            )
        disabled = {name.strip() for name in self.config.disabled_rules}
        self.rules: List[FilterRule] = [
            rule for rule in rules if rule.pattern and rule.name not in disabled
        ]
        self._compiled = [(rule, rule.compiled()) for rule in self.rules]

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled) and bool(self._compiled)

    # ------------------------------------------------------------------
    def inspect(
        self,
        *,
        path: str = "",
        query: str = "",
        user_agent: str = "",
        method: str = "GET",
    ) -> FilterVerdict:
        """Bewertet eine Anfrage, ohne etwas zu unternehmen."""
        verdict = FilterVerdict()
        if not self.enabled:
            return verdict

        if self.config.exempt_paths and _matches(path, self.config.exempt_paths):
            return verdict

        url = f"{path}?{query}" if query else path
        laenge = len(url)

        if laenge > self.config.max_url_length:
            verdict.score += 3
            verdict.matched.append(
                FilterRule("ueberlange_url", "", 3, "url",
                           f"URL laenger als {self.config.max_url_length} Zeichen")
            )

        # Nur den Anfang pruefen. Ohne diese Grenze koennte jemand mit einer
        # 200 KB langen URL pro Anfrage Rechenzeit binden - die Regeln
        # laufen ueber die gesamte Zeichenkette. Ein Angriff steckt ohnehin
        # im vorderen Teil; alles dahinter ist bereits als ueberlange URL
        # vermerkt.
        grenze = min(self.config.max_url_length, _MAX_INSPECT)
        if laenge > grenze:
            url = url[:grenze]

        # Doppelt dekodieren: Angreifer verstecken Muster gern hinter
        # %252e%252e statt %2e%2e.
        haystacks: Dict[str, str] = {
            "url": _decode(url, self.config.decode_rounds),
            "user_agent": (user_agent or "")[:_MAX_INSPECT],
            "method": (method or "").upper()[:16],
        }

        for rule, pattern in self._compiled:
            text = haystacks.get(rule.target, "")
            if text and pattern.search(text):
                verdict.matched.append(rule)
                verdict.score += rule.severity

        verdict.blocked = verdict.score >= self.config.block_score
        return verdict

    # ------------------------------------------------------------------
    def handle(
        self,
        ip: Optional[str],
        verdict: FilterVerdict,
        *,
        route: str = "",
        user_agent: str = "",
        source: str = "app",
    ) -> Optional[Block]:
        """Protokolliert einen Treffer und sperrt bei genuegend Schwere.

        Gibt die Sperre zurueck, falls eine entstanden ist.
        """
        if self.guard is None or verdict.clean:
            return None

        detail = f"score {verdict.score}: {verdict.summary}"

        # Bei action=log wird nur mitgeschrieben - zum gefahrlosen Einfahren.
        if self.config.action == "log" or not verdict.blocked:
            self.guard.record_suspicious(
                ip, route=route, user_agent=user_agent, source=source, detail=detail
            )
            return None

        return self.guard.record_honeypot(
            ip,
            route=route,
            reason=Reason.MALICIOUS_REQUEST,
            user_agent=user_agent,
            source=source,
            detail=detail,
            seconds=self.config.block_seconds,
        )

    def explain(self, text: str) -> FilterVerdict:
        """Prueft eine beliebige Zeichenkette - fuer ``loginshield filter --test``."""
        return self.inspect(path=text, user_agent=text)


def _decode(text: str, rounds: int = 2) -> str:
    """Dekodiert Prozentkodierung mehrfach, ohne dabei zu stolpern."""
    current = text or ""
    for _ in range(max(1, rounds)):
        try:
            decoded = unquote_plus(current)
        except Exception:  # pragma: no cover - defensiv
            break
        if decoded == current:
            break
        current = decoded
    return current


def _matches(path: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*"):
            if path.startswith(pattern[:-1]):
                return True
        elif path == pattern:
            return True
    return False
