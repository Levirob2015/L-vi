"""Optionale Anbindung an die System-Firewall.

LoginShield sperrt zunaechst nur in der eigenen Anwendung. Wer moechte, kann
zusaetzlich ein Kommando ausfuehren lassen, das die IP auf Netzwerkebene
blockt. Das Kommando wird ohne Shell gestartet (kein ``shell=True``), damit
eine IP-Angabe niemals als Shell-Code interpretiert werden kann - dieser Weg
ist die klassische Schwachstelle solcher Integrationen.

Beispiel (nftables)::

    firewall:
      enabled: true
      block_command:   ["nft", "add", "element", "inet", "filter", "banned", "{ {ip} }"]
      unblock_command: ["nft", "delete", "element", "inet", "filter", "banned", "{ {ip} }"]
"""

from __future__ import annotations

import logging
import subprocess
from typing import List, Optional, Sequence

from .config import FirewallConfig
from .netutils import normalize_ip

log = logging.getLogger("loginshield.firewall")


class Firewall:
    def __init__(self, config: Optional[FirewallConfig] = None) -> None:
        self.config = config or FirewallConfig()

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled and self.config.block_command)

    def block(self, ip: str, seconds: int) -> bool:
        return self._run(self.config.block_command, ip, seconds)

    def unblock(self, ip: str) -> bool:
        if not self.config.unblock_command:
            return False
        return self._run(self.config.unblock_command, ip, 0)

    # ------------------------------------------------------------------
    def _run(self, template: Sequence[str], ip: str, seconds: int) -> bool:
        if not self.config.enabled or not template:
            return False

        # Nur validierte IPs weiterreichen - nie rohen Nutzereingang.
        safe_ip = normalize_ip(ip)
        if safe_ip is None:
            log.warning("Firewall-Kommando uebersprungen, ungueltige IP: %r", ip)
            return False

        argv: List[str] = [
            part.replace("{ip}", safe_ip).replace("{seconds}", str(int(seconds)))
            for part in template
        ]
        try:
            result = subprocess.run(  # noqa: S603 - feste Argumentliste, keine Shell
                argv,
                capture_output=True,
                timeout=self.config.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            log.error("Firewall-Kommando fehlgeschlagen (%s): %s", argv[0], exc)
            return False

        if result.returncode != 0:
            log.error(
                "Firewall-Kommando %s endete mit %s: %s",
                argv[0],
                result.returncode,
                result.stderr.decode("utf-8", "replace").strip()[:300],
            )
            return False
        return True
