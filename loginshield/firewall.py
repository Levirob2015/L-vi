"""Anbindung an die System-Firewall.

LoginShield sperrt zunaechst nur in der eigenen Anwendung: ein gesperrter
Angreifer bekommt HTTP 403, seine Pakete erreichen den Server aber weiterhin.
Mit einer Firewall-Anbindung wird die IP zusaetzlich auf Netzwerkebene
geblockt - sie kommt dann an keinen Dienst mehr heran, auch nicht an SSH.

Unterstuetzt werden:

* ``nftables``  - bevorzugt, weil Sperren dort eine eigene Ablaufzeit haben
* ``iptables``  - eigene Kette, Ablauf steuert LoginShield
* ``ufw``       - die Ubuntu-Oberflaeche fuer iptables
* ``command``   - beliebige eigene Kommandos

Sicherheitsgrundsaetze dieses Moduls:

* Kommandos laufen **ohne Shell** (kein ``shell=True``) mit fester
  Argumentliste. Eine IP kann damit niemals als Shell-Code enden - das ist
  die klassische Luecke selbstgebauter fail2ban-Klone.
* Es werden nur IPs weitergereicht, die vorher als gueltige Adresse geparst
  wurden.
* LoginShield legt eine **eigene** Tabelle bzw. Kette an und fasst nichts
  anderes an. ``clear()`` entfernt nur die eigenen Eintraege.
* ``127.0.0.0/8`` und ``::1`` werden nie gesperrt - das wuerde den Server
  von seinen eigenen Diensten abschneiden.
* Schlaegt ein Firewall-Kommando fehl, wird das protokolliert, aber nie eine
  Ausnahme nach oben gereicht: die Sperre in der Anwendung gilt weiter.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from .config import FirewallConfig
from .netutils import is_network, parse_ip, parse_target

log = logging.getLogger("loginshield.firewall")

#: Diese Adressen werden nie an die Firewall weitergereicht.
NEVER_BLOCK = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


@dataclass
class CommandResult:
    argv: List[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(argv: Sequence[str], timeout: float = 10.0) -> CommandResult:
    """Fuehrt ein Kommando ohne Shell aus."""
    argv = list(argv)
    try:
        completed = subprocess.run(  # noqa: S603 - feste Argumentliste, keine Shell
            argv, capture_output=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return CommandResult(argv, 127, "", f"{argv[0]}: nicht gefunden")
    except subprocess.TimeoutExpired:
        return CommandResult(argv, 124, "", f"{argv[0]}: Zeitueberschreitung")
    except OSError as exc:
        return CommandResult(argv, 1, "", str(exc))
    return CommandResult(
        argv,
        completed.returncode,
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )


# ----------------------------------------------------------------------
# Backends
# ----------------------------------------------------------------------
class Backend:
    """Gemeinsame Basis. Ein Backend uebersetzt block/unblock in Kommandos."""

    name = "none"
    binary = ""
    #: True, wenn das Backend Sperren selbst ablaufen laesst.
    supports_timeout = False

    def __init__(self, config: FirewallConfig,
                 run: Callable[..., CommandResult] = run_command) -> None:
        self.config = config
        self._run = run

    # -- Hilfen --------------------------------------------------------
    def _argv(self, *parts: str) -> List[str]:
        argv = [str(part) for part in parts]
        if self.config.sudo:
            # -n: niemals interaktiv nach einem Passwort fragen, sonst
            # haengt ein Dienst ohne Terminal endlos.
            return ["sudo", "-n"] + argv
        return argv

    def execute(self, *parts: str) -> CommandResult:
        argv = self._argv(*parts)
        if self.config.dry_run:
            log.info("[Trockenlauf] %s", " ".join(argv))
            return CommandResult(argv, 0, "", "", skipped=True)
        result = self._run(argv, self.config.timeout)
        if not result.ok:
            log.error(
                "Firewall-Kommando fehlgeschlagen (%s): %s",
                " ".join(argv), (result.stderr or result.stdout).strip()[:300],
            )
        return result

    # -- Schnittstelle -------------------------------------------------
    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def is_ready(self) -> bool:
        """Ist die noetige Struktur (Tabelle/Kette) bereits angelegt?"""
        return True

    def setup_commands(self) -> List[List[str]]:
        return []

    def setup(self) -> bool:
        for parts in self.setup_commands():
            if not self.execute(*parts).ok:
                return False
        return True

    def block(self, ip: str, seconds: int) -> bool:
        raise NotImplementedError

    def unblock(self, ip: str) -> bool:
        raise NotImplementedError

    def list_blocked(self) -> List[str]:
        return []

    def allow_sync(self, cidrs: Sequence[str]) -> bool:
        """Traegt die Allowlist in die Firewall ein.

        Nicht jedes Backend kann das - dann bleibt es bei der Allowlist der
        Anwendung, die ohnehin verhindert, dass diese Adressen ueberhaupt
        gesperrt werden.
        """
        return True

    def healthy(self) -> bool:
        """Stehen die eigenen Regeln noch so da, wie sie gesetzt wurden?

        Nicht dasselbe wie :meth:`is_ready`: Die Struktur kann vorhanden
        sein, waehrend die Regeln darin fehlen. Genau das passiert im
        Betrieb staendig - ein ``systemctl restart nftables``, ein
        Wechsel der Firewall-Verwaltung, ein anderes Werkzeug, das seine
        eigenen Regeln laedt.
        """
        return self.is_ready()

    def clear(self) -> bool:
        ok = True
        for ip in self.list_blocked():
            ok = self.unblock(ip) and ok
        return ok


class NullBackend(Backend):
    """Kein Backend - die Sperre gilt nur in der Anwendung."""

    name = "none"

    def available(self) -> bool:
        return True

    def block(self, ip: str, seconds: int) -> bool:
        return False

    def unblock(self, ip: str) -> bool:
        return False


class NftablesBackend(Backend):
    """nftables mit eigener Tabelle und ablaufenden Elementen.

    Die Sets bekommen ``flags timeout``: nftables entfernt eine IP dann von
    selbst, wenn die Zeit um ist. Selbst wenn LoginShield abstuerzt, bleibt
    niemand dauerhaft ausgesperrt.
    """

    name = "nftables"
    binary = "nft"
    supports_timeout = True

    @property
    def table(self) -> str:
        return self.config.table

    def _set_for(self, target: str) -> Optional[str]:
        """Waehlt das passende Set: je Adressfamilie und Einzel-IP vs. Netz.

        Netze brauchen ein Set mit ``flags interval`` - ein normales Set
        nimmt nur einzelne Adressen auf.
        """
        network = is_network(target)
        address = parse_ip(target.split("/")[0])
        if address is None:
            return None
        if address.version == 4:
            return "netzwerk4" if network else "blocked4"
        return "netzwerk6" if network else "blocked6"

    def setup_commands(self) -> List[List[str]]:
        table = self.table
        befehle = [
            ["nft", "add", "table", "inet", table],
            ["nft", "add", "set", "inet", table, "blocked4",
             "{ type ipv4_addr; flags timeout; }"],
            ["nft", "add", "set", "inet", table, "blocked6",
             "{ type ipv6_addr; flags timeout; }"],
            # Eigene Sets fuer ganze Netze - 'interval' erlaubt CIDR-Eintraege.
            ["nft", "add", "set", "inet", table, "netzwerk4",
             "{ type ipv4_addr; flags interval, timeout; }"],
            ["nft", "add", "set", "inet", table, "netzwerk6",
             "{ type ipv6_addr; flags interval, timeout; }"],
            # Die Allowlist, damit die Firewall selbst weiss, wen sie nie
            # anfassen darf. 'interval' wegen der CIDR-Eintraege.
            ["nft", "add", "set", "inet", table, "erlaubt4",
             "{ type ipv4_addr; flags interval; }"],
            ["nft", "add", "set", "inet", table, "erlaubt6",
             "{ type ipv6_addr; flags interval; }"],
            # Eigene Kette mit Prioritaet -10: greift vor den ueblichen
            # filter-Regeln (Prioritaet 0), aendert diese aber nicht.
            ["nft", "add", "chain", "inet", table, "input",
             "{ type filter hook input priority -10; policy accept; }"],
            # Vorhandene Regeln der eigenen Kette leeren, bevor sie neu
            # geschrieben werden. 'nft add rule' haengt naemlich jedes Mal
            # an: Ein zweites 'firewall --setup' haette sonst jede Regel
            # doppelt - und zwei Verbindungsbremsen hintereinander halbieren
            # das erlaubte Mass. Die Sets bleiben unangetastet, gesperrte
            # Adressen ueberstehen die Einrichtung also.
            ["nft", "flush", "chain", "inet", table, "input"],
            # Zuerst die Allowlist: 'accept' beendet nur diese Kette, die
            # uebrigen Regeln des Systems gelten weiter. Damit kann sich
            # niemand mit einer eigenen Regel selbst aussperren - der
            # schlimmste denkbare Fehler dieses Programms.
            ["nft", "add", "rule", "inet", table, "input",
             "ip", "saddr", "@erlaubt4", "accept"],
            ["nft", "add", "rule", "inet", table, "input",
             "ip6", "saddr", "@erlaubt6", "accept"],
            # Ungueltige Pakete verwerfen: Standardhaertung, die auch
            # einfache Scan- und Umgehungsversuche abfaengt.
            ["nft", "add", "rule", "inet", table, "input",
             "ct", "state", "invalid", "drop"],
            ["nft", "add", "rule", "inet", table, "input",
             "ip", "saddr", "@blocked4", "drop"],
            ["nft", "add", "rule", "inet", table, "input",
             "ip6", "saddr", "@blocked6", "drop"],
            ["nft", "add", "rule", "inet", table, "input",
             "ip", "saddr", "@netzwerk4", "drop"],
            ["nft", "add", "rule", "inet", table, "input",
             "ip6", "saddr", "@netzwerk6", "drop"],
        ]
        befehle.extend(self._verbindungsbremse(table))
        return befehle

    def _verbindungsbremse(self, table: str) -> List[List[str]]:
        """Neue Verbindungen je Absender-IP schon im Kern begrenzen.

        Das ist die Schicht, die die Anwendung nicht haben kann: Ein Fluten
        mit Verbindungsversuchen beschaeftigt den Server, lange bevor eine
        Zeile Python laeuft. Der Zaehler steht in einem dynamischen Set -
        jede Adresse bekommt ihr eigenes Konto, und die Eintraege raeumen
        sich nach einer Minute selbst weg.

        Wichtig ist die Reihenfolge: Diese Regeln stehen **hinter** der
        Allowlist. Wer dort steht, wird nie ausgebremst.
        """
        config = self.config
        if not config.conn_limit_enabled:
            return []
        rate = f"{max(1, int(config.conn_limit_rate))}/minute"
        burst = f"{max(1, int(config.conn_limit_burst))}"
        befehle: List[List[str]] = []
        for suffix, familie in (("4", "ip"), ("6", "ip6")):
            befehle.append([
                "nft", "add", "set", "inet", table, f"verbindungen{suffix}",
                f"{{ type ipv{suffix}_addr; flags dynamic, timeout; "
                f"timeout 1m; }}",
            ])
            regel = ["nft", "add", "rule", "inet", table, "input", "tcp"]
            if config.conn_limit_ports:
                ports = ", ".join(str(int(p)) for p in config.conn_limit_ports)
                regel += ["dport", "{ " + ports + " }"]
            regel += [
                "ct", "state", "new",
                "add", f"@verbindungen{suffix}",
                f"{{ {familie} saddr limit rate over {rate} burst {burst} "
                f"packets }}",
                "drop",
            ]
            befehle.append(regel)
        return befehle

    def allow_sync(self, cidrs: Sequence[str]) -> bool:
        """Schreibt die Allowlist in die Firewall (ersetzt den Inhalt)."""
        ok = True
        eintraege = {"erlaubt4": [], "erlaubt6": []}
        for cidr in cidrs:
            address = parse_ip(str(cidr).split("/")[0])
            if address is None:
                continue
            eintraege["erlaubt4" if address.version == 4 else "erlaubt6"].append(
                str(cidr)
            )
        for set_name, werte in eintraege.items():
            self.execute("nft", "flush", "set", "inet", self.table, set_name)
            if not werte:
                continue
            element = "{ " + ", ".join(werte) + " }"
            if not self.execute("nft", "add", "element", "inet", self.table,
                                set_name, element).ok:
                ok = False
        return ok

    def is_ready(self) -> bool:
        result = self._run(self._argv("nft", "list", "set", "inet", self.table,
                                      "blocked4"), self.config.timeout)
        return result.ok

    def healthy(self) -> bool:
        # Es genuegt nicht, dass die Tabelle da ist: Wird die Kette
        # geleert, bleiben die Sets stehen und die Sperrliste sieht
        # unveraendert aus - nur wirkt sie nicht mehr. Deshalb wird nach
        # der Regel selbst gesehen.
        result = self._run(
            self._argv("nft", "list", "chain", "inet", self.table, "input"),
            self.config.timeout,
        )
        if not result.ok:
            return False
        text = result.stdout
        noetig = ["@blocked4", "@blocked6"]
        if self.config.conn_limit_enabled:
            noetig.append("limit rate over")
        if self.config.sync_allowlist:
            noetig.append("@erlaubt4")
        return all(teil in text for teil in noetig)

    def block(self, ip: str, seconds: int) -> bool:
        set_name = self._set_for(ip)
        if set_name is None:
            return False
        element = f"{{ {ip} timeout {max(1, int(seconds))}s }}"
        return self.execute("nft", "add", "element", "inet", self.table,
                            set_name, element).ok

    def unblock(self, ip: str) -> bool:
        set_name = self._set_for(ip)
        if set_name is None:
            return False
        result = self.execute("nft", "delete", "element", "inet", self.table,
                              set_name, f"{{ {ip} }}")
        if not result.ok and "No such file or directory" in result.stderr:
            return True  # war ohnehin nicht drin
        return result.ok

    def list_blocked(self) -> List[str]:
        found: List[str] = []
        for set_name in ("blocked4", "blocked6", "netzwerk4", "netzwerk6"):
            result = self._run(
                self._argv("nft", "list", "set", "inet", self.table, set_name),
                self.config.timeout,
            )
            if not result.ok:
                continue
            match = re.search(r"elements\s*=\s*\{(.*?)\}", result.stdout, re.S)
            if not match:
                continue
            for entry in match.group(1).split(","):
                entry = entry.strip()
                if not entry:
                    continue
                target = parse_target(entry.split()[0])
                if target is not None:
                    found.append(target)
        return found

    def clear(self) -> bool:
        # Die ganze eigene Tabelle loeschen - fremde Regeln bleiben unberuehrt.
        return self.execute("nft", "delete", "table", "inet", self.table).ok


class IptablesBackend(Backend):
    """iptables/ip6tables mit einer eigenen Kette.

    Kein eigener Ablauf: LoginShield entfernt die Regel, wenn die Sperre
    endet (``loginshield prune`` bzw. die Wartung im laufenden Betrieb).
    """

    name = "iptables"
    binary = "iptables"

    @property
    def chain(self) -> str:
        return self.config.table.upper()

    def _binary_for(self, target: str) -> Optional[str]:
        # Auch eine CIDR-Angabe muss die richtige Adressfamilie treffen -
        # deshalb vor dem Parsen die Praefixlaenge abschneiden.
        address = parse_ip(str(target).split("/")[0])
        if address is None:
            return None
        return "iptables" if address.version == 4 else "ip6tables"

    def setup_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []
        for binary in ("iptables", "ip6tables"):
            commands.append([binary, "-N", self.chain])
            # -C prueft, ob der Sprung schon existiert; erst dann einfuegen.
            commands.append([binary, "-I", "INPUT", "1", "-j", self.chain])
        return commands

    def setup(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            # Kette anlegen; existiert sie schon, ist das kein Fehler.
            create = self.execute(binary, "-N", self.chain)
            if not create.ok and "exists" not in (create.stderr or "").lower():
                ok = False
            check = self._run(
                self._argv(binary, "-C", "INPUT", "-j", self.chain),
                self.config.timeout,
            )
            if not check.ok and not self.config.dry_run:
                if not self.execute(binary, "-I", "INPUT", "1", "-j", self.chain).ok:
                    ok = False
            if not self._verbindungsbremse(binary):
                ok = False
        return ok

    def _verbindungsbremse(self, binary: str) -> bool:
        """Neue Verbindungen je Absender-IP begrenzen (hashlimit).

        ``--hashlimit-mode srcip`` fuehrt einen eigenen Zaehler je
        Absenderadresse - eine einzelne IP kann den Server also nicht mit
        Verbindungsversuchen zustellen. Die Regel steht am Ende der Kette,
        also hinter allen Freigaben.
        """
        config = self.config
        if not config.conn_limit_enabled:
            return True
        name = f"ls{'6' if binary == 'ip6tables' else '4'}conn"
        regel = ["-p", "tcp"]
        if config.conn_limit_ports:
            regel += ["-m", "multiport", "--dports",
                      ",".join(str(int(p)) for p in config.conn_limit_ports)]
        regel += [
            "-m", "conntrack", "--ctstate", "NEW",
            "-m", "hashlimit",
            "--hashlimit-above", f"{max(1, int(config.conn_limit_rate))}/min",
            "--hashlimit-burst", str(max(1, int(config.conn_limit_burst))),
            "--hashlimit-mode", "srcip",
            "--hashlimit-name", name,
            "-j", "DROP",
        ]
        # Nicht doppelt anlegen - sonst begrenzen zwei Regeln nacheinander.
        vorhanden = self._run(
            self._argv(binary, "-C", self.chain, *regel), self.config.timeout,
        )
        if vorhanden.ok:
            return True
        result = self.execute(binary, "-A", self.chain, *regel)
        if not result.ok:
            log.warning(
                "Verbindungsbremse konnte nicht gesetzt werden (%s): %s - "
                "fehlt das Modul xt_hashlimit?", binary, result.stderr[:200],
            )
        return result.ok

    def allow_sync(self, cidrs: Sequence[str]) -> bool:
        """Schreibt die Allowlist als RETURN-Regeln an den Anfang der Kette.

        RETURN heisst: zurueck in die INPUT-Kette, ohne die uebrigen Regeln
        dieser Kette zu pruefen. Wer hier steht, wird von LoginShield nie
        verworfen - auch nicht von der Verbindungsbremse.
        """
        ok = True
        for binary in ("iptables", "ip6tables"):
            # Erst die alten Freigaben entfernen, damit entfernte Eintraege
            # nicht ewig weiterwirken.
            bestand = self._run(self._argv(binary, "-S", self.chain),
                                self.config.timeout)
            if bestand.ok:
                for zeile in bestand.stdout.splitlines():
                    treffer = re.search(r"-s\s+(\S+)", zeile)
                    if treffer and zeile.rstrip().endswith("-j RETURN"):
                        self.execute(binary, "-D", self.chain, "-s",
                                     treffer.group(1), "-j", "RETURN")
            for cidr in cidrs:
                if self._binary_for(cidr) != binary:
                    continue
                if not self.execute(binary, "-I", self.chain, "1", "-s",
                                    str(cidr), "-j", "RETURN").ok:
                    ok = False
        return ok

    def is_ready(self) -> bool:
        result = self._run(self._argv("iptables", "-S", self.chain),
                           self.config.timeout)
        return result.ok

    def healthy(self) -> bool:
        # Die eigene Kette kann existieren, ohne dass INPUT noch
        # hineinspringt - dann steht sie da und wird nie durchlaufen.
        for binary in ("iptables", "ip6tables"):
            if not self._run(self._argv(binary, "-S", self.chain),
                             self.config.timeout).ok:
                return False
            if not self._run(self._argv(binary, "-C", "INPUT", "-j", self.chain),
                             self.config.timeout).ok:
                return False
        return True

    def block(self, ip: str, seconds: int) -> bool:
        binary = self._binary_for(ip)
        if binary is None:
            return False
        # Doppelte Regeln vermeiden - sonst waechst die Kette endlos.
        exists = self._run(
            self._argv(binary, "-C", self.chain, "-s", ip, "-j", "DROP"),
            self.config.timeout,
        )
        if exists.ok:
            return True
        return self.execute(binary, "-I", self.chain, "1", "-s", ip, "-j", "DROP").ok

    def unblock(self, ip: str) -> bool:
        binary = self._binary_for(ip)
        if binary is None:
            return False
        result = self.execute(binary, "-D", self.chain, "-s", ip, "-j", "DROP")
        if not result.ok and "does a matching rule exist" in result.stderr.lower():
            return True
        return result.ok

    def list_blocked(self) -> List[str]:
        found: List[str] = []
        for binary in ("iptables", "ip6tables"):
            result = self._run(self._argv(binary, "-S", self.chain),
                               self.config.timeout)
            if not result.ok:
                continue
            for line in result.stdout.splitlines():
                match = re.search(r"-s\s+(\S+)\s", line)
                if match and "-j DROP" in line:
                    address = parse_ip(match.group(1).split("/")[0])
                    if address is not None:
                        found.append(str(address))
        return found

    def clear(self) -> bool:
        ok = True
        for binary in ("iptables", "ip6tables"):
            if not self.execute(binary, "-F", self.chain).ok:
                ok = False
        return ok


class UfwBackend(Backend):
    """ufw - die vereinfachte Oberflaeche fuer iptables."""

    name = "ufw"
    binary = "ufw"

    def block(self, ip: str, seconds: int) -> bool:
        # insert 1: vor die eigenen Freigaben, sonst greift eine allow-Regel
        # weiter oben und die Sperre laeuft ins Leere.
        return self.execute("ufw", "insert", "1", "deny", "from", ip,
                            "to", "any").ok

    def unblock(self, ip: str) -> bool:
        return self.execute("ufw", "--force", "delete", "deny", "from", ip,
                            "to", "any").ok

    def list_blocked(self) -> List[str]:
        result = self._run(self._argv("ufw", "status"), self.config.timeout)
        if not result.ok:
            return []
        found = []
        for line in result.stdout.splitlines():
            if "DENY" not in line.upper():
                continue
            for token in line.split():
                address = parse_ip(token)
                if address is not None:
                    found.append(str(address))
                    break
        return found


class MultiBackend(Backend):
    """Mehrere Firewalls gleichzeitig bespielen.

    Zwei Schichten statt einer: faellt eine aus - falsch konfiguriert, Regeln
    von aussen geloescht, Dienst neu gestartet - haelt die andere. Eine
    Sperre gilt als gesetzt, sobald **eine** Firewall sie angenommen hat;
    Fehler der anderen werden protokolliert.
    """

    name = "multi"

    def __init__(self, config: FirewallConfig, backends: Sequence[Backend],
                 run: Callable[..., CommandResult] = run_command) -> None:
        super().__init__(config, run)
        self.backends = [b for b in backends if b.available()]
        self.name = "multi(" + "+".join(b.name for b in self.backends) + ")"

    @property
    def supports_timeout(self) -> bool:  # type: ignore[override]
        return all(b.supports_timeout for b in self.backends) if self.backends else False

    def available(self) -> bool:
        return bool(self.backends)

    def is_ready(self) -> bool:
        return bool(self.backends) and all(b.is_ready() for b in self.backends)

    def setup_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []
        for backend in self.backends:
            commands.extend(backend.setup_commands())
        return commands

    def setup(self) -> bool:
        return all(backend.setup() for backend in self.backends) if self.backends else False

    def block(self, ip: str, seconds: int) -> bool:
        ergebnisse = [backend.block(ip, seconds) for backend in self.backends]
        for backend, ok in zip(self.backends, ergebnisse):
            if not ok:
                log.error("%s konnte %s nicht sperren", backend.name, ip)
        return any(ergebnisse)

    def unblock(self, ip: str) -> bool:
        # Beim Entsperren zaehlt jede Schicht: bleibt eine Sperre stehen,
        # kommt derjenige weiterhin nicht durch.
        ergebnisse = [backend.unblock(ip) for backend in self.backends]
        return all(ergebnisse) if ergebnisse else False

    def list_blocked(self) -> List[str]:
        gesehen: List[str] = []
        for backend in self.backends:
            for eintrag in backend.list_blocked():
                if eintrag not in gesehen:
                    gesehen.append(eintrag)
        return gesehen

    def allow_sync(self, cidrs: Sequence[str]) -> bool:
        # Jede Schicht muss die Freigabe kennen: reicht eine sie nicht
        # durch, sperrt genau diese Schicht das eigene Buero aus.
        ergebnisse = [backend.allow_sync(cidrs) for backend in self.backends]
        return all(ergebnisse) if ergebnisse else False

    def healthy(self) -> bool:
        # Eine kaputte Schicht genuegt: Der Sinn zweier Firewalls ist,
        # dass beide stehen.
        return bool(self.backends) and all(b.healthy() for b in self.backends)

    def clear(self) -> bool:
        return all(backend.clear() for backend in self.backends)


class CommandBackend(Backend):
    """Eigene Kommandos aus der Konfiguration.

    ``{ip}`` und ``{seconds}`` werden ersetzt::

        firewall:
          backend: command
          block_command:   ["nft", "add", "element", ...]
          unblock_command: ["nft", "delete", "element", ...]
    """

    name = "command"

    def available(self) -> bool:
        return bool(self.config.block_command)

    def _expand(self, template: Sequence[str], ip: str, seconds: int) -> List[str]:
        return [
            part.replace("{ip}", ip).replace("{seconds}", str(int(seconds)))
            for part in template
        ]

    def block(self, ip: str, seconds: int) -> bool:
        if not self.config.block_command:
            return False
        return self.execute(*self._expand(self.config.block_command, ip, seconds)).ok

    def unblock(self, ip: str) -> bool:
        if not self.config.unblock_command:
            return False
        return self.execute(*self._expand(self.config.unblock_command, ip, 0)).ok


BACKENDS = {
    "nftables": NftablesBackend,
    "iptables": IptablesBackend,
    "ufw": UfwBackend,
    "command": CommandBackend,
    "none": NullBackend,
}

#: Reihenfolge der automatischen Erkennung.
AUTO_ORDER = ("nftables", "iptables", "ufw")


@dataclass
class FirewallStatus:
    backend: str
    available: bool
    ready: bool
    enabled: bool
    dry_run: bool
    blocked: List[str] = field(default_factory=list)
    note: str = ""


class Firewall:
    """Fassade: waehlt das Backend und schuetzt vor Fehlbedienung."""

    def __init__(self, config: Optional[FirewallConfig] = None,
                 run: Callable[..., CommandResult] = run_command) -> None:
        self.config = config or FirewallConfig()
        self._run = run
        self.backend = self._select_backend()

    def _select_backend(self) -> Backend:
        namen = [name.lower() for name in self.config.backends]

        # Mehrere Backends: alle gleichzeitig bespielen.
        if len(namen) > 1:
            gewaehlt = []
            for name in namen:
                backend_cls = BACKENDS.get(name)
                if backend_cls is None:
                    log.error("Unbekanntes Firewall-Backend %r - uebersprungen", name)
                    continue
                backend = backend_cls(self.config, self._run)
                if backend.available():
                    gewaehlt.append(backend)
                else:
                    log.warning("Firewall-Backend %r nicht verfuegbar", name)
            if not gewaehlt:
                return NullBackend(self.config, self._run)
            if len(gewaehlt) == 1:
                return gewaehlt[0]
            return MultiBackend(self.config, gewaehlt, self._run)

        requested = namen[0] if namen else "auto"

        if requested == "auto":
            # Eigene Kommandos haben Vorrang - wer sie setzt, will sie nutzen.
            if self.config.block_command:
                return CommandBackend(self.config, self._run)
            for name in AUTO_ORDER:
                backend = BACKENDS[name](self.config, self._run)
                if backend.available():
                    return backend
            return NullBackend(self.config, self._run)

        backend_cls = BACKENDS.get(requested)
        if backend_cls is None:
            log.error("Unbekanntes Firewall-Backend %r - Firewall bleibt aus",
                      requested)
            return NullBackend(self.config, self._run)
        return backend_cls(self.config, self._run)

    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled) and not isinstance(self.backend, NullBackend)

    @property
    def name(self) -> str:
        return self.backend.name

    def _safe_ip(self, ip: str) -> Optional[str]:
        """Prueft eine IP oder ein Netz, bevor es an die Firewall geht."""
        target = parse_target(ip)
        if target is None:
            log.warning("Firewall-Kommando uebersprungen, ungueltige Angabe: %r", ip)
            return None

        address = parse_ip(target.split("/")[0])
        if address is None:  # pragma: no cover - von parse_target abgedeckt
            return None

        # Weder die Loopback-Adresse selbst noch ein Netz, das sie enthaelt.
        for network in NEVER_BLOCK:
            if address.version != network.version:
                continue
            if address in network:
                log.warning(
                    "Firewall-Sperre fuer %s abgelehnt: eigene Adresse des Servers",
                    target,
                )
                return None
            if is_network(target):
                if ipaddress.ip_network(target, strict=False).overlaps(network):
                    log.warning(
                        "Firewall-Sperre fuer %s abgelehnt: enthaelt die eigene "
                        "Adresse des Servers", target,
                    )
                    return None
        return target

    def block(self, ip: str, seconds: int) -> bool:
        if not self.enabled:
            return False
        safe = self._safe_ip(ip)
        if safe is None:
            return False

        ok = self.backend.block(safe, int(seconds))

        # Mit verify wird nachgesehen, ob die Sperre wirklich angekommen ist.
        # Ein Kommando, das Erfolg meldet ohne zu wirken, ist gefaehrlicher
        # als gar keine Firewall - man haelt sich faelschlich fuer geschuetzt.
        if self.config.verify and not self.config.dry_run:
            if safe not in self.backend.list_blocked():
                log.warning(
                    "Sperre fuer %s war nach dem Kommando nicht auffindbar - "
                    "zweiter Versuch", safe,
                )
                ok = self.backend.block(safe, int(seconds))
                if safe not in self.backend.list_blocked():
                    log.error(
                        "Sperre fuer %s kommt in der Firewall nicht an. "
                        "Pruefen mit: loginshield firewall --selftest", safe,
                    )
                    return False
        return ok

    def unblock(self, ip: str) -> bool:
        if not self.enabled:
            return False
        safe = self._safe_ip(ip)
        if safe is None:
            return False
        return self.backend.unblock(safe)

    def setup(self) -> bool:
        return self.backend.setup()

    def watchdog(self) -> dict:
        """Sieht nach, ob die eigenen Regeln noch stehen - und stellt sie her.

        Der stillste Ausfall dieses Programms: Die Regeln sind weg, die
        Sperren in der Datenbank gelten weiter, das Dashboard zeigt
        vierzig gesperrte Adressen - und keine einzige davon wird noch
        aufgehalten. Passieren kann das durch einen Neustart des
        Firewall-Dienstes, durch ein anderes Werkzeug, das seinen
        Regelsatz laedt, oder durch ein ``nft flush ruleset`` von Hand.

        Deshalb wird bei jeder Wartung nachgesehen. Fehlt etwas, wird die
        Struktur neu angelegt; die Sperren schreibt der Aufrufer
        anschliessend zurueck.
        """
        ergebnis = {"geprueft": False, "gesund": True, "repariert": False}
        if not self.enabled or self.config.dry_run:
            return ergebnis
        if isinstance(self.backend, NullBackend) or not self.backend.available():
            return ergebnis

        ergebnis["geprueft"] = True
        if self.backend.healthy():
            return ergebnis

        ergebnis["gesund"] = False
        log.warning(
            "Die Firewall-Regeln von LoginShield fehlen - sie werden neu "
            "angelegt. Hat ein anderes Werkzeug den Regelsatz geladen?"
        )
        if self.backend.setup():
            ergebnis["repariert"] = True
            log.warning("Firewall-Regeln wiederhergestellt.")
        else:
            log.error(
                "Firewall-Regeln liessen sich nicht wiederherstellen. "
                "Die Sperren gelten derzeit nur innerhalb der Anwendung. "
                "Pruefen mit: loginshield firewall --selftest"
            )
        return ergebnis

    def sync_allowlist(self, cidrs: Sequence[str]) -> bool:
        """Traegt die Allowlist in die Firewall ein.

        Damit weiss auch die unterste Schicht, wen sie nie anfassen darf.
        Ohne das koennte die Verbindungsbremse das eigene Buero ausbremsen -
        sie zaehlt Pakete und kennt die Allowlist der Anwendung nicht.
        """
        if not self.enabled or not self.config.sync_allowlist:
            return False
        # Fehlt die eigene Struktur noch, scheitert jeder Eintrag einzeln
        # und fuellt das Log mit Fehlern, die nur eines bedeuten: 'firewall
        # --setup' fehlt. Das sagt die Meldung beim Abgleich bereits.
        if not self.config.dry_run and not self.backend.is_ready():
            return False
        gepruefte = []
        for cidr in cidrs:
            target = parse_target(str(cidr))
            if target is None:
                log.warning("Allowlist-Eintrag uebersprungen, ungueltig: %r", cidr)
                continue
            gepruefte.append(target)
        return self.backend.allow_sync(gepruefte)

    def list_blocked(self) -> List[str]:
        if isinstance(self.backend, NullBackend):
            return []
        return self.backend.list_blocked()

    def clear(self) -> bool:
        return self.backend.clear()

    def status(self) -> FirewallStatus:
        available = self.backend.available()
        ready = available and self.backend.is_ready()
        note = ""
        if not available:
            note = f"{self.backend.binary or 'Backend'} ist auf diesem System nicht verfuegbar"
        elif not ready:
            note = "Struktur fehlt - 'loginshield firewall --setup' ausfuehren"
        return FirewallStatus(
            backend=self.backend.name,
            available=available,
            ready=ready,
            enabled=self.enabled,
            dry_run=bool(self.config.dry_run),
            blocked=self.list_blocked() if ready else [],
            note=note,
        )

    def diagnose(self) -> List[str]:
        """Sucht die haeufigen Stolpersteine und benennt sie konkret.

        Ohne das bekommt man im Fehlerfall nur ein stilles 'hat nicht
        geklappt' im Log - und sucht an der falschen Stelle.
        """
        hinweise: List[str] = []

        if isinstance(self.backend, NullBackend):
            hinweise.append(
                "Kein Firewall-Backend gefunden. Installiere nftables, iptables "
                "oder ufw - oder setze firewall.backend auf 'command'."
            )
            return hinweise

        if not self.backend.available():
            hinweise.append(
                f"'{self.backend.binary}' ist nicht installiert oder nicht im PATH."
            )
            return hinweise

        # Rechte pruefen: nft/iptables brauchen root oder CAP_NET_ADMIN.
        if hasattr(os, "geteuid") and os.geteuid() != 0 and not self.config.sudo:
            hinweise.append(
                "Der Dienst laeuft nicht als root und firewall.sudo ist aus. "
                "Firewall-Kommandos werden vermutlich an fehlenden Rechten "
                "scheitern - entweder als root starten oder sudo: true setzen "
                "und 'nft' in /etc/sudoers.d/ gezielt freigeben."
            )

        if not self.backend.is_ready():
            hinweise.append(
                "Die eigene Tabelle bzw. Kette fehlt noch: "
                "'loginshield firewall --setup' ausfuehren."
            )

        if self.config.dry_run:
            hinweise.append(
                "Trockenlauf ist aktiv (firewall.dry_run) - es wird nichts "
                "wirklich gesperrt."
            )

        if not self.backend.supports_timeout:
            hinweise.append(
                f"{self.backend.name} laesst Sperren nicht selbst ablaufen. "
                "LoginShield muss dafuer laufen - sonst bleiben Eintraege "
                "haengen. 'loginshield prune' per Cron hilft."
            )

        return hinweise

    def selftest(self, probe: str = "192.0.2.201") -> Tuple[bool, List[str]]:
        """Prueft die gesamte Kette an einer Testadresse.

        Sperren, nachsehen, wieder entsperren - damit steht fest, ob die
        Anbindung auf diesem Rechner wirklich funktioniert, statt es erst
        beim ersten echten Angriff zu merken.

        ``probe`` liegt standardmaessig in 192.0.2.0/24 (RFC 5737): eine
        Adresse, die nirgendwohin fuehrt und niemandem gehoert.
        """
        schritte: List[str] = []

        if self.config.dry_run:
            return False, ["Trockenlauf ist aktiv - ein Selbsttest waere ohne Aussage."]
        if isinstance(self.backend, NullBackend):
            return False, ["Kein Backend aktiv."]
        if not self.backend.available():
            return False, [f"'{self.backend.binary}' ist nicht verfuegbar."]

        war_schon_da = probe in self.backend.list_blocked()
        if war_schon_da:
            return False, [f"{probe} ist bereits gesperrt - Test abgebrochen, "
                           f"um eine echte Sperre nicht zu beschaedigen."]

        if not self.backend.is_ready():
            schritte.append("Struktur fehlte, wird angelegt ...")
            if not self.backend.setup():
                return False, schritte + ["Einrichtung fehlgeschlagen (Rechte?)."]

        if not self.backend.block(probe, 60):
            return False, schritte + [f"Sperren von {probe} fehlgeschlagen."]
        schritte.append(f"{probe} gesperrt")

        gefunden = probe in self.backend.list_blocked()
        if not gefunden:
            self.backend.unblock(probe)
            return False, schritte + [
                "Die Sperre taucht nicht in der Firewall auf - das Kommando "
                "lief durch, hat aber nicht gewirkt."
            ]
        schritte.append("in der Firewall wiedergefunden")

        if not self.backend.unblock(probe):
            return False, schritte + [f"Entsperren von {probe} fehlgeschlagen - "
                                      f"bitte von Hand entfernen."]
        schritte.append("wieder entsperrt")

        if probe in self.backend.list_blocked():
            return False, schritte + [f"{probe} ist noch immer gesperrt."]
        schritte.append("Rueckstandsfrei - die Anbindung funktioniert.")
        return True, schritte

    def sync(self, active: Sequence, now: float) -> dict:
        """Gleicht die Firewall mit den aktiven Sperren ab.

        Noetig nach einem Neustart: nftables- und iptables-Regeln sind dann
        weg, die Sperren in der Datenbank aber noch gueltig. Umgekehrt werden
        Eintraege entfernt, die LoginShield nicht mehr kennt - sonst bleibt
        jemand fuer immer ausgesperrt.
        """
        result = {"added": 0, "removed": 0, "failed": 0}
        if not self.enabled:
            return result

        # Fehlt die eigene Tabelle, wuerde jeder einzelne Eintrag scheitern
        # und das Log fluten. Eine Meldung mit dem noetigen Hinweis genuegt.
        if not self.config.dry_run and not self.backend.is_ready():
            log.warning(
                "Firewall-Abgleich uebersprungen: die eigene Struktur fehlt. "
                "Anlegen mit 'loginshield firewall --setup'."
            )
            result["failed"] = len(active)
            return result

        wanted = {}
        for block in active:
            safe = self._safe_ip(block.ip)
            if safe is not None:
                wanted[safe] = max(1, int(block.expires_ts - now))

        present = set(self.list_blocked())

        for ip, seconds in wanted.items():
            if ip in present:
                continue
            if self.backend.block(ip, seconds):
                result["added"] += 1
            else:
                result["failed"] += 1

        for ip in present - set(wanted):
            if self.backend.unblock(ip):
                result["removed"] += 1
            else:
                result["failed"] += 1

        if result["added"] or result["removed"]:
            log.info("Firewall abgeglichen: %s hinzugefuegt, %s entfernt",
                     result["added"], result["removed"])
        return result
