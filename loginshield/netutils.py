"""IP-Hilfsfunktionen.

Wichtigster Teil: :func:`client_ip`. Ein Angreifer kann ``X-Forwarded-For``
frei setzen. Wer diesen Header blind auswertet, laesst sich die Sperrlogik
mit einem einzigen gefaelschten Header aushebeln (oder sperrt fremde IPs).
Deshalb wird der Header nur ausgewertet, wenn der direkte Peer ein
konfigurierter, vertrauenswuerdiger Proxy ist.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Sequence, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def parse_ip(value: Optional[str]) -> Optional[Address]:
    """Robuste IP-Erkennung: toleriert Ports, Klammern und Leerzeichen."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None

    # "[2001:db8::1]:443" oder "[2001:db8::1]"
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            text = text[1:end]
    # "1.2.3.4:5678" - aber nicht eine nackte IPv6-Adresse zerlegen
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]

    # "::ffff:1.2.3.4" auf IPv4 zurueckfuehren
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def normalize_ip(value: Optional[str]) -> Optional[str]:
    addr = parse_ip(value)
    return str(addr) if addr else None


def parse_networks(values: Optional[Iterable[str]]) -> List[Network]:
    """Wandelt eine Liste aus IPs/CIDRs in Netzwerke um. Ungueltiges wird ignoriert."""
    networks: List[Network] = []
    for raw in values or ():
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return networks


def ip_in_networks(ip: Optional[str], networks: Sequence[Network]) -> bool:
    addr = parse_ip(ip)
    if addr is None or not networks:
        return False
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False


def client_ip(
    peer_ip: Optional[str],
    forwarded_for: Optional[str] = None,
    trusted_proxies: Optional[Sequence[Network]] = None,
) -> Optional[str]:
    """Ermittelt die echte Client-IP.

    * Ohne konfigurierte Proxies gilt immer die Peer-Adresse (faelschungssicher).
    * Mit Proxies wird ``X-Forwarded-For`` von rechts nach links durchlaufen und
      die erste Adresse genommen, die nicht selbst ein vertrauenswuerdiger
      Proxy ist. Alles weiter links kann der Client frei erfinden.
    """
    peer = normalize_ip(peer_ip)
    if not trusted_proxies or not forwarded_for:
        return peer
    if not ip_in_networks(peer, trusted_proxies):
        # Der direkte Gegenueber ist kein bekannter Proxy -> Header ignorieren.
        return peer

    for raw in reversed(forwarded_for.split(",")):
        candidate = normalize_ip(raw)
        if candidate is None:
            continue
        if ip_in_networks(candidate, trusted_proxies):
            continue
        return candidate
    return peer


def subnet_of(ip: Optional[str], prefix_v4: int = 24,
              prefix_v6: int = 64) -> Optional[str]:
    """Das umgebende Netz einer Adresse, z.B. ``203.0.113.0/24``.

    Angreifer aus Botnetzen sitzen haeufig im selben Adressblock: wird eine
    IP gesperrt, kommt die naechste Anfrage vom Nachbarn. Ueber das Netz
    laesst sich das als ein Angriff erkennen.
    """
    address = parse_ip(ip)
    if address is None:
        return None
    prefix = prefix_v4 if address.version == 4 else prefix_v6
    try:
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except ValueError:
        return None


def is_network(value: Optional[str]) -> bool:
    """``True`` fuer eine CIDR-Angabe, die mehr als eine Adresse umfasst."""
    if not value or "/" not in str(value):
        return False
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return net.num_addresses > 1


def parse_target(value: Optional[str]) -> Optional[str]:
    """Normalisiert eine Sperr-Zielangabe: einzelne IP oder Netz."""
    if not value:
        return None
    text = str(value).strip()
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return None
    return normalize_ip(text)


def networks_overlap(outer: str, inner_networks: Sequence[Network]) -> bool:
    """Liegt eines der Netze ganz oder teilweise in ``outer``?

    Damit wird verhindert, dass eine Netzsperre die eigene Allowlist
    ueberdeckt - sonst sperrt man mit einem /24 das eigene Buero aus.
    """
    try:
        block = ipaddress.ip_network(outer, strict=False)
    except ValueError:
        return False
    for net in inner_networks:
        if net.version != block.version:
            continue
        if net.overlaps(block):
            return True
    return False


def is_public(ip: Optional[str]) -> bool:
    addr = parse_ip(ip)
    return bool(addr and addr.is_global)
