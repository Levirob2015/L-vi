"""Netzsperre: ein ganzer Adressblock statt einzelner IPs.

Ein Botnetz weicht nach einer Sperre auf die Nachbaradresse aus. Haeufen
sich Sperren im selben Block, wird der Block als Ganzes gesperrt.
"""

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError
from loginshield.models import Reason
from loginshield.netutils import (
    is_network,
    networks_overlap,
    parse_networks,
    parse_target,
    subnet_of,
)


def blocke_ips(guard, anzahl, netz="198.51.100.", start=10, sekunden=600):
    """Sperrt einzelne Adressen aus demselben Block."""
    for index in range(anzahl):
        guard.block(f"{netz}{start + index}", seconds=sekunden, reason="test")


# -- Hilfsfunktionen -----------------------------------------------------
def test_subnet_of():
    assert subnet_of("198.51.100.66") == "198.51.100.0/24"
    assert subnet_of("198.51.100.66", prefix_v4=16) == "198.51.0.0/16"
    assert subnet_of("2001:db8::5") == "2001:db8::/64"
    assert subnet_of("kein-ip") is None
    assert subnet_of(None) is None


def test_is_network():
    assert is_network("203.0.113.0/24")
    assert is_network("2001:db8::/64")
    # Ein /32 ist genau eine Adresse - kein Netz im Sinne der Sperre.
    assert not is_network("203.0.113.5/32")
    assert not is_network("203.0.113.5")
    assert not is_network("quatsch/24")


def test_parse_target():
    assert parse_target("203.0.113.5") == "203.0.113.5"
    assert parse_target("203.0.113.7/24") == "203.0.113.0/24"  # wird normalisiert
    assert parse_target("  198.51.100.0/24 ") == "198.51.100.0/24"
    assert parse_target("kaputt") is None


def test_networks_overlap():
    allow = parse_networks(["198.51.100.20", "10.0.0.0/8"])
    assert networks_overlap("198.51.100.0/24", allow)   # enthaelt die erlaubte IP
    assert networks_overlap("10.1.0.0/16", allow)
    assert not networks_overlap("203.0.113.0/24", allow)


# -- Erkennung -----------------------------------------------------------
def test_netz_wird_nach_schwelle_gesperrt(config, store, clock):
    config.rules.subnet_threshold = 4
    guard = Guard(config, store, clock=clock)

    blocke_ips(guard, 3)
    assert guard.store.active_network_blocks(clock.now) == []
    # Eine unbeteiligte Adresse im selben Netz darf noch durch.
    assert guard.check("198.51.100.200").allowed

    blocke_ips(guard, 1, start=13)
    netze = guard.store.active_network_blocks(clock.now)
    assert len(netze) == 1
    assert netze[0].ip == "198.51.100.0/24"
    assert netze[0].reason == Reason.SUBNET_ABUSE
    assert netze[0].is_network is True


def test_gesperrtes_netz_blockt_unbeteiligte_adressen(config, store, clock):
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)
    blocke_ips(guard, 3)

    # Diese Adresse war nie auffaellig, liegt aber im gesperrten Block.
    entscheidung = guard.check("198.51.100.250")
    assert not entscheidung.allowed
    assert entscheidung.detail == Reason.SUBNET_ABUSE

    # Ausserhalb des Blocks bleibt alles frei.
    assert guard.check("203.0.113.5").allowed


def test_netzsperre_laeuft_ab(config, store, clock):
    config.rules.subnet_threshold = 3
    config.rules.subnet_block_seconds = 600
    guard = Guard(config, store, clock=clock)
    blocke_ips(guard, 3)
    assert not guard.check("198.51.100.250").allowed

    clock.advance(601)
    guard.maintenance()
    assert guard.check("198.51.100.250").allowed


def test_alte_sperren_zaehlen_nicht_mit(config, store, clock):
    config.rules.subnet_threshold = 3
    config.rules.subnet_window = 3600
    guard = Guard(config, store, clock=clock)

    blocke_ips(guard, 2)
    clock.advance(3601)  # Fenster laeuft weiter
    blocke_ips(guard, 1, start=12)
    assert guard.store.active_network_blocks(clock.now) == []


def test_verschiedene_netze_zaehlen_getrennt(config, store, clock):
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)

    guard.block("198.51.100.10", seconds=600)
    guard.block("203.0.113.10", seconds=600)
    guard.block("192.0.2.10", seconds=600)
    assert guard.store.active_network_blocks(clock.now) == []


def test_ipv6_netzsperre(config, store, clock):
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)
    for index in range(3):
        guard.block(f"2001:db8::{index + 1}", seconds=600)

    netze = guard.store.active_network_blocks(clock.now)
    assert len(netze) == 1
    assert netze[0].ip == "2001:db8::/64"
    assert not guard.check("2001:db8::ffff").allowed


def test_abschaltbar(config, store, clock):
    config.rules.subnet_enabled = False
    guard = Guard(config, store, clock=clock)
    blocke_ips(guard, 6)
    assert guard.store.active_network_blocks(clock.now) == []


def test_greift_auch_bei_echten_angriffen(config, store, clock):
    """Nicht nur bei manuellen Sperren, sondern im normalen Ablauf."""
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)

    for index in range(3):
        ip = f"198.51.100.{40 + index}"
        for _ in range(config.rules.ip_failure_threshold):
            guard.record_failure(ip, identity="admin")

    netze = guard.store.active_network_blocks(clock.now)
    assert len(netze) == 1
    assert netze[0].ip == "198.51.100.0/24"


# -- Sicherheitsnetze ----------------------------------------------------
def test_netz_mit_allowlist_adresse_wird_nie_gesperrt(config, store, clock):
    # Das ist der gefaehrlichste Fall: ein /24 wuerde das eigene Buero
    # mit aussperren, obwohl dessen IP ausdruecklich erlaubt ist.
    config.rules.subnet_threshold = 3
    config.allowlist = ["198.51.100.20"]
    guard = Guard(config, store, clock=clock)

    blocke_ips(guard, 3, start=30)
    assert guard.store.active_network_blocks(clock.now) == []
    assert guard.check("198.51.100.20").reason == Reason.ALLOWLISTED


def test_dynamische_allowlist_schuetzt_ebenfalls(config, store, clock):
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)
    guard.allow("198.51.100.20", note="Buero")

    blocke_ips(guard, 3, start=30)
    assert guard.store.active_network_blocks(clock.now) == []


def test_manuelle_netzsperre_prueft_die_allowlist(config, store, clock):
    config.allowlist = ["203.0.113.9"]
    guard = Guard(config, store, clock=clock)
    with pytest.raises(ValueError):
        guard.block("203.0.113.0/24")
    # Mit --force ist es eine bewusste Entscheidung.
    assert guard.block("203.0.113.0/24", force=True) is not None


def test_keine_doppelte_netzsperre(config, store, clock):
    config.rules.subnet_threshold = 3
    guard = Guard(config, store, clock=clock)
    blocke_ips(guard, 5)
    assert len(guard.store.active_network_blocks(clock.now)) == 1


def test_schwelle_unter_zwei_wird_abgelehnt():
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"subnet_threshold": 1}})


def test_unsinnige_praefixe_werden_abgelehnt():
    for wert in (0, 4, 33):
        with pytest.raises(ConfigError):
            Config.from_dict({"rules": {"subnet_prefix_v4": wert}})
    for wert in (8, 129):
        with pytest.raises(ConfigError):
            Config.from_dict({"rules": {"subnet_prefix_v6": wert}})


# -- Bedienung -----------------------------------------------------------
def test_netz_von_hand_sperren_und_aufheben(guard, clock):
    block = guard.block("203.0.113.0/24", seconds=600, reason="manual")
    assert block.is_network is True
    assert not guard.check("203.0.113.77").allowed

    assert guard.unblock("203.0.113.0/24")
    assert guard.check("203.0.113.77").allowed


def test_cidr_wird_normalisiert(guard):
    # 203.0.113.77/24 meint dasselbe Netz wie 203.0.113.0/24
    block = guard.block("203.0.113.77/24", seconds=600)
    assert block.ip == "203.0.113.0/24"


def test_ungueltiges_netz(guard):
    with pytest.raises(ValueError):
        guard.block("203.0.113.0/99")


# -- Firewall ------------------------------------------------------------
def test_firewall_nutzt_intervall_set_fuer_netze():
    from tests.test_firewall import FakeRunner
    from loginshield.config import FirewallConfig
    from loginshield.firewall import Firewall

    runner = FakeRunner()
    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), runner)

    firewall.block("203.0.113.0/24", 600)
    # Netze brauchen ein Set mit 'flags interval'.
    assert runner.contains("netzwerk4")
    assert runner.contains("203.0.113.0/24")

    runner.calls.clear()
    firewall.block("203.0.113.5", 600)
    assert runner.contains("blocked4")
    assert not runner.contains("netzwerk4")


def test_firewall_setup_legt_intervall_sets_an():
    from tests.test_firewall import FakeRunner
    from loginshield.config import FirewallConfig
    from loginshield.firewall import Firewall

    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), FakeRunner())
    befehle = [" ".join(parts) for parts in firewall.backend.setup_commands()]
    assert any("netzwerk4" in c and "flags interval" in c for c in befehle)
    assert any("netzwerk6" in c and "flags interval" in c for c in befehle)


def test_firewall_lehnt_netz_mit_localhost_ab():
    from tests.test_firewall import FakeRunner
    from loginshield.config import FirewallConfig
    from loginshield.firewall import Firewall

    runner = FakeRunner()
    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), runner)
    # 127.0.0.0/8 enthaelt die eigene Adresse des Servers.
    assert firewall.block("127.0.0.0/8", 600) is False
    assert firewall.block("0.0.0.0/0", 600) is False   # das ganze Internet
    assert runner.calls == []


def test_iptables_nimmt_cidr_direkt():
    from tests.test_firewall import FakeRunner, RULE_MISSING
    from loginshield.config import FirewallConfig
    from loginshield.firewall import Firewall

    runner = FakeRunner(RULE_MISSING)
    firewall = Firewall(FirewallConfig(enabled=True, backend="iptables"), runner)
    firewall.block("203.0.113.0/24", 600)
    assert runner.contains("-s 203.0.113.0/24 -j DROP")
