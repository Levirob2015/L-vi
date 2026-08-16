import os
import shutil

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError, FirewallConfig
from loginshield.firewall import (
    CommandResult,
    Firewall,
    IptablesBackend,
    NftablesBackend,
    NullBackend,
    UfwBackend,
)


class FakeRunner:
    """Nimmt Kommandos entgegen, statt sie auszufuehren."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, argv, timeout=10):
        argv = list(argv)
        self.calls.append(argv)
        for needle, response in self.responses.items():
            if needle in " ".join(argv):
                return response
        return CommandResult(argv, 0, "", "")

    @property
    def commands(self):
        return [" ".join(call) for call in self.calls]

    def contains(self, fragment):
        return any(fragment in command for command in self.commands)


#: iptables '-C' prueft, ob eine Regel existiert - Exitcode 1 heisst "nein".
RULE_MISSING = {"-C ": CommandResult([], 1, "", "does a matching rule exist?")}


def make(backend="nftables", responses=None, **kwargs):
    config = FirewallConfig(enabled=True, backend=backend, **kwargs)
    runner = FakeRunner(responses)
    return Firewall(config, runner), runner


# -- Auswahl des Backends ------------------------------------------------
def test_auto_erkennung_bevorzugt_nftables(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    firewall, _ = make(backend="auto")
    assert firewall.name == "nftables"


def test_auto_faellt_auf_iptables_zurueck(monkeypatch):
    monkeypatch.setattr(shutil, "which",
                        lambda binary: None if binary == "nft" else "/sbin/" + binary)
    firewall, _ = make(backend="auto")
    assert firewall.name == "iptables"


def test_auto_ohne_werkzeuge_ist_wirkungslos(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: None)
    firewall, _ = make(backend="auto")
    assert firewall.name == "none"
    assert not firewall.enabled
    assert firewall.block("203.0.113.5", 60) is False


def test_eigene_kommandos_haben_vorrang(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend="auto",
                            block_command=["mein-skript", "{ip}"])
    firewall = Firewall(config, FakeRunner())
    assert firewall.name == "command"


def test_unbekanntes_backend_schaltet_ab():
    config = FirewallConfig(enabled=True, backend="gibt-es-nicht")
    firewall = Firewall(config, FakeRunner())
    assert isinstance(firewall.backend, NullBackend)


def test_abgeschaltet_fuehrt_nichts_aus():
    config = FirewallConfig(enabled=False, backend="nftables")
    runner = FakeRunner()
    firewall = Firewall(config, runner)
    assert firewall.block("203.0.113.5", 60) is False
    assert runner.calls == []


# -- Sicherheitsnetze ----------------------------------------------------
def test_localhost_wird_nie_gesperrt():
    # Sonst schneidet sich der Server von seinen eigenen Diensten ab.
    firewall, runner = make()
    assert firewall.block("127.0.0.1", 60) is False
    assert firewall.block("::1", 60) is False
    assert runner.calls == []


def test_ungueltige_ip_wird_abgelehnt():
    firewall, runner = make()
    assert firewall.block("kein-ip; rm -rf /", 60) is False
    assert runner.calls == []


def test_keine_shell_und_keine_zusammengesetzten_strings():
    # Jedes Argument bleibt ein eigenes Listenelement - eine IP kann
    # deshalb nie als Kommando interpretiert werden.
    firewall, runner = make()
    firewall.block("203.0.113.5", 900)
    for call in runner.calls:
        assert isinstance(call, list)
        assert all(isinstance(part, str) for part in call)
    assert not runner.contains("&&")
    assert not runner.contains("|")


def test_trockenlauf_aendert_nichts():
    firewall, runner = make(dry_run=True)
    assert firewall.block("203.0.113.5", 900) is True
    assert runner.calls == []  # nur protokolliert


def test_sudo_praefix():
    firewall, runner = make(sudo=True)
    firewall.block("203.0.113.5", 900)
    assert runner.calls[0][:2] == ["sudo", "-n"]  # -n = nie interaktiv fragen


# -- nftables ------------------------------------------------------------
def test_nftables_block_mit_ablaufzeit():
    firewall, runner = make("nftables")
    firewall.block("203.0.113.5", 900)
    assert runner.contains("nft add element inet loginshield blocked4")
    assert runner.contains("timeout 900s")  # nftables raeumt selbst auf


def test_nftables_waehlt_das_richtige_set():
    firewall, runner = make("nftables")
    firewall.block("2001:db8::5", 900)
    assert runner.contains("blocked6")
    assert not runner.contains("blocked4")


def test_nftables_unblock():
    firewall, runner = make("nftables")
    firewall.unblock("203.0.113.5")
    assert runner.contains("nft delete element inet loginshield blocked4")


def test_nftables_unblock_toleriert_fehlenden_eintrag():
    config = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner({"delete element": CommandResult(
        [], 1, "", "Error: No such file or directory")})
    firewall = Firewall(config, runner)
    assert firewall.unblock("203.0.113.5") is True


def test_nftables_setup_legt_eigene_tabelle_an():
    firewall, _ = make("nftables")
    commands = [" ".join(parts) for parts in firewall.backend.setup_commands()]
    assert any("add table inet loginshield" in c for c in commands)
    assert any("flags timeout" in c for c in commands)
    assert any("priority -10" in c for c in commands)
    # Nur die eigene Tabelle, keine fremden Regeln.
    assert not any("filter" in c and "loginshield" not in c for c in commands)


def test_nftables_liste_parsen():
    output = """table inet loginshield {
\tset blocked4 {
\t\ttype ipv4_addr
\t\tflags timeout
\t\telements = { 203.0.113.5 timeout 15m expires 14m30s,
\t\t\t 198.51.100.9 timeout 1h expires 59m }
\t}
}"""
    config = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner({"list set inet loginshield blocked4":
                         CommandResult([], 0, output, "")})
    firewall = Firewall(config, runner)
    assert sorted(firewall.list_blocked()) == ["198.51.100.9", "203.0.113.5"]


def test_nftables_clear_loescht_nur_eigene_tabelle():
    firewall, runner = make("nftables")
    firewall.clear()
    assert runner.commands == ["nft delete table inet loginshield"]


def test_eigener_tabellenname():
    firewall, runner = make("nftables", table="meinschutz")
    firewall.block("203.0.113.5", 60)
    assert runner.contains("inet meinschutz")


# -- iptables ------------------------------------------------------------
def test_iptables_nutzt_eigene_kette():
    firewall, runner = make("iptables", RULE_MISSING)
    firewall.block("203.0.113.5", 900)
    assert runner.contains("iptables -I LOGINSHIELD 1 -s 203.0.113.5 -j DROP")


def test_iptables_vermeidet_doppelte_regeln():
    config = FirewallConfig(enabled=True, backend="iptables")
    runner = FakeRunner({"-C LOGINSHIELD": CommandResult([], 0, "", "")})
    firewall = Firewall(config, runner)
    assert firewall.block("203.0.113.5", 900) is True
    assert not runner.contains("-I LOGINSHIELD")  # war schon da


def test_iptables_nimmt_ip6tables_fuer_v6():
    firewall, runner = make("iptables", RULE_MISSING)
    firewall.block("2001:db8::5", 900)
    assert runner.contains("ip6tables")


def test_iptables_liste_parsen():
    output = ("-N LOGINSHIELD\n"
              "-A LOGINSHIELD -s 203.0.113.5/32 -j DROP\n"
              "-A LOGINSHIELD -s 198.51.100.9/32 -j DROP\n")
    config = FirewallConfig(enabled=True, backend="iptables")
    runner = FakeRunner({"iptables -S LOGINSHIELD": CommandResult([], 0, output, "")})
    firewall = Firewall(config, runner)
    assert "203.0.113.5" in firewall.list_blocked()


# -- ufw -----------------------------------------------------------------
def test_ufw_sperrt_ganz_oben():
    firewall, runner = make("ufw")
    firewall.block("203.0.113.5", 900)
    # insert 1: sonst greift eine allow-Regel weiter oben zuerst.
    assert runner.contains("ufw insert 1 deny from 203.0.113.5")


# -- eigene Kommandos ----------------------------------------------------
def test_command_backend_ersetzt_platzhalter():
    config = FirewallConfig(
        enabled=True, backend="command",
        block_command=["mein-skript", "block", "{ip}", "{seconds}"],
        unblock_command=["mein-skript", "unblock", "{ip}"],
    )
    runner = FakeRunner()
    firewall = Firewall(config, runner)
    firewall.block("203.0.113.5", 900)
    assert runner.calls[0] == ["mein-skript", "block", "203.0.113.5", "900"]
    firewall.unblock("203.0.113.5")
    assert runner.calls[1] == ["mein-skript", "unblock", "203.0.113.5"]


# -- Abgleich ------------------------------------------------------------
def test_sync_schreibt_fehlende_sperren(guard, clock):
    guard.config.firewall.enabled = True
    guard.config.firewall.backend = "nftables"
    runner = FakeRunner()
    guard.firewall = Firewall(guard.config.firewall, runner)

    guard.block("203.0.113.5", seconds=600)
    runner.calls.clear()

    result = guard.sync_firewall()
    assert result["added"] == 1
    assert runner.contains("203.0.113.5")


def test_sync_entfernt_verwaiste_eintraege():
    # Wichtig: sonst bleibt jemand fuer immer ausgesperrt, dessen Sperre
    # in LoginShield laengst abgelaufen ist.
    output = "elements = { 198.51.100.9 timeout 15m expires 14m }"
    config = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner({"list set inet loginshield blocked4":
                         CommandResult([], 0, output, "")})
    firewall = Firewall(config, runner)

    result = firewall.sync([], now=1000)
    assert result["removed"] == 1
    assert runner.contains("delete element inet loginshield blocked4")


def test_sync_laesst_vorhandene_in_ruhe():
    output = "elements = { 203.0.113.5 timeout 15m expires 14m }"
    config = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner({"list set": CommandResult([], 0, output, "")})
    firewall = Firewall(config, runner)

    class FakeBlock:
        ip = "203.0.113.5"
        expires_ts = 1600

    result = firewall.sync([FakeBlock()], now=1000)
    assert result == {"added": 0, "removed": 0, "failed": 0}


def test_sync_beim_start(config, tmp_path):
    config.firewall.enabled = True
    config.firewall.backend = "nftables"
    config.firewall.sync_on_start = True
    runner = FakeRunner()

    guard = Guard(config, firewall=Firewall(config.firewall, runner))
    try:
        assert runner.contains("list set inet loginshield")
    finally:
        guard.close()


# -- Guard-Anbindung -----------------------------------------------------
def test_sperre_landet_in_der_firewall(config, store, clock):
    config.firewall.enabled = True
    config.firewall.backend = "nftables"
    runner = FakeRunner()
    guard = Guard(config, store, clock=clock,
                  firewall=Firewall(config.firewall, runner))

    for _ in range(config.rules.ip_failure_threshold):
        guard.record_failure("198.51.100.66", identity="admin")

    assert runner.contains("add element inet loginshield blocked4")
    assert runner.contains("198.51.100.66")

    runner.calls.clear()
    guard.unblock("198.51.100.66")
    assert runner.contains("delete element")


def test_abgelaufene_sperre_wird_in_der_firewall_geloest(config, store, clock):
    config.firewall.enabled = True
    config.firewall.backend = "iptables"
    runner = FakeRunner()
    guard = Guard(config, store, clock=clock,
                  firewall=Firewall(config.firewall, runner))

    guard.block("203.0.113.7", seconds=60)
    clock.advance(61)
    runner.calls.clear()

    guard.maintenance()
    assert runner.contains("-D LOGINSHIELD -s 203.0.113.7")


def test_firewall_fehler_bricht_die_sperre_nicht(config, store, clock):
    config.firewall.enabled = True
    config.firewall.backend = "nftables"
    runner = FakeRunner({"add element": CommandResult([], 1, "", "Permission denied")})
    guard = Guard(config, store, clock=clock,
                  firewall=Firewall(config.firewall, runner))

    block = guard.block("203.0.113.7", seconds=600)
    # Die Sperre in der Anwendung gilt trotzdem.
    assert block is not None
    assert not guard.check("203.0.113.7").allowed


# -- Konfiguration -------------------------------------------------------
def test_unbekanntes_backend_wird_abgelehnt():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"backend": "quatsch"}})


def test_command_backend_braucht_kommando():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"enabled": True, "backend": "command"}})


def test_tabellenname_wird_geprueft():
    # Der Name landet in Firewall-Kommandos - kein Freitext.
    for name in ("mit leerzeichen", "semikolon;rm", "", "1zahl-zuerst"):
        with pytest.raises(ConfigError):
            Config.from_dict({"firewall": {"table": name}})
    Config.from_dict({"firewall": {"table": "mein_schutz2"}})


def test_status():
    firewall, _ = make("nftables")
    status = firewall.status()
    assert status.backend == "nftables"
    assert status.enabled is True


# -- Echte Integration (nur wenn ausdruecklich gewuenscht) ---------------
REAL = os.environ.get("LOGINSHIELD_FIREWALL_IT") == "1"


@pytest.mark.skipif(not REAL, reason="setzt LOGINSHIELD_FIREWALL_IT=1 und Root voraus")
def test_echtes_nftables_end_to_end():
    config = FirewallConfig(enabled=True, backend="nftables", table="lstest")
    firewall = Firewall(config)
    assert firewall.backend.available()

    assert firewall.setup()
    try:
        assert firewall.backend.is_ready()
        assert firewall.block("203.0.113.5", 300)
        assert "203.0.113.5" in firewall.list_blocked()
        assert firewall.unblock("203.0.113.5")
        assert "203.0.113.5" not in firewall.list_blocked()
    finally:
        firewall.clear()


# -- Diagnose und Selbsttest --------------------------------------------
def test_diagnose_ohne_backend(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: None)
    firewall, _ = make(backend="auto")
    hinweise = " ".join(firewall.diagnose())
    assert "Kein Firewall-Backend" in hinweise


def test_diagnose_meldet_fehlendes_werkzeug(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: None)
    firewall, _ = make("nftables")
    assert "nicht installiert" in " ".join(firewall.diagnose())


def test_diagnose_meldet_fehlende_rechte(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/nft")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    firewall, _ = make("nftables")
    assert "nicht als root" in " ".join(firewall.diagnose())


def test_diagnose_meldet_trockenlauf(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/nft")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    firewall, _ = make("nftables", dry_run=True)
    assert "Trockenlauf" in " ".join(firewall.diagnose())


def test_diagnose_warnt_bei_fehlendem_ablauf(monkeypatch):
    # iptables kennt keine ablaufenden Regeln - darauf muss hingewiesen werden.
    monkeypatch.setattr(shutil, "which", lambda binary: "/sbin/iptables")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    firewall, _ = make("iptables")
    assert "nicht selbst ablaufen" in " ".join(firewall.diagnose())


def test_selftest_erfolgreich():
    zustand = {"gesperrt": []}

    def runner(argv, timeout=10):
        text = " ".join(argv)
        if "add element" in text:
            zustand["gesperrt"].append("192.0.2.201")
        elif "delete element" in text:
            zustand["gesperrt"] = []
        elif "list set" in text and "blocked4" in text:
            inhalt = ("elements = { 192.0.2.201 timeout 1m }"
                      if zustand["gesperrt"] else "")
            return CommandResult(argv, 0, inhalt, "")
        return CommandResult(argv, 0, "", "")

    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), runner)
    ok, schritte = firewall.selftest()
    assert ok is True
    assert "funktioniert" in schritte[-1]


def test_selftest_erkennt_wirkungsloses_kommando():
    # Kommando meldet Erfolg, die Sperre taucht aber nirgends auf -
    # genau der Fall, den man sonst erst beim echten Angriff bemerkt.
    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), FakeRunner())
    ok, schritte = firewall.selftest()
    assert ok is False
    assert "taucht nicht in der Firewall auf" in " ".join(schritte)


def test_selftest_verweigert_trockenlauf():
    firewall, _ = make("nftables", dry_run=True)
    ok, schritte = firewall.selftest()
    assert ok is False
    assert "Trockenlauf" in schritte[0]


def test_selftest_fasst_echte_sperre_nicht_an():
    output = "elements = { 192.0.2.201 timeout 15m }"
    runner = FakeRunner({"list set": CommandResult([], 0, output, "")})
    firewall = Firewall(FirewallConfig(enabled=True, backend="nftables"), runner)
    ok, schritte = firewall.selftest()
    assert ok is False
    assert "bereits gesperrt" in schritte[0]


# -- Zwei Firewalls gleichzeitig ----------------------------------------
def test_mehrere_backends(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend=["nftables", "iptables"])
    runner = FakeRunner(RULE_MISSING)
    firewall = Firewall(config, runner)

    assert "nftables" in firewall.name and "iptables" in firewall.name
    firewall.block("203.0.113.5", 900)
    # Die Sperre landet in beiden Firewalls.
    assert runner.contains("nft add element")
    assert runner.contains("iptables -I LOGINSHIELD")


def test_mehrere_backends_eines_faellt_aus(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend=["nftables", "iptables"])
    # nft schlaegt fehl, iptables nicht - die Sperre gilt trotzdem.
    runner = FakeRunner({
        "nft add element": CommandResult([], 1, "", "Permission denied"),
        "-C ": CommandResult([], 1, "", "no rule"),
    })
    firewall = Firewall(config, runner)
    assert firewall.block("203.0.113.5", 900) is True


def test_mehrere_backends_beide_fallen_aus(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend=["nftables", "iptables"])
    runner = FakeRunner({"": CommandResult([], 1, "", "kaputt")})
    firewall = Firewall(config, runner)
    assert firewall.block("203.0.113.5", 900) is False


def test_mehrere_backends_nicht_verfuegbare_werden_uebersprungen(monkeypatch):
    monkeypatch.setattr(shutil, "which",
                        lambda binary: None if binary == "nft" else "/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend=["nftables", "iptables"])
    firewall = Firewall(config, FakeRunner(RULE_MISSING))
    # Nur iptables uebrig - dann kein Multi-Backend, sondern direkt iptables.
    assert firewall.name == "iptables"


def test_mehrere_backends_liste_ist_vereinigt(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda binary: "/usr/sbin/" + binary)
    config = FirewallConfig(enabled=True, backend=["nftables", "iptables"])
    runner = FakeRunner({
        "list set inet loginshield blocked4":
            CommandResult([], 0, "elements = { 203.0.113.5 timeout 1h }", ""),
        "iptables -S LOGINSHIELD":
            CommandResult([], 0, "-A LOGINSHIELD -s 198.51.100.9/32 -j DROP", ""),
    })
    firewall = Firewall(config, runner)
    assert sorted(firewall.list_blocked()) == ["198.51.100.9", "203.0.113.5"]


def test_auto_laesst_sich_nicht_kombinieren():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"backend": ["auto", "iptables"]}})


# -- Nachpruefen der Sperre ---------------------------------------------
def test_verify_erkennt_wirkungsloses_kommando():
    # Kommando meldet Erfolg, die Sperre taucht nicht auf.
    firewall, runner = make("nftables", verify=True)
    assert firewall.block("203.0.113.5", 900) is False
    # Ein zweiter Versuch wurde unternommen.
    assert len([c for c in runner.commands if "add element" in c]) == 2


def test_verify_bestaetigt_wirksame_sperre():
    zustand = {"drin": False}

    def runner(argv, timeout=10):
        text = " ".join(argv)
        if "add element" in text:
            zustand["drin"] = True
        elif "list set" in text and "blocked4" in text:
            inhalt = "elements = { 203.0.113.5 timeout 15m }" if zustand["drin"] else ""
            return CommandResult(argv, 0, inhalt, "")
        return CommandResult(argv, 0, "", "")

    config = FirewallConfig(enabled=True, backend="nftables", verify=True)
    assert Firewall(config, runner).block("203.0.113.5", 900) is True


def test_verify_ohne_wirkung_im_trockenlauf():
    firewall, runner = make("nftables", verify=True, dry_run=True)
    # Im Trockenlauf wird nichts nachgeprueft - es gibt ja nichts zu finden.
    assert firewall.block("203.0.113.5", 900) is True


def test_nft_setup_verwirft_ungueltige_pakete():
    firewall, _ = make("nftables")
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    assert any("ct state invalid drop" in c for c in befehle)


# -- Verbindungsbremse ---------------------------------------------------
# Die Schicht, die die Anwendung nicht haben kann: Wer den Server mit
# Verbindungsversuchen flutet, beschaeftigt ihn, bevor eine Zeile Python
# laeuft. Diese Regeln greifen im Kern des Betriebssystems.
def test_bremse_ist_voreingestellt_aus():
    """Der Wert muss zum eigenen Verkehr passen - sonst fliegen Besucher raus."""
    firewall, _ = make("nftables")
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    assert not any("limit rate over" in c for c in befehle)


def test_nft_bremse_begrenzt_je_absender():
    firewall, _ = make("nftables", conn_limit_enabled=True,
                       conn_limit_rate=90, conn_limit_burst=30)
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    regel = [c for c in befehle if "limit rate over" in c]
    assert len(regel) == 2                      # je einmal fuer IPv4 und IPv6
    assert any("ip saddr limit rate over 90/minute burst 30 packets" in c
               for c in regel)
    assert any("ip6 saddr limit rate over 90/minute burst 30 packets" in c
               for c in regel)
    # Der Zaehler laeuft je Adresse und raeumt sich selbst weg.
    assert any("flags dynamic, timeout" in c for c in befehle)


def test_nft_bremse_nur_auf_den_genannten_ports():
    firewall, _ = make("nftables", conn_limit_enabled=True,
                       conn_limit_ports=[443])
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    assert any("dport { 443 }" in c for c in befehle)


def test_nft_bremse_ohne_ports_gilt_fuer_alle():
    firewall, _ = make("nftables", conn_limit_enabled=True, conn_limit_ports=[])
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    assert any("limit rate over" in c and "dport" not in c for c in befehle)


def test_bremse_steht_hinter_der_allowlist():
    """Sonst koennte die Bremse das eigene Buero ausbremsen."""
    firewall, _ = make("nftables", conn_limit_enabled=True)
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    erlaubt = next(i for i, c in enumerate(befehle) if "@erlaubt4 accept" in c)
    bremse = next(i for i, c in enumerate(befehle) if "limit rate over" in c)
    assert erlaubt < bremse


def test_iptables_bremse():
    firewall, runner = make("iptables", responses=RULE_MISSING,
                            conn_limit_enabled=True, conn_limit_rate=90)
    firewall.setup()
    assert runner.contains("--hashlimit-above 90/min")
    assert runner.contains("--hashlimit-mode srcip")


def test_iptables_bremse_wird_nicht_doppelt_gesetzt():
    """Zwei Bremsen hintereinander wuerden das erlaubte Mass halbieren."""
    firewall, runner = make("iptables", conn_limit_enabled=True)  # -C meldet Erfolg
    firewall.setup()
    assert not runner.contains("-A LOGINSHIELD -p tcp")


def test_bremse_verlangt_eine_eingeschaltete_firewall():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"conn_limit_enabled": True}})


def test_unsinnige_werte_werden_abgelehnt():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"conn_limit_rate": 0}})
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"conn_limit_ports": [70000]}})
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"conn_limit_ports": list(range(20))}})


# -- Allowlist in der Firewall ------------------------------------------
def test_nft_allowlist_wird_eingetragen():
    firewall, runner = make("nftables")
    assert firewall.sync_allowlist(["203.0.113.10", "198.51.100.0/24", "2001:db8::1"])
    assert runner.contains("flush set inet loginshield erlaubt4")
    assert runner.contains(
        "add element inet loginshield erlaubt4 { 203.0.113.10, 198.51.100.0/24 }")
    assert runner.contains("add element inet loginshield erlaubt6 { 2001:db8::1 }")


def test_nft_setup_leert_die_eigene_kette_zuerst():
    """'nft add rule' haengt an - ohne flush waere jede Regel doppelt."""
    firewall, _ = make("nftables")
    befehle = [" ".join(p) for p in firewall.backend.setup_commands()]
    flush = next(i for i, c in enumerate(befehle) if "flush chain" in c)
    erste_regel = next(i for i, c in enumerate(befehle) if "add rule" in c)
    assert flush < erste_regel
    # Die Sets werden nicht geleert - Sperren ueberstehen die Einrichtung.
    assert not any("flush set" in c for c in befehle)


def test_iptables_allowlist_als_return_regel():
    firewall, runner = make("iptables")
    firewall.sync_allowlist(["203.0.113.10"])
    assert runner.contains("-I LOGINSHIELD 1 -s 203.0.113.10 -j RETURN")


def test_allowlist_abschaltbar():
    firewall, runner = make("nftables", sync_allowlist=False)
    assert firewall.sync_allowlist(["203.0.113.10"]) is False
    assert not runner.contains("erlaubt4")


def test_ungueltige_allowlist_eintraege_werden_uebergangen():
    firewall, runner = make("nftables")
    firewall.sync_allowlist(["203.0.113.10", "kein-netz", ""])
    assert runner.contains("{ 203.0.113.10 }")


def test_guard_gibt_die_allowlist_weiter(tmp_path):
    """Die Bremse zaehlt nur Pakete - sie muss die Freigabe selbst kennen."""
    config = Config(db_path=str(tmp_path / "t.db"), allowlist=["203.0.113.10"])
    config.firewall = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner()
    guard = Guard(config, firewall=Firewall(config.firewall, runner))
    try:
        guard.sync_allowlist()
        assert runner.contains("erlaubt4 { 203.0.113.10 }")
    finally:
        guard.close()


def test_neue_freigabe_erreicht_die_firewall(tmp_path):
    config = Config(db_path=str(tmp_path / "t.db"))
    config.firewall = FirewallConfig(enabled=True, backend="nftables")
    runner = FakeRunner()
    guard = Guard(config, firewall=Firewall(config.firewall, runner))
    try:
        guard.allow("198.51.100.7", "Buero")
        assert runner.contains("erlaubt4 { 198.51.100.7 }")
    finally:
        guard.close()
