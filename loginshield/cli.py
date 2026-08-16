"""Kommandozeile: ``loginshield <befehl>``."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import secrets
import sys
import threading
import time
from typing import List, Optional

from .config import Config, ConfigError, find_config, load_config
from .dashboard import Dashboard
from .engine import Guard
from .logwatch import LogWatcher
from .models import Event, Reason
from .store import Store
from .version import __version__

CONFIG_TEMPLATE = """# LoginShield - Konfiguration
# Alle Zeitangaben in Sekunden. Doku: siehe README.md

db_path: loginshield.db

# Diese Adressen werden nie gesperrt. Trage hier dein Buero/VPN ein,
# damit du dich nicht selbst aussperrst.
allowlist:
  - 127.0.0.1
  - ::1

# NUR diesen Proxys wird der Header X-Forwarded-For geglaubt.
# Leer lassen, wenn die App direkt im Netz haengt - sonst kann jeder
# seine IP faelschen und die Sperren umgehen.
trusted_proxies: []
  # - 10.0.0.0/8

# hashed = Benutzernamen werden nur als HMAC gespeichert (empfohlen)
identity_mode: hashed
identity_hmac_key: "__HMAC__"

retention_days: 30

rules:
  ip_failure_threshold: 5        # Fehlversuche einer IP ...
  ip_failure_window: 300         # ... in diesem Zeitraum -> Sperre
  identity_failure_threshold: 10 # Fehlversuche gegen EIN Konto
  identity_failure_window: 900
  identity_action: throttle      # throttle | lock | off
  identity_throttle_seconds: 30
  spray_identity_threshold: 5    # eine IP probiert so viele Konten -> Sperre
  spray_window: 600
  request_limit: 60              # Requests pro IP ...
  request_window: 60             # ... pro Minute
  rate_limit_strikes: 20         # so oft darf das Limit reissen, dann Sperre
  subnet_enabled: true           # Netzsperre gegen Botnetze
  subnet_threshold: 4            # so viele gesperrte IPs aus einem Block ...
  subnet_window: 3600            # ... in diesem Zeitraum -> ganzes Netz sperren
  subnet_prefix_v4: 24           # Groesse des gesperrten Blocks (IPv4)
  subnet_prefix_v6: 64
  subnet_block_seconds: 21600    # 6 Stunden
  block_base_seconds: 900        # erste Sperre: 15 Minuten
  block_max_seconds: 86400       # Obergrenze: 24 Stunden
  block_escalation_factor: 2.0   # jede weitere Sperre dauert doppelt so lang
  strike_memory: 604800

dashboard:
  host: 127.0.0.1
  port: 8787
  token: "__TOKEN__"
  refresh_seconds: 10
  allow_mutations: true

# Sperren zusaetzlich auf Netzwerkebene durchsetzen.
# Ohne Firewall gilt die Sperre nur in der Anwendung (HTTP 403), mit
# Firewall kommt die IP an keinen Dienst mehr heran - auch nicht an SSH.
#
# Einrichten:  sudo loginshield firewall --setup
# Pruefen:     loginshield firewall --status
firewall:
  enabled: false
  backend: auto           # auto | nftables | iptables | ufw | command | none
                          # Liste = mehrere gleichzeitig: [nftables, iptables]
  verify: false           # nach jeder Sperre nachsehen, ob sie ankam
  dry_run: false          # true = Kommandos nur anzeigen, nichts aendern
  sudo: false             # Kommandos mit 'sudo -n' ausfuehren
  sync_on_start: true     # aktive Sperren beim Start in die Firewall schreiben
  table: loginshield      # eigene nft-Tabelle bzw. iptables-Kette
  timeout: 10
  sync_allowlist: true    # Allowlist auch der Firewall bekannt machen
  # Verbindungsbremse: begrenzt neue Verbindungen je Absender-IP schon im
  # Kern des Systems - also bevor eine Zeile Python laeuft. Wirkt gegen
  # Fluten, gegen die die Anwendung selbst machtlos ist.
  # ACHTUNG: zu niedrig eingestellt sperrt sie echte Besucher aus.
  # Vorher ansehen:  loginshield firewall --limit-probe
  conn_limit_enabled: false
  conn_limit_ports: [80, 443]   # leer = alle TCP-Ports
  conn_limit_rate: 120          # neue Verbindungen je IP und Minute
  conn_limit_burst: 40          # wie viele auf einen Schlag durchgehen
  # Nur fuer backend: command
  block_command: []
  unblock_command: []

# Die Falle: vorgetaeuschte Schwachstellen.
# Wer /.env, /wp-admin oder /phpmyadmin aufruft, sucht gezielt nach Luecken.
# Ein einziger Treffer genuegt fuer eine Sperre - Vertipper sehen anders aus.
honeypot:
  enabled: true
  block_seconds: 86400      # 24 Stunden
  paths: []                 # leer = eingebaute Liste (loginshield honeypot --list)
  extra_paths: []           # eigene Koeder, z.B. ["/api/v1/debug*"]
  exclude_paths: []         # falls ein Koeder mit einer echten Route kollidiert
  tarpit_seconds: 0         # Antwort verzoegern, um Scanner auszubremsen
  hidden_field: website     # unsichtbares Formularfeld im Login (Bot-Falle)
  decoy_user: svc_backup    # untergeschobene Zugangsdaten
  decoy_password: ""        # leer = stabil aus dem Schluessel abgeleitet

# Die zweite Firewall: filtert Anfragen nach Inhalt (SQL-Injection,
# Path Traversal, Log4Shell, Angriffswerkzeuge).
# Erst mit action: log einfahren und 'loginshield status' beobachten,
# dann auf block umstellen.
requestfilter:
  enabled: true
  action: block           # block | log
  block_score: 8          # Summe der Regelschweren, ab der gesperrt wird
  block_seconds: 21600
  inspect_body: true      # auch POST-Daten pruefen (nicht nur die URL)
  max_body_bytes: 65536
  exempt_paths: []        # eigene Routen ausnehmen
  disabled_rules: []      # einzelne Regeln abschalten
  extra_rules: []         # eigene Muster ergaenzen

# Anomalie-Erkennung: lernt aus den eigenen Aufzeichnungen, wie normaler
# Verkehr auf DIESEM Server aussieht, und meldet Abweichungen - auch bei
# Angriffsmustern, die in keiner Regel stehen.
# Erst lernen:  loginshield learn
# Dann ansehen: loginshield anomalies
anomaly:
  enabled: true
  action: report          # report = nur melden, block = ab block_score sperren
  learn_days: 7
  window: 3600            # betrachteter Zeitraum bei einer Pruefung
  report_score: 40        # ab hier taucht eine Adresse im Bericht auf
  block_score: 70
  min_events: 200         # darunter wird gar nicht geurteilt
  min_addresses: 20
  evaluate_interval: 300  # wie oft im Betrieb geprueft wird (0 = nur auf Zuruf)
  relearn_hours: 24       # wie oft der Normalzustand aufgefrischt wird
  cache_seconds: 60       # Zwischenspeicher fuer das Dashboard

# Dateipruefung: Webshells und getarnte Dateien finden.
# Kein eigener Virenscanner - ist ClamAV installiert, wird es mitbenutzt.
# Pruefen mit:  loginshield scan /var/www
malware:
  enabled: true
  action: report          # report | quarantine
  quarantine_dir: quarantine
  block_score: 8
  clamav: auto            # auto | on | off
  inspect_archives: true  # in ZIP-Dateien hineinsehen (auch .docx usw.)

# Dateiveraenderungen ueberwachen - die wirksamste Erkennung NACH einem
# Einbruch. Erst auf einem sauberen System lernen:
#   loginshield integrity --learn --path /var/www
integrity:
  enabled: false
  paths: []
  # - /var/www

# Optional: Logdateien mitlesen (loginshield watch)
logwatch: []
#  - path: /var/log/auth.log
#    format: sshd
#  - path: /var/log/nginx/access.log
#    format: nginx
#    path_filter: /login
#    failure_statuses: [401, 403]
"""


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command is None:
        parser.print_help()
        return 0

    try:
        return args.handler(args)
    except ConfigError as exc:
        print(f"Konfigurationsfehler: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loginshield",
        description="Schutz gegen Brute-Force- und automatisierte Angriffe.",
    )
    parser.add_argument("--version", action="version", version=f"LoginShield {__version__}")
    parser.add_argument("-c", "--config", help="Pfad zur Konfigurationsdatei")
    parser.add_argument("--db", help="Pfad zur Datenbank (ueberschreibt die Konfiguration)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mehr Log-Ausgaben")
    subparsers = parser.add_subparsers(dest="command")

    init = subparsers.add_parser("init", help="Konfigurationsdatei anlegen")
    init.add_argument("--path", default=None, help="Zieldatei (Standard: loginshield.yaml)")
    init.add_argument("--force", action="store_true", help="Vorhandene Datei ueberschreiben")
    init.set_defaults(handler=cmd_init)

    serve = subparsers.add_parser("serve", help="Dashboard starten")
    serve.add_argument("--host", help="Bind-Adresse")
    serve.add_argument("--port", type=int, help="Port")
    serve.add_argument("--watch", action="store_true",
                       help="Zusaetzlich die konfigurierten Logdateien mitlesen")
    serve.set_defaults(handler=cmd_serve)

    watch = subparsers.add_parser("watch", help="Logdateien mitlesen und schuetzen")
    watch.add_argument("--path", action="append", default=[],
                       help="Zusaetzliche Logdatei (wiederholbar)")
    watch.add_argument("--format", default="sshd", choices=("sshd", "nginx", "custom"),
                       help="Format fuer --path")
    watch.add_argument("--from-start", action="store_true",
                       help="Datei von vorne lesen statt nur neue Zeilen")
    watch.add_argument("--interval", type=float, default=2.0, help="Abfrageintervall")
    watch.set_defaults(handler=cmd_watch)

    status = subparsers.add_parser("status", help="Lage-Ueberblick")
    status.add_argument("--hours", type=float, default=24.0)
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=cmd_status)

    block = subparsers.add_parser("block", help="IP oder ganzes Netz sperren")
    block.add_argument("ip", metavar="IP-ODER-NETZ",
                       help="Einzelne Adresse oder CIDR, z.B. 203.0.113.0/24")
    block.add_argument("--minutes", type=float, default=None,
                       help="Dauer (Standard: eskalierende Dauer aus der Konfiguration)")
    block.add_argument("--reason", default=Reason.MANUAL)
    block.add_argument("--force", action="store_true",
                       help="Auch sperren, wenn die IP auf der Allowlist steht")
    block.set_defaults(handler=cmd_block)

    unblock = subparsers.add_parser("unblock", help="Sperre aufheben")
    unblock.add_argument("ip", metavar="IP-ODER-NETZ")
    unblock.set_defaults(handler=cmd_unblock)

    check = subparsers.add_parser("check", help="Status einer IP abfragen")
    check.add_argument("ip")
    check.set_defaults(handler=cmd_check)

    allow = subparsers.add_parser("allow", help="Allowlist verwalten")
    allow_sub = allow.add_subparsers(dest="allow_command", required=True)
    allow_add = allow_sub.add_parser("add", help="IP/CIDR nie sperren")
    allow_add.add_argument("cidr")
    allow_add.add_argument("--note", default="")
    allow_add.set_defaults(handler=cmd_allow_add)
    allow_rm = allow_sub.add_parser("remove", help="Eintrag entfernen")
    allow_rm.add_argument("cidr")
    allow_rm.set_defaults(handler=cmd_allow_remove)
    allow_ls = allow_sub.add_parser("list", help="Eintraege anzeigen")
    allow_ls.set_defaults(handler=cmd_allow_list)
    allow.set_defaults(handler=cmd_allow_list)

    export = subparsers.add_parser("export", help="Ereignisse exportieren")
    export.add_argument("--hours", type=float, default=24.0)
    export.add_argument("--format", choices=("json", "csv"), default="json")
    export.add_argument("--out", help="Zieldatei (Standard: Standardausgabe)")
    export.set_defaults(handler=cmd_export)

    prune = subparsers.add_parser("prune", help="Alte Daten loeschen")
    prune.add_argument("--days", type=float, default=None,
                       help="Aufbewahrung in Tagen (Standard: aus der Konfiguration)")
    prune.set_defaults(handler=cmd_prune)

    firewall = subparsers.add_parser(
        "firewall", help="Sperren zusaetzlich auf Netzwerkebene durchsetzen"
    )
    firewall_action = firewall.add_mutually_exclusive_group()
    firewall_action.add_argument("--status", action="store_true",
                                 help="Backend und Zustand anzeigen (Standard)")
    firewall_action.add_argument("--setup", action="store_true",
                                 help="Eigene Tabelle/Kette anlegen")
    firewall_action.add_argument("--sync", action="store_true",
                                 help="Aktive Sperren in die Firewall schreiben")
    firewall_action.add_argument("--list", action="store_true",
                                 help="Von der Firewall gesperrte IPs anzeigen")
    firewall_action.add_argument("--clear", action="store_true",
                                 help="Alle eigenen Firewall-Eintraege entfernen")
    firewall_action.add_argument("--selftest", action="store_true",
                                 help="Sperren, nachsehen, entsperren - prueft die "
                                      "Anbindung an einer Testadresse")
    firewall_action.add_argument("--limit-probe", action="store_true",
                                 help="Aus dem bisherigen Verkehr ablesen, welche "
                                      "Verbindungsbremse gefahrlos waere")
    firewall.add_argument("--dry-run", action="store_true",
                          help="Nur anzeigen, was ausgefuehrt wuerde")
    firewall.add_argument("--yes", action="store_true",
                          help="Rueckfrage bei --clear ueberspringen")
    firewall.set_defaults(handler=cmd_firewall)

    scan = subparsers.add_parser(
        "scan", help="Dateien auf Webshells und getarnte Inhalte pruefen"
    )
    scan.add_argument("pfad", help="Datei oder Verzeichnis")
    scan.add_argument("--quarantine", action="store_true",
                      help="Funde beiseitelegen (loescht nie)")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(handler=cmd_scan)

    integrity = subparsers.add_parser(
        "integrity", help="Dateiveraenderungen ueberwachen"
    )
    integrity_action = integrity.add_mutually_exclusive_group()
    integrity_action.add_argument("--learn", action="store_true",
                                  help="Aktuellen Zustand als Grundlage festhalten")
    integrity_action.add_argument("--check", action="store_true",
                                  help="Gegen die Grundlage pruefen (Standard)")
    integrity_action.add_argument("--status", action="store_true")
    integrity.add_argument("--path", action="append", default=[],
                           help="Zu ueberwachender Pfad (wiederholbar)")
    integrity.add_argument("--json", action="store_true")
    integrity.set_defaults(handler=cmd_integrity)

    quarantine = subparsers.add_parser(
        "quarantine", help="Beiseitegelegte Dateien verwalten"
    )
    quarantine.add_argument("--list", action="store_true", help="Inhalt anzeigen")
    quarantine.add_argument("--restore", metavar="KENNUNG",
                            help="Datei zurueckholen (bei einem Fehlalarm)")
    quarantine.set_defaults(handler=cmd_quarantine)

    learn = subparsers.add_parser(
        "learn", help="Normalzustand aus den eigenen Aufzeichnungen lernen"
    )
    learn.add_argument("--days", type=float, default=None,
                       help="Lernzeitraum in Tagen (Standard: aus der Konfiguration)")
    learn.set_defaults(handler=cmd_learn)

    anomalies = subparsers.add_parser(
        "anomalies", help="Adressen anzeigen, die vom Normalzustand abweichen"
    )
    anomalies.add_argument("--hours", type=float, default=1.0,
                           help="Betrachteter Zeitraum")
    anomalies.add_argument("--min-score", type=int, default=None,
                           help="Nur ab diesem Punktwert anzeigen")
    anomalies.add_argument("--json", action="store_true")
    anomalies.set_defaults(handler=cmd_anomalies)

    filt = subparsers.add_parser(
        "filter", help="Anfrage-Firewall: Regeln anzeigen oder eine URL pruefen"
    )
    filt.add_argument("--test", metavar="URL",
                      help="Eine URL oder Zeichenkette gegen die Regeln pruefen")
    filt.add_argument("--list", action="store_true", help="Alle Regeln anzeigen")
    filt.set_defaults(handler=cmd_filter)

    honeypot = subparsers.add_parser(
        "honeypot", help="Koeder-Server starten oder die Falle inspizieren"
    )
    honeypot.add_argument("--host", default="0.0.0.0", help="Bind-Adresse")
    honeypot.add_argument("--port", type=int, default=8081, help="Port des Koeders")
    honeypot.add_argument("--list", action="store_true",
                          help="Nur die Koederpfade anzeigen")
    honeypot.add_argument("--credentials", action="store_true",
                          help="Die untergeschobenen Zugangsdaten anzeigen")
    honeypot.add_argument("--only-traps", action="store_true",
                          help="Nur bekannte Koederpfade sperren, nicht jeden Zugriff")
    honeypot.set_defaults(handler=cmd_honeypot)

    demo = subparsers.add_parser(
        "demo", help="Beispiel-Angriffsdaten erzeugen (zum Ausprobieren des Dashboards)"
    )
    demo.add_argument("--events", type=int, default=400)
    demo.set_defaults(handler=cmd_demo)

    return parser


# -- Hilfen --------------------------------------------------------------
def _config(args) -> Config:
    config = load_config(args.config)
    if args.db:
        config.db_path = args.db
    return config


def _guard(args) -> Guard:
    return Guard(_config(args))


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _table(rows: List[List[str]], headers: List[str]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    out = [line, "  ".join("-" * width for width in widths)]
    for row in rows:
        out.append("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(out)


# -- Befehle -------------------------------------------------------------
def cmd_init(args) -> int:
    try:
        import yaml  # noqa: F401
        default_name = "loginshield.yaml"
        yaml_available = True
    except ImportError:
        default_name = "loginshield.json"
        yaml_available = False

    path = args.path or default_name
    if os.path.exists(path) and not args.force:
        print(f"{path} existiert bereits. Mit --force ueberschreiben.", file=sys.stderr)
        return 1

    token = secrets.token_urlsafe(32)
    hmac_key = secrets.token_urlsafe(32)

    if path.endswith((".yaml", ".yml")) and yaml_available:
        content = CONFIG_TEMPLATE.replace("__TOKEN__", token).replace("__HMAC__", hmac_key)
    else:
        config = Config()
        config.dashboard.token = token
        config.identity_hmac_key = hmac_key
        config.allowlist = ["127.0.0.1", "::1"]
        content = json.dumps(config.as_dict(), indent=2, ensure_ascii=False) + "\n"
        if path.endswith((".yaml", ".yml")):
            print("Hinweis: PyYAML fehlt - schreibe JSON-Inhalt.", file=sys.stderr)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    try:
        os.chmod(path, 0o600)  # enthaelt Token und HMAC-Schluessel
    except OSError:
        pass

    print(f"Konfiguration geschrieben: {path}")
    print("Dashboard-Token wurde erzeugt und steht in der Datei (Rechte 600).")
    print("Naechster Schritt:  loginshield demo  &&  loginshield serve")
    return 0


def cmd_serve(args) -> int:
    config = _config(args)
    if args.host:
        config.dashboard.host = args.host
    if args.port:
        config.dashboard.port = args.port
    config.dashboard.validate()

    guard = Guard(config)
    watcher = None
    if args.watch and config.logwatch:
        watcher = LogWatcher(guard, config.logwatch)
        threading.Thread(target=watcher.run, daemon=True).start()
        print(f"Log-Watcher aktiv fuer {len(config.logwatch)} Quelle(n).")
    elif args.watch:
        print("Hinweis: keine logwatch-Quellen konfiguriert.", file=sys.stderr)

    dashboard = Dashboard(guard, config.dashboard)
    print(f"Dashboard laeuft auf {dashboard.url}")
    if not config.dashboard.token and config.dashboard.host in ("127.0.0.1", "::1"):
        print("Kein Token gesetzt - Zugriff nur von diesem Rechner moeglich.")
    print("Beenden mit Strg+C.")
    try:
        dashboard.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard wird beendet ...")
    finally:
        if watcher is not None:
            watcher.stop()
        dashboard.stop()
        guard.close()
    return 0


def cmd_watch(args) -> int:
    from .config import LogSourceConfig

    config = _config(args)
    sources = list(config.logwatch)
    for path in args.path:
        sources.append(LogSourceConfig(path=path, format=args.format))
    if not sources:
        print(
            "Keine Logquellen. Konfiguriere 'logwatch' oder nutze --path /var/log/auth.log",
            file=sys.stderr,
        )
        return 1

    guard = Guard(config)
    watcher = LogWatcher(guard, sources, from_start=args.from_start)
    for missing in watcher.missing_sources():
        print(f"Warnung: Datei nicht gefunden: {missing}", file=sys.stderr)

    print(f"Beobachte {len(sources)} Logdatei(en). Beenden mit Strg+C.")
    for source in sources:
        print(f"  - {source.path} ({source.format})")
    try:
        watcher.run(interval=args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop()
        watcher.close()
        guard.close()
    return 0


def cmd_status(args) -> int:
    guard = _guard(args)
    try:
        data = guard.status(hours=args.hours)
        if args.json:
            print(json.dumps(data, indent=2, default=str))
            return 0

        print(f"Lage der letzten {args.hours:g} Stunden")
        print("=" * 46)
        print(f"  Fehlversuche       {data['failures']}")
        print(f"  Erfolge            {data['successes']}")
        print(f"  Abgewiesen         {data['denied']}")
        print(f"  Angreifende IPs    {data['attacking_ips']}")
        print(f"  Neue Sperren       {data['new_blocks']}")
        print(f"  Aktive Sperren     {data['active_blocks']}")

        offenders = data["top_offenders"]
        if offenders:
            print("\nAuffaelligste IPs")
            rows = [
                [
                    item["ip"],
                    item["failures"],
                    item["identities"],
                    time.strftime("%d.%m. %H:%M", time.localtime(item["last_seen"])),
                ]
                for item in offenders
            ]
            print(_table(rows, ["IP", "Fehlversuche", "Konten", "Zuletzt"]))

        blocks = guard.store.list_blocks(limit=20)
        if blocks:
            now = guard.clock()
            print("\nAktive Sperren")
            rows = [
                [
                    b.ip + ("  (ganzes Netz)" if b.is_network else ""),
                    b.reason,
                    _fmt_duration(b.remaining(now)),
                    b.strikes,
                ]
                for b in blocks
            ]
            print(_table(rows, ["Ziel", "Grund", "Rest", "Stufe"]))
        return 0
    finally:
        guard.close()


def cmd_block(args) -> int:
    guard = _guard(args)
    try:
        seconds = args.minutes * 60 if args.minutes else None
        block = guard.block(
            args.ip, seconds=seconds, reason=args.reason, force=args.force
        )
        print(
            f"{block.ip} gesperrt fuer {_fmt_duration(block.remaining(guard.clock()))} "
            f"(Stufe {block.strikes}, Grund: {block.reason})"
        )
        return 0
    finally:
        guard.close()


def cmd_unblock(args) -> int:
    guard = _guard(args)
    try:
        if guard.unblock(args.ip):
            print(f"{args.ip} entsperrt.")
            return 0
        print(f"{args.ip} war nicht gesperrt.")
        return 1
    finally:
        guard.close()


def cmd_check(args) -> int:
    guard = _guard(args)
    try:
        decision = guard.check(args.ip, count_request=False)
        now = guard.clock()
        print(f"IP            {args.ip}")
        print(f"Allowlist     {'ja' if guard.is_allowlisted(args.ip) else 'nein'}")
        print(f"Entscheidung  {'erlaubt' if decision.allowed else 'abgewiesen'}"
              f" ({decision.reason})")
        if decision.retry_after:
            print(f"Wartezeit     {_fmt_duration(decision.retry_after)}")
        failures = guard.store.count_failures_by_ip(
            args.ip, now - guard.config.rules.ip_failure_window
        )
        print(f"Fehlversuche  {failures} im aktuellen Zeitfenster")
        return 0 if decision.allowed else 1
    finally:
        guard.close()


def cmd_allow_add(args) -> int:
    guard = _guard(args)
    try:
        guard.allow(args.cidr, args.note)
        print(f"Allowlist ergaenzt: {args.cidr}")
        if guard.unblock(args.cidr):
            print("Bestehende Sperre wurde aufgehoben.")
        return 0
    finally:
        guard.close()


def cmd_allow_remove(args) -> int:
    guard = _guard(args)
    try:
        if guard.disallow(args.cidr):
            print(f"Entfernt: {args.cidr}")
            return 0
        print(f"Nicht auf der Allowlist: {args.cidr}")
        return 1
    finally:
        guard.close()


def cmd_allow_list(args) -> int:
    guard = _guard(args)
    try:
        entries = guard.store.allow_list()
        static = guard.config.allowlist
        if static:
            print("Aus der Konfiguration:")
            for item in static:
                print(f"  {item}")
        if not entries:
            print("Keine dynamischen Eintraege.")
            return 0
        print("Dynamisch (Datenbank):")
        rows = [
            [
                entry["cidr"],
                entry["note"] or "-",
                time.strftime("%d.%m.%Y", time.localtime(entry["created_ts"])),
            ]
            for entry in entries
        ]
        print(_table(rows, ["Eintrag", "Notiz", "Seit"]))
        return 0
    finally:
        guard.close()


def cmd_export(args) -> int:
    config = _config(args)
    store = Store(config.db_path, identity_mode=config.identity_mode,
                  identity_hmac_key=config.identity_hmac_key)
    try:
        since = time.time() - args.hours * 3600
        attempts = list(store.iter_attempts(since))
        handle = open(args.out, "w", encoding="utf-8", newline="") if args.out else sys.stdout
        try:
            if args.format == "json":
                json.dump([a.as_dict() for a in attempts], handle, indent=2, default=str)
                handle.write("\n")
            else:
                fields = ["ts", "ip", "event", "identity", "route", "source", "detail"]
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for attempt in attempts:
                    writer.writerow(attempt.as_dict())
        finally:
            if args.out:
                handle.close()
        if args.out:
            print(f"{len(attempts)} Ereignisse geschrieben nach {args.out}")
        return 0
    finally:
        store.close()


def cmd_prune(args) -> int:
    config = _config(args)
    if args.days:
        config.retention_days = args.days
    guard = Guard(config)
    try:
        result = guard.maintenance()
        print(
            f"Abgelaufene Sperren aufgehoben: {result['expired_blocks']}\n"
            f"Geloeschte Ereignisse:          {result['pruned_attempts']}\n"
            f"Geloeschte Sperrhistorie:       {result['pruned_blocks']}"
        )
        guard.store.vacuum()
        return 0
    finally:
        guard.close()


def cmd_firewall(args) -> int:
    from .firewall import Firewall

    config = _config(args)
    if args.dry_run:
        config.firewall.dry_run = True
    # Fuer die Unterbefehle zaehlt das Backend, nicht der enabled-Schalter:
    # man soll einrichten und pruefen koennen, bevor man scharf schaltet.
    was_enabled = config.firewall.enabled
    config.firewall.enabled = True

    firewall = Firewall(config.firewall)
    status = firewall.status()

    if args.setup:
        if not status.available:
            print(f"Backend '{status.backend}' ist hier nicht verfuegbar: "
                  f"{status.note}", file=sys.stderr)
            return 1
        print(f"Richte {status.backend} ein ...")
        for parts in firewall.backend.setup_commands():
            print("  " + " ".join(parts))
        if config.firewall.dry_run:
            print("\nTrockenlauf - es wurde nichts geaendert.")
            return 0
        if not firewall.setup():
            print("\nEinrichtung fehlgeschlagen. Fehlen Root-Rechte? "
                  "(sudo loginshield firewall --setup)", file=sys.stderr)
            return 1
        print("\nFertig. Jetzt in der Konfiguration setzen:")
        print("  firewall:")
        print("    enabled: true")
        print(f"    backend: {status.backend}")
        return 0

    if args.sync:
        # Sonst gleicht schon der Konstruktor ab und der Bericht meldet 0.
        config.firewall.sync_on_start = False
        guard = Guard(config)
        try:
            result = guard.sync_firewall()
            print(f"Hinzugefuegt: {result['added']}\n"
                  f"Entfernt:     {result['removed']}\n"
                  f"Fehler:       {result['failed']}")
            return 1 if result["failed"] else 0
        finally:
            guard.close()

    if args.list:
        blocked = firewall.list_blocked()
        if not blocked:
            print("Die Firewall enthaelt keine LoginShield-Eintraege.")
            return 0
        print(f"Von LoginShield gesperrt ({len(blocked)}):")
        for ip in blocked:
            print(f"  {ip}")
        return 0

    if args.selftest:
        print("Selbsttest der Firewall-Anbindung")
        print("=" * 46)
        for hinweis in firewall.diagnose():
            print(f"  ! {hinweis}")
        ok, schritte = firewall.selftest()
        for schritt in schritte:
            print(f"  {'+' if ok else '-'} {schritt}")
        print()
        if ok:
            print("Ergebnis: Die Firewall-Anbindung funktioniert.")
            return 0
        print("Ergebnis: Die Anbindung funktioniert NICHT.", file=sys.stderr)
        return 1

    if args.limit_probe:
        return _limit_probe(config)

    if args.clear:
        blocked = firewall.list_blocked()
        if not args.yes:
            print(f"Das entfernt {len(blocked)} Eintrag/Eintraege aus der Firewall.")
            print("Die Sperren in LoginShield bleiben bestehen.")
            print("Zum Ausfuehren erneut mit --yes aufrufen.")
            return 0
        if firewall.clear():
            print("Firewall-Eintraege entfernt.")
            return 0
        print("Aufraeumen fehlgeschlagen.", file=sys.stderr)
        return 1

    # Standard: Status
    print("Firewall")
    print("=" * 46)
    print(f"  Backend           {status.backend}")
    print(f"  Verfuegbar        {'ja' if status.available else 'nein'}")
    print(f"  Eingerichtet      {'ja' if status.ready else 'nein'}")
    print(f"  In Konfiguration  {'aktiv' if was_enabled else 'aus'}")
    if status.dry_run:
        print("  Trockenlauf       ja (es wird nichts wirklich gesperrt)")
    print(f"  Eintraege         {len(status.blocked)}")

    hinweise = firewall.diagnose()
    for hinweis in hinweise:
        print(f"\n  ! {hinweis}")
    if not hinweise and status.note:
        print(f"\n  Hinweis: {status.note}")
    if status.ready:
        print("\n  Pruefen mit: loginshield firewall --selftest")
    if not was_enabled:
        print("\n  Die Firewall ist in der Konfiguration nicht aktiv.")
        print("  Sperren gelten derzeit nur innerhalb der Anwendung.")
    return 0


def _limit_probe(config, tage: float = 7.0) -> int:
    """Liest aus dem bisherigen Verkehr ab, welche Bremse gefahrlos waere.

    Eine Verbindungsbremse ist die einzige Einstellung dieses Programms,
    die im Zweifel echte Besucher aussperrt. Deshalb wird sie nicht
    geraten, sondern aus den eigenen Zahlen abgeleitet.

    Eine Einschraenkung, die man kennen muss: Gezaehlt wird, was die
    Anwendung gemeldet hat - Anfragen, nicht TCP-Verbindungen. Ein
    Browser oeffnet mehrere Verbindungen fuer eine Seite und nutzt sie
    dann fuer viele Anfragen. Die Zahl unten ist damit ein Anhaltspunkt,
    keine Messung. Der Vorschlag rechnet deshalb reichlich Luft dazu.
    """
    # Hier wird nur gelesen - die Firewall wird gar nicht angefasst.
    config.firewall.enabled = False
    guard = Guard(config)
    try:
        jetzt = guard.clock()
        profile = guard.store.profile_by_ip(jetzt - tage * 86400, jetzt)
        spitzen = []
        for ip, eintrag in profile.items():
            zeiten = sorted(eintrag.get("timestamps") or [])
            if len(zeiten) < 2:
                continue
            # Groesste Anzahl innerhalb einer Minute (gleitendes Fenster).
            hoechst, start = 0, 0
            for ende in range(len(zeiten)):
                while zeiten[ende] - zeiten[start] > 60:
                    start += 1
                hoechst = max(hoechst, ende - start + 1)
            spitzen.append((hoechst, ip))

        print("Verbindungsbremse - Anhaltspunkt aus dem eigenen Verkehr")
        print("=" * 58)
        if not spitzen:
            print("  Zu wenige Daten. Lass LoginShield erst einige Tage "
                  "mitlaufen.")
            return 0

        spitzen.sort(reverse=True)
        gemessen = spitzen[0][0]
        print(f"  Zeitraum            letzte {tage:.0f} Tage")
        print(f"  Adressen            {len(spitzen)}")
        print(f"  Hoechster Wert      {gemessen} Anfragen je Minute "
              f"({spitzen[0][1]})")
        if len(spitzen) > 1:
            print("  Die naechsten:")
            for wert, ip in spitzen[1:4]:
                print(f"    {wert:5d}  {ip}")

        vorschlag = max(60, int(gemessen * 3))
        print()
        print("  Vorschlag (dreifache Spitze, mindestens 60):")
        print("    firewall:")
        print("      conn_limit_enabled: true")
        print(f"      conn_limit_rate: {vorschlag}")
        print(f"      conn_limit_burst: {max(20, vorschlag // 3)}")
        print()
        print("  Gezaehlt wurden Anfragen, nicht Verbindungen - das ist ein")
        print("  Anhaltspunkt, keine Messung. Erst die eigene Adresse in die")
        print("  Allowlist, dann einschalten und die Seite selbst aufrufen.")
        return 0
    finally:
        guard.close()


def cmd_scan(args) -> int:
    guard = _guard(args)
    try:
        scanner = guard.filescan
        if not scanner.enabled:
            print("Die Dateipruefung ist abgeschaltet (malware.enabled).",
                  file=sys.stderr)
            return 1

        clam = scanner.clamav_binary()
        if not args.json:
            print(f"Pruefe {args.pfad}")
            hinweis = clam or ("nicht installiert - es wird nur mit den "
                               "eigenen Merkmalen geprueft")
            print(f"ClamAV: {hinweis}\n")

        if os.path.isdir(args.pfad):
            ergebnisse = scanner.scan_dir(args.pfad)
        else:
            einzeln = scanner.scan_file(args.pfad)
            ergebnisse = [] if einzeln.clean else [einzeln]

        if args.json:
            print(json.dumps([r.as_dict() for r in ergebnisse], indent=2,
                             ensure_ascii=False))
            return 1 if ergebnisse else 0

        if not ergebnisse:
            print("  Nichts gefunden.")
            return 0

        rows = [[r.verdict, r.score, os.path.relpath(r.path), r.summary[:52]]
                for r in sorted(ergebnisse, key=lambda r: -r.score)]
        print(_table(rows, ["Bewertung", "Punkte", "Datei", "Begruendung"]))

        if args.quarantine:
            print()
            for ergebnis in ergebnisse:
                if scanner.is_malicious(ergebnis):
                    ziel = guard.quarantine.store(ergebnis.path, ergebnis)
                    if ziel:
                        print(f"  beiseitegelegt: {os.path.relpath(ergebnis.path)}")
            print("\nZurueckholen mit: loginshield quarantine --list")
        else:
            print("\nBeiseitelegen mit: loginshield scan <pfad> --quarantine")
        return 1
    finally:
        guard.close()


def cmd_integrity(args) -> int:
    guard = _guard(args)
    try:
        monitor = guard.integrity
        pfade = args.path or list(monitor.config.paths)

        if args.status:
            status = monitor.status()
            if status["ready"]:
                print(f"Grundlage vorhanden: {status['files']} Dateien")
                print(f"Ueberwacht: {', '.join(status['paths']) or '-'}")
                return 0
            print(status["reason"], file=sys.stderr)
            return 1

        if not pfade:
            print("Kein Pfad angegeben. Entweder 'integrity.paths' in der "
                  "Konfiguration setzen oder --path benutzen.", file=sys.stderr)
            return 1

        if args.learn:
            print("Achtung: nur auf einem System lernen, das sauber ist.")
            print("Nach einem Einbruch gilt die Webshell sonst als normal.\n")
            anzahl = monitor.learn(pfade)
            print(f"Grundlage angelegt: {anzahl} Dateien aus "
                  f"{', '.join(pfade)}")
            return 0

        bericht = monitor.check(pfade)
        if args.json:
            print(json.dumps(bericht.as_dict(), indent=2, ensure_ascii=False))
            return 1 if bericht.changes else 0

        if bericht.error:
            print(bericht.error, file=sys.stderr)
            return 1

        print(f"Geprueft: {bericht.checked} Dateien")
        if not bericht.changes:
            print("  Unveraendert.")
            return 0

        print(f"\n{bericht.verdict.upper()} - {len(bericht.changes)} Veraenderung(en):\n")
        rows = [[c.kind, os.path.relpath(c.path), c.severity, c.description[:48]]
                for c in sorted(bericht.changes, key=lambda c: -c.severity)]
        print(_table(rows, ["Art", "Datei", "Schwere", "Bedeutung"]))
        return 1
    finally:
        guard.close()


def cmd_quarantine(args) -> int:
    guard = _guard(args)
    try:
        if args.restore:
            ziel = guard.quarantine.restore(args.restore)
            if ziel:
                print(f"Zurueckgeholt nach: {ziel}")
                return 0
            print(f"Nicht gefunden: {args.restore}", file=sys.stderr)
            return 1

        eintraege = guard.quarantine.list()
        if not eintraege:
            print("Die Quarantaene ist leer.")
            return 0
        rows = [
            [
                eintrag["id"],
                os.path.basename(eintrag.get("original", "?")),
                (eintrag.get("result") or {}).get("verdict", "-"),
                time.strftime("%d.%m. %H:%M",
                              time.localtime(eintrag.get("quarantined_ts", 0))),
            ]
            for eintrag in eintraege
        ]
        print(_table(rows, ["Kennung", "Datei", "Bewertung", "Seit"]))
        print("\nZurueckholen mit: loginshield quarantine --restore <Kennung>")
        return 0
    finally:
        guard.close()


def cmd_learn(args) -> int:
    guard = _guard(args)
    try:
        baseline = guard.anomaly.learn_and_store(days=args.days)
        tage = args.days or guard.config.anomaly.learn_days
        print(f"Normalzustand aus {tage:g} Tagen gelernt:")
        print(f"  Ereignisse            {baseline.ereignisse}")
        print(f"  Adressen              {baseline.adressen}")
        print(f"  Bekannte Pfade        {len(baseline.bekannte_pfade)}")
        print(f"  Bekannte Kennungen    {len(baseline.bekannte_kennungen)}")
        print(f"  Fehlerquote           {baseline.fehlerquote * 100:.1f}%")
        print(f"  Ereignisse je Adresse {baseline.ereignisse_je_ip_median:.0f} "
              f"(typisch)")
        print(f"  Aktive Stunden (UTC)  "
              f"{', '.join(str(h) for h in baseline.aktive_stunden) or '-'}")

        status = guard.anomaly.status()
        print()
        if status["ready"]:
            print("Die Datengrundlage reicht - Abweichungen werden ab jetzt bewertet.")
            print("Ansehen mit:  loginshield anomalies")
        else:
            print(f"Hinweis: {status['reason']}")
        return 0
    finally:
        guard.close()


def cmd_anomalies(args) -> int:
    guard = _guard(args)
    try:
        status = guard.anomaly.status()
        if not status["ready"]:
            print(status["reason"], file=sys.stderr)
            print("\nLieber keine Aussage als eine geratene.", file=sys.stderr)
            return 1

        gesamt = guard.anomaly.global_report(window=args.hours * 3600)
        berichte = guard.anomaly.scan(window=args.hours * 3600)
        if args.min_score is not None:
            berichte = [r for r in berichte if r.score >= args.min_score]

        if args.json:
            print(json.dumps(
                {"gesamt": gesamt.as_dict(),
                 "adressen": [r.as_dict() for r in berichte]},
                indent=2, ensure_ascii=False))
            return 0

        print(f"Abweichungen der letzten {args.hours:g} Stunden")
        print("=" * 46)
        print(f"Grundlinie: {status['events']} Ereignisse von {status['addresses']} "
              f"Adressen, {status['age_hours']:.0f}h alt\n")

        # Die Gesamtsicht zuerst: ein verteilter Angriff faellt bei keiner
        # einzelnen Adresse auf, in der Summe aber sehr wohl.
        if gesamt.signals:
            print(f"  GESAMTLAGE   {gesamt.score:.0f}/100   [{gesamt.verdict}]")
            for signal in gesamt.signals:
                print(f"     - {signal.erklaerung}  (+{signal.punkte:.0f})")
            print()

        if not berichte:
            if not gesamt.signals:
                print("  Nichts Auffaelliges.")
            else:
                print("  Keine einzelne Adresse faellt auf - der Angriff ist "
                      "auf viele verteilt.")
            return 0

        for report in berichte:
            print(f"  {report.ip}   {report.score:.0f}/100   [{report.verdict}]")
            for signal in report.signals:
                print(f"     - {signal.erklaerung}  (+{signal.punkte:.0f})")
            print()
        print(f"{len(berichte)} Adresse(n) auffaellig. Sperren mit: "
              f"loginshield block <IP>")
        return 0
    finally:
        guard.close()


def cmd_filter(args) -> int:
    guard = _guard(args)
    try:
        filt = guard.requestfilter

        if args.test:
            verdict = filt.explain(args.test)
            print(f"Geprueft: {args.test}\n")
            if verdict.clean:
                print("  Unauffaellig - keine Regel greift.")
                return 0
            rows = [[r.name, r.severity, r.description] for r in verdict.matched]
            print(_table(rows, ["Regel", "Schwere", "Bedeutung"]))
            print(f"\n  Summe: {verdict.score} (Schwelle: {filt.config.block_score})")
            if verdict.blocked:
                print(f"  -> Wuerde gesperrt ({filt.config.action})")
                return 1
            print("  -> Wird nur vermerkt, nicht gesperrt")
            return 0

        print(f"Anfrage-Firewall: {len(filt.rules)} Regeln, "
              f"Sperrschwelle {filt.config.block_score}, Modus {filt.config.action}\n")
        rows = [[r.name, r.severity, r.target, r.description] for r in filt.rules]
        print(_table(rows, ["Regel", "Schwere", "Prueft", "Bedeutung"]))
        print("\nEine URL pruefen:  loginshield filter --test \"/x?id=1' OR '1'='1\"")
        return 0
    finally:
        guard.close()


def cmd_honeypot(args) -> int:
    from .honeypot import HoneypotServer

    guard = _guard(args)
    try:
        honeypot = guard.honeypot

        if args.list:
            print(f"Koederpfade ({len(honeypot.traps)}), ein Treffer genuegt fuer "
                  f"{_fmt_duration(honeypot.config.block_seconds)} Sperre:\n")
            rows = [[trap.pattern, trap.kind] for trap in honeypot.traps]
            print(_table(rows, ["Pfad", "vorgetaeuschte Luecke"]))
            return 0

        if args.credentials:
            user, password = honeypot.credentials()
            print("Untergeschobene Zugangsdaten (Honeytoken):")
            print(f"  Benutzer:  {user}")
            print(f"  Passwort:  {password}")
            print("\nDiese Daten stehen in den gefaelschten Dateien und sind nirgends")
            print("gueltig. Taucht der Benutzername am echten Login auf, hat derjenige")
            print("die Koederdatei gelesen -> sofortige Sperre.")
            print("\nIm eigenen Login pruefen mit:")
            print("  if guard.honeypot.is_honeytoken(username):")
            print("      guard.record_honeypot(ip, reason='honeypot_token')")
            return 0

        if not honeypot.enabled:
            print("Der Honeypot ist in der Konfiguration abgeschaltet "
                  "(honeypot.enabled: false).", file=sys.stderr)
            return 1

        server = HoneypotServer(
            guard, honeypot, host=args.host, port=args.port,
            block_every_request=not args.only_traps,
        )
        print(f"Koeder-Server laeuft auf http://{args.host}:{server.port}/")
        print(f"Sperrdauer bei Treffer: {_fmt_duration(honeypot.config.block_seconds)}")
        if args.only_traps:
            print("Es werden nur bekannte Koederpfade gesperrt.")
        else:
            print("ACHTUNG: Jeder Zugriff auf diesen Port fuehrt zur Sperre.")
            print("Nur auf einem Port betreiben, den keine echte Anwendung nutzt.")
        print("Beenden mit Strg+C.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nKoeder-Server wird beendet ...")
        finally:
            server.stop()
        return 0
    finally:
        guard.close()


def cmd_demo(args) -> int:
    """Erzeugt realistisch aussehende Beispieldaten - nur zum Ausprobieren."""
    guard = _guard(args)
    try:
        now = time.time()
        rng = random.Random(20240815)
        # Nur fuer Dokumentation reservierte Bereiche (RFC 5737) - diese
        # Adressen gehoeren niemandem und beschuldigen keinen echten Betreiber.
        attackers = ["198.51.100.%d" % rng.randint(2, 250) for _ in range(6)]
        users = ["admin", "root", "info", "test", "backup", "postgres", "anna", "ben"]
        legit = ["203.0.113.%d" % rng.randint(2, 60) for _ in range(4)]

        store = guard.store
        for index in range(args.events):
            ts = now - rng.random() * 23 * 3600
            if rng.random() < 0.78:
                store.record_attempt(
                    rng.choice(attackers),
                    Event.LOGIN_FAILURE,
                    identity=rng.choice(users),
                    route="/login",
                    user_agent="python-requests/2.31",
                    source="demo",
                    detail="HTTP 401",
                    ts=ts,
                )
            else:
                store.record_attempt(
                    rng.choice(legit),
                    Event.LOGIN_SUCCESS,
                    identity=rng.choice(["anna", "ben"]),
                    route="/login",
                    user_agent="Mozilla/5.0",
                    source="demo",
                    ts=ts,
                )

        # Ein paar Scanner, die in den Honeypot getappt sind
        scanner_paths = ["/.env", "/wp-admin/setup-config.php", "/.git/config",
                         "/phpmyadmin/index.php", "/backup.sql"]
        for index, path in enumerate(scanner_paths):
            store.record_attempt(
                "192.0.2.%d" % (30 + index),
                Event.HONEYPOT,
                route=path,
                user_agent="Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                source="demo",
                detail=f"{Reason.HONEYPOT_PATH} Demo-Daten",
                ts=now - rng.random() * 6 * 3600,
            )
        guard.block("192.0.2.30", reason=Reason.HONEYPOT_PATH,
                    seconds=guard.config.honeypot.block_seconds, detail="/.env")

        for ip in attackers[:3]:
            guard.block(ip, reason=Reason.BRUTE_FORCE_IP, detail="Demo-Daten")

        print(f"{args.events} Beispielereignisse, 5 Honeypot-Treffer und "
              f"4 Sperren angelegt.")
        print("Jetzt ansehen mit:  loginshield status   oder   loginshield serve")
        return 0
    finally:
        guard.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
