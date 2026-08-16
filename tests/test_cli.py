import json
import os

import pytest

from loginshield.cli import main

#: 'loginshield demo' legt zusaetzlich zu --events so viele Honeypot-Treffer an.
DEMO_HONEYPOT_EVENTS = 5


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "cli.db")


def run(args, db=None):
    argv = list(args)
    if db:
        argv = ["--db", db] + argv
    return main(argv)


def test_ohne_befehl_zeigt_hilfe(capsys):
    assert main([]) == 0
    assert "loginshield" in capsys.readouterr().out


def test_init_schreibt_konfiguration(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    files = os.listdir(tmp_path)
    assert any(name.startswith("loginshield.") for name in files)

    # Token und HMAC-Schluessel wurden erzeugt und die Datei ist nicht lesbar fuer andere
    name = next(name for name in files if name.startswith("loginshield."))
    content = (tmp_path / name).read_text()
    assert "__TOKEN__" not in content and "__HMAC__" not in content
    assert oct(os.stat(tmp_path / name).st_mode)[-3:] == "600"

    # Ohne --force wird nicht ueberschrieben
    assert main(["init"]) == 1
    assert main(["init", "--force"]) == 0


def test_block_check_unblock(db, capsys):
    assert run(["block", "203.0.113.5", "--minutes", "30"], db) == 0
    assert "gesperrt" in capsys.readouterr().out

    assert run(["check", "203.0.113.5"], db) == 1  # gesperrt -> Exit 1
    assert "abgewiesen" in capsys.readouterr().out

    assert run(["unblock", "203.0.113.5"], db) == 0
    assert run(["check", "203.0.113.5"], db) == 0
    assert run(["unblock", "203.0.113.5"], db) == 1


def test_block_lehnt_unsinn_ab(db, capsys):
    assert run(["block", "keine-ip"], db) == 1
    assert "Fehler" in capsys.readouterr().err


def test_allowlist_befehle(db, capsys):
    assert run(["allow", "add", "10.0.0.0/8", "--note", "intern"], db) == 0
    assert run(["allow", "list"], db) == 0
    assert "10.0.0.0/8" in capsys.readouterr().out
    assert run(["allow", "remove", "10.0.0.0/8"], db) == 0
    assert run(["allow", "remove", "10.0.0.0/8"], db) == 1


def test_allow_add_hebt_sperre_auf(db, capsys):
    run(["block", "203.0.113.5", "--minutes", "30"], db)
    capsys.readouterr()
    run(["allow", "add", "203.0.113.5"], db)
    assert "Sperre wurde aufgehoben" in capsys.readouterr().out


def test_demo_und_status(db, capsys):
    assert run(["demo", "--events", "50"], db) == 0
    capsys.readouterr()

    assert run(["status"], db) == 0
    output = capsys.readouterr().out
    assert "Fehlversuche" in output
    assert "Aktive Sperren" in output

    assert run(["status", "--json"], db) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["failures"] > 0
    assert data["honeypot"] == DEMO_HONEYPOT_EVENTS
    assert data["active_blocks"] == 4  # 3x Brute Force + 1x Honeypot


def test_export_json_und_csv(db, tmp_path, capsys):
    run(["demo", "--events", "20"], db)
    capsys.readouterr()
    total = 20 + DEMO_HONEYPOT_EVENTS

    out = tmp_path / "export.json"
    assert run(["export", "--out", str(out)], db) == 0
    assert len(json.loads(out.read_text())) == total

    out_csv = tmp_path / "export.csv"
    assert run(["export", "--format", "csv", "--out", str(out_csv)], db) == 0
    lines = out_csv.read_text().strip().splitlines()
    assert lines[0].startswith("ts,ip,event")
    assert len(lines) == total + 1  # plus Kopfzeile


def test_prune(db, capsys):
    run(["demo", "--events", "10"], db)
    capsys.readouterr()
    assert run(["prune", "--days", "0.0001"], db) == 0
    assert "Geloeschte Ereignisse" in capsys.readouterr().out


def test_firewall_status(db, capsys):
    assert run(["firewall", "--status"], db) == 0
    output = capsys.readouterr().out
    assert "Backend" in output
    # Ohne Aktivierung in der Konfiguration muss der Hinweis kommen.
    assert "nicht aktiv" in output


def test_firewall_setup_trockenlauf(db, capsys, monkeypatch):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which", lambda binary: "/usr/sbin/" + binary)
    assert run(["firewall", "--setup", "--dry-run"], db) == 0
    output = capsys.readouterr().out
    assert "add table inet loginshield" in output
    assert "nichts geaendert" in output


def test_firewall_limit_probe_ohne_daten(db, capsys):
    assert run(["firewall", "--limit-probe"], db) == 0
    assert "Zu wenige Daten" in capsys.readouterr().out


def test_firewall_limit_probe_schlaegt_wert_vor(db, capsys):
    """Die Bremse wird nicht geraten, sondern aus dem Verkehr abgeleitet."""
    assert run(["demo"], db) == 0
    capsys.readouterr()
    assert run(["firewall", "--limit-probe"], db) == 0

    output = capsys.readouterr().out
    assert "conn_limit_rate:" in output
    # Die Einschraenkung muss dabeistehen - es ist kein Messwert.
    assert "Anfragen, nicht Verbindungen" in output


def test_firewall_clear_fragt_nach(db, capsys, monkeypatch):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which", lambda binary: None)
    assert run(["firewall", "--clear"], db) == 0
    assert "erneut mit --yes" in capsys.readouterr().out


def test_honeypot_liste(db, capsys):
    assert run(["honeypot", "--list"], db) == 0
    output = capsys.readouterr().out
    assert "/.env" in output
    assert "/wp-admin*" in output


def test_honeypot_zugangsdaten(db, capsys):
    assert run(["honeypot", "--credentials"], db) == 0
    output = capsys.readouterr().out
    assert "svc_backup" in output
    assert "is_honeytoken" in output  # Hinweis zur Einbindung


def test_honeypot_abgeschaltet(tmp_path, capsys):
    path = tmp_path / "aus.json"
    path.write_text('{"honeypot": {"enabled": false}}')
    assert main(["--config", str(path), "--db", str(tmp_path / "x.db"),
                 "honeypot"]) == 1
    assert "abgeschaltet" in capsys.readouterr().err


def test_watch_ohne_quellen(db, capsys):
    assert run(["watch"], db) == 1
    assert "Keine Logquellen" in capsys.readouterr().err


def test_config_fehler_wird_gemeldet(tmp_path, capsys):
    path = tmp_path / "kaputt.json"
    path.write_text('{"rules": {"ip_failure_threshold": 0}}')
    assert main(["--config", str(path), "status"]) == 2
    assert "Konfigurationsfehler" in capsys.readouterr().err


def test_learn_und_anomalies(db, capsys):
    import random
    import sys
    sys.path.insert(0, "/home/user/L-vi")
    from loginshield import Config, Guard
    from loginshield.models import Event
    from tests.test_anomaly import normalbetrieb

    config = Config()
    config.db_path = db
    guard = Guard(config)
    jetzt = guard.clock()
    normalbetrieb(guard.store, jetzt, rng=random.Random(3))
    for index in range(60):
        guard.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                   route=f"/admin/x{index}", ts=jetzt - 100)
    guard.close()

    assert run(["learn"], db) == 0
    ausgabe = capsys.readouterr().out
    assert "Normalzustand aus" in ausgabe
    assert "Die Datengrundlage reicht" in ausgabe

    assert run(["anomalies"], db) == 0
    ausgabe = capsys.readouterr().out
    assert "198.51.100.77" in ausgabe
    assert "/100" in ausgabe          # Punktwert
    assert "ueblich sind" in ausgabe  # Begruendung

    assert run(["anomalies", "--json"], db) == 0
    daten = json.loads(capsys.readouterr().out)
    # Neuer Aufbau: Gesamtlage und Einzeladressen getrennt.
    assert daten["adressen"][0]["signals"]
    assert "gesamt" in daten


def test_anomalies_ohne_grundlinie(db, capsys):
    assert run(["anomalies"], db) == 1
    fehler = capsys.readouterr().err
    assert "Noch keine Grundlinie" in fehler
    assert "Lieber keine Aussage als eine geratene" in fehler


def test_integrity_mit_pfad_prueft_auch_ohne_schalter(db, capsys, tmp_path):
    """Wer --path angibt, will die Pruefung jetzt.

    Vorher liess sich lernen, aber nicht nachsehen: Der Bericht meldete
    "nicht eingerichtet", obwohl gerade eine Grundlage angelegt worden war.
    """
    wurzel = tmp_path / "webroot"
    (wurzel / "uploads").mkdir(parents=True)
    (wurzel / "index.php").write_text("<?php echo 'hallo'; ?>")

    assert run(["integrity", "--learn", "--path", str(wurzel)], db) == 0
    capsys.readouterr()

    (wurzel / "uploads" / "bild.php").write_text("<?php ?>")
    run(["integrity", "--path", str(wurzel)], db)

    ausgabe = capsys.readouterr()
    assert "abgeschaltet" not in (ausgabe.out + ausgabe.err)
    assert "bild.php" in ausgabe.out
