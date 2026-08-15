import json
import os

import pytest

from loginshield.cli import main


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
    assert data["active_blocks"] == 3


def test_export_json_und_csv(db, tmp_path, capsys):
    run(["demo", "--events", "20"], db)
    capsys.readouterr()

    out = tmp_path / "export.json"
    assert run(["export", "--out", str(out)], db) == 0
    assert len(json.loads(out.read_text())) == 20

    out_csv = tmp_path / "export.csv"
    assert run(["export", "--format", "csv", "--out", str(out_csv)], db) == 0
    lines = out_csv.read_text().strip().splitlines()
    assert lines[0].startswith("ts,ip,event")
    assert len(lines) == 21


def test_prune(db, capsys):
    run(["demo", "--events", "10"], db)
    capsys.readouterr()
    assert run(["prune", "--days", "0.0001"], db) == 0
    assert "Geloeschte Ereignisse" in capsys.readouterr().out


def test_watch_ohne_quellen(db, capsys):
    assert run(["watch"], db) == 1
    assert "Keine Logquellen" in capsys.readouterr().err


def test_config_fehler_wird_gemeldet(tmp_path, capsys):
    path = tmp_path / "kaputt.json"
    path.write_text('{"rules": {"ip_failure_threshold": 0}}')
    assert main(["--config", str(path), "status"]) == 2
    assert "Konfigurationsfehler" in capsys.readouterr().err
