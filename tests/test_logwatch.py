from loginshield.config import LogSourceConfig
from loginshield.logwatch import LogWatcher, Tailer, parse_line

SSHD = LogSourceConfig(path="dummy", format="sshd")
NGINX = LogSourceConfig(path="dummy", format="nginx")


def test_sshd_fehlversuch():
    line = ("Aug 15 10:22:31 srv sshd[2431]: Failed password for invalid user admin "
            "from 203.0.113.44 port 51234 ssh2")
    event = parse_line(line, SSHD)
    assert event.ip == "203.0.113.44"
    assert event.identity == "admin"
    assert event.success is False


def test_sshd_fehlversuch_echter_benutzer():
    line = "Aug 15 10:22:31 srv sshd[2431]: Failed password for root from 203.0.113.44 port 22 ssh2"
    event = parse_line(line, SSHD)
    assert (event.ip, event.identity, event.success) == ("203.0.113.44", "root", False)


def test_sshd_invalid_user():
    line = "Aug 15 10:22:31 srv sshd[2431]: Invalid user oracle from 198.51.100.3 port 40000"
    event = parse_line(line, SSHD)
    assert (event.ip, event.identity) == ("198.51.100.3", "oracle")


def test_sshd_erfolg():
    line = ("Aug 15 10:25:02 srv sshd[2500]: Accepted publickey for anna from 203.0.113.9 "
            "port 51235 ssh2: RSA SHA256:xyz")
    event = parse_line(line, SSHD)
    assert event.success is True
    assert event.identity == "anna"


def test_sshd_ipv6():
    line = "Aug 15 10:22:31 srv sshd[1]: Failed password for root from 2001:db8::5 port 22 ssh2"
    event = parse_line(line, SSHD)
    assert event.ip == "2001:db8::5"


def test_sshd_irrelevante_zeile():
    assert parse_line("Aug 15 10:00:00 srv systemd[1]: Started Daily apt.", SSHD) is None
    assert parse_line("", SSHD) is None


def test_nginx_fehlerstatus():
    line = ('203.0.113.77 - - [15/Aug/2026:10:00:01 +0000] "POST /login HTTP/1.1" '
            '401 153 "-" "curl/8.4"')
    event = parse_line(line, NGINX)
    assert event.ip == "203.0.113.77"
    assert event.success is False
    assert event.route == "/login"


def test_nginx_ok_ist_kein_ereignis():
    line = ('203.0.113.77 - - [15/Aug/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 512')
    assert parse_line(line, NGINX) is None


def test_nginx_pfadfilter():
    source = LogSourceConfig(path="dummy", format="nginx", path_filter="/admin")
    fail = ('203.0.113.77 - - [15/Aug/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 1')
    assert parse_line(fail, source) is None

    hit = ('203.0.113.77 - - [15/Aug/2026:10:00:01 +0000] "POST /admin/login HTTP/1.1" 403 1')
    assert parse_line(hit, source).success is False

    ok = ('203.0.113.77 - - [15/Aug/2026:10:00:01 +0000] "POST /admin/login HTTP/1.1" 200 1')
    assert parse_line(ok, source).success is True


def test_custom_pattern():
    source = LogSourceConfig(
        path="dummy",
        format="custom",
        pattern=r"LOGIN_FAIL user=(?P<identity>\S+) ip=(?P<ip>\S+)",
        success_pattern=r"LOGIN_OK user=(?P<identity>\S+) ip=(?P<ip>\S+)",
    )
    fail = parse_line("2026-08-15 LOGIN_FAIL user=bob ip=192.0.2.5", source)
    assert (fail.ip, fail.identity, fail.success) == ("192.0.2.5", "bob", False)

    ok = parse_line("2026-08-15 LOGIN_OK user=bob ip=192.0.2.5", source)
    assert ok.success is True
    assert parse_line("etwas anderes", source) is None


def test_tailer_liest_nur_neues(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("alte zeile\n", encoding="utf-8")

    tailer = Tailer(str(path))
    assert tailer.read_new() == []  # Bestand wird uebersprungen

    with open(path, "a", encoding="utf-8") as handle:
        handle.write("neue zeile\n")
    assert tailer.read_new() == ["neue zeile"]
    assert tailer.read_new() == []
    tailer.close()


def test_tailer_from_start(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("eins\nzwei\n", encoding="utf-8")
    tailer = Tailer(str(path), from_start=True)
    assert tailer.read_new() == ["eins", "zwei"]
    tailer.close()


def test_tailer_haelt_unvollstaendige_zeile_zurueck(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("", encoding="utf-8")
    tailer = Tailer(str(path))
    tailer.read_new()

    with open(path, "a", encoding="utf-8") as handle:
        handle.write("halbe ")
    assert tailer.read_new() == []
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("zeile\n")
    assert tailer.read_new() == ["halbe zeile"]
    tailer.close()


def test_tailer_erkennt_rotation(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("", encoding="utf-8")
    tailer = Tailer(str(path))
    tailer.read_new()

    with open(path, "a", encoding="utf-8") as handle:
        handle.write("vor rotation\n")
    assert tailer.read_new() == ["vor rotation"]

    # Rotation: Datei wird ersetzt
    (tmp_path / "app.log.1").write_bytes(path.read_bytes())
    path.unlink()
    path.write_text("nach rotation\n", encoding="utf-8")
    assert tailer.read_new() == ["nach rotation"]
    tailer.close()


def test_tailer_fehlende_datei(tmp_path):
    tailer = Tailer(str(tmp_path / "gibt-es-nicht.log"))
    assert tailer.read_new() == []


def test_watcher_meldet_an_guard(tmp_path, guard, config):
    path = tmp_path / "auth.log"
    path.write_text("", encoding="utf-8")
    source = LogSourceConfig(path=str(path), format="sshd")
    watcher = LogWatcher(guard, [source])
    watcher.poll_once()

    with open(path, "a", encoding="utf-8") as handle:
        for _ in range(config.rules.ip_failure_threshold):
            handle.write(
                "Aug 15 10:22:31 srv sshd[1]: Failed password for root "
                "from 203.0.113.44 port 22 ssh2\n"
            )

    handled = watcher.poll_once()
    assert handled == config.rules.ip_failure_threshold
    assert guard.store.active_block("203.0.113.44", now=guard.clock()) is not None
    watcher.close()


def test_watcher_meldet_fehlende_quellen(tmp_path, guard):
    source = LogSourceConfig(path=str(tmp_path / "weg.log"), format="sshd")
    watcher = LogWatcher(guard, [source])
    assert list(watcher.missing_sources()) == [source.path]
    watcher.close()
