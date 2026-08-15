import json

import pytest

from loginshield.config import Config, ConfigError, find_config, load_config


def test_defaults_sind_gueltig():
    Config().validate()


def test_from_dict_mit_unterobjekten():
    config = Config.from_dict({
        "db_path": "x.db",
        "allowlist": ["10.0.0.0/8"],
        "rules": {"ip_failure_threshold": 3},
        "dashboard": {"port": 9000},
        "logwatch": [{"path": "/var/log/auth.log", "format": "sshd"}],
    })
    assert config.rules.ip_failure_threshold == 3
    assert config.dashboard.port == 9000
    assert config.logwatch[0].format == "sshd"


def test_unbekannte_felder_fliegen_auf():
    with pytest.raises(ConfigError):
        Config.from_dict({"tippfehlr": 1})
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"gibt_es_nicht": 1}})


def test_ungueltige_schwellwerte():
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"ip_failure_threshold": 0}})
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"block_base_seconds": 100, "block_max_seconds": 10}})
    with pytest.raises(ConfigError):
        Config.from_dict({"rules": {"identity_action": "quatsch"}})


def test_dashboard_ohne_token_nur_lokal():
    # Ohne Token darf das Dashboard nicht ins Netz gehaengt werden.
    with pytest.raises(ConfigError):
        Config.from_dict({"dashboard": {"host": "0.0.0.0"}})
    Config.from_dict({"dashboard": {"host": "0.0.0.0", "token": "geheim"}})


def test_firewall_erkennt_backend_automatisch():
    # Ohne Angabe wird das Backend erkannt - kein Pflichtfeld mehr.
    config = Config.from_dict({"firewall": {"enabled": True}})
    assert config.firewall.backend == "auto"


def test_firewall_command_backend_braucht_kommando():
    with pytest.raises(ConfigError):
        Config.from_dict({"firewall": {"enabled": True, "backend": "command"}})


def test_logwatch_validierung():
    with pytest.raises(ConfigError):
        Config.from_dict({"logwatch": [{"path": "/x", "format": "custom"}]})
    with pytest.raises(ConfigError):
        Config.from_dict({"logwatch": [{"path": "", "format": "sshd"}]})


def test_env_ueberschreibt_datei():
    config = Config()
    config.apply_env({
        "LOGINSHIELD_DB": "/tmp/env.db",
        "LOGINSHIELD_TOKEN": "env-token",
        "LOGINSHIELD_HMAC_KEY": "env-key",
    })
    assert config.db_path == "/tmp/env.db"
    assert config.dashboard.token == "env-token"
    assert config.identity_hmac_key == "env-key"


def test_json_datei_laden(tmp_path):
    path = tmp_path / "loginshield.json"
    path.write_text(json.dumps({"db_path": "abc.db", "rules": {"ip_failure_threshold": 7}}))
    config = load_config(str(path))
    assert config.db_path == "abc.db"
    assert config.rules.ip_failure_threshold == 7


def test_yaml_datei_laden(tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "loginshield.yaml"
    path.write_text(yaml.safe_dump({"db_path": "y.db", "allowlist": ["127.0.0.1"]}))
    config = load_config(str(path))
    assert config.db_path == "y.db"
    assert config.allowlist == ["127.0.0.1"]


def test_fehlende_datei():
    with pytest.raises(ConfigError):
        load_config("/gibt/es/nicht.yaml")


def test_find_config(tmp_path):
    assert find_config(str(tmp_path)) is None
    (tmp_path / "loginshield.json").write_text("{}")
    assert find_config(str(tmp_path)).endswith("loginshield.json")
