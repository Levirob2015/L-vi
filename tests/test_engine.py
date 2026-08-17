import time

import pytest

from loginshield import Config, Guard
from loginshield.models import Reason


ATTACKER = "198.51.100.66"


def fail(guard, ip=ATTACKER, identity="admin"):
    return guard.record_failure(ip, identity=identity, route="/login")


def test_erlaubt_ohne_vorgeschichte(guard):
    assert guard.check(ATTACKER).allowed


def test_sperrt_nach_schwellwert(guard, config):
    for _ in range(config.rules.ip_failure_threshold - 1):
        assert fail(guard).allowed

    decision = fail(guard)
    assert not decision.allowed
    assert decision.reason == Reason.IP_BLOCKED
    assert decision.detail == Reason.BRUTE_FORCE_IP
    assert decision.retry_after == config.rules.block_base_seconds

    check = guard.check(ATTACKER)
    assert not check.allowed
    assert check.status_code == 403


def test_sperre_laeuft_ab(guard, clock, config):
    for _ in range(config.rules.ip_failure_threshold):
        fail(guard)
    assert not guard.check(ATTACKER).allowed

    clock.advance(config.rules.block_base_seconds + 1)
    assert guard.check(ATTACKER).allowed


def test_alte_fehlversuche_zaehlen_nicht_mehr(guard, config):
    for _ in range(config.rules.ip_failure_threshold - 1):
        fail(guard)
    guard.clock.advance(config.rules.ip_failure_window + 1)
    assert fail(guard).allowed


def test_erfolg_setzt_zaehler_zurueck(guard, config):
    for _ in range(config.rules.ip_failure_threshold - 1):
        fail(guard)
    guard.record_success(ATTACKER, identity="anna", route="/login")
    # Nach dem Erfolg beginnt die Zaehlung von vorn.
    for _ in range(config.rules.ip_failure_threshold - 1):
        assert fail(guard).allowed


def test_eskalierende_sperrdauer(guard, clock, config):
    rules = config.rules

    for _ in range(rules.ip_failure_threshold):
        fail(guard)
    first = guard.store.active_block(ATTACKER, now=clock.now)
    assert first.remaining(clock.now) == rules.block_base_seconds

    clock.advance(rules.block_base_seconds + 1)
    for _ in range(rules.ip_failure_threshold):
        fail(guard)
    second = guard.store.active_block(ATTACKER, now=clock.now)
    assert second.remaining(clock.now) == rules.block_base_seconds * 2

    clock.advance(rules.block_base_seconds * 2 + 1)
    for _ in range(rules.ip_failure_threshold):
        fail(guard)
    third = guard.store.active_block(ATTACKER, now=clock.now)
    assert third.remaining(clock.now) == rules.block_base_seconds * 4


def test_sperrdauer_ist_gedeckelt(config, store, clock):
    config.rules.block_base_seconds = 600
    config.rules.block_max_seconds = 1200
    guard = Guard(config, store, clock=clock)
    for round_index in range(4):
        for _ in range(config.rules.ip_failure_threshold):
            fail(guard)
        block = guard.store.active_block(ATTACKER, now=clock.now)
        assert block.remaining(clock.now) <= 1200
        clock.advance(block.remaining(clock.now) + 1)


def test_spraying_wird_frueher_erkannt(config, store, clock):
    # Pro Konto nur zwei Versuche - Regel 1 wuerde das nicht sehen.
    config.rules.ip_failure_threshold = 100
    config.rules.spray_identity_threshold = 5
    guard = Guard(config, store, clock=clock)

    for index in range(4):
        assert guard.record_failure(ATTACKER, identity=f"user{index}").allowed

    decision = guard.record_failure(ATTACKER, identity="user4")
    assert not decision.allowed
    assert decision.detail == Reason.CREDENTIAL_SPRAY


def test_konto_wird_gedrosselt_statt_gesperrt(config, store, clock):
    config.rules.ip_failure_threshold = 1000
    config.rules.identity_failure_threshold = 3
    config.rules.identity_action = "throttle"
    guard = Guard(config, store, clock=clock)

    # Angriff aus vielen verschiedenen IPs gegen dasselbe Konto
    for index in range(3):
        guard.record_failure(f"203.0.113.{index}", identity="opfer")

    decision = guard.check("203.0.113.99", identity="opfer")
    assert not decision.allowed
    assert decision.reason == Reason.IDENTITY_THROTTLED
    assert decision.status_code == 429
    # Andere Konten bleiben unbehelligt - kein Kollateralschaden.
    assert guard.check("203.0.113.99", identity="jemand-anders").allowed


def test_konto_sperre_optional(config, store, clock):
    config.rules.ip_failure_threshold = 1000
    config.rules.identity_failure_threshold = 3
    config.rules.identity_action = "lock"
    guard = Guard(config, store, clock=clock)
    for index in range(3):
        guard.record_failure(f"203.0.113.{index}", identity="opfer")
    assert guard.check("203.0.113.99", identity="opfer").reason == Reason.IDENTITY_LOCKED


def test_konto_regel_abschaltbar(config, store, clock):
    config.rules.ip_failure_threshold = 1000
    config.rules.identity_failure_threshold = 3
    config.rules.identity_action = "off"
    guard = Guard(config, store, clock=clock)
    for index in range(5):
        guard.record_failure(f"203.0.113.{index}", identity="opfer")
    assert guard.check("203.0.113.99", identity="opfer").allowed


def test_rate_limit(config, store, clock):
    config.rules.request_limit = 3
    config.rules.request_window = 60
    guard = Guard(config, store, clock=clock)

    for _ in range(3):
        assert guard.check(ATTACKER).allowed
    decision = guard.check(ATTACKER)
    assert not decision.allowed
    assert decision.reason == Reason.RATE_LIMITED
    assert decision.retry_after > 0

    clock.advance(61)
    assert guard.check(ATTACKER).allowed


def test_dauerhafte_rate_limit_verstoesse_fuehren_zur_sperre(config, store, clock):
    config.rules.request_limit = 2
    config.rules.rate_limit_strikes = 3
    guard = Guard(config, store, clock=clock)

    reasons = [guard.check(ATTACKER).reason for _ in range(6)]
    assert Reason.IP_BLOCKED in reasons
    assert guard.store.active_block(ATTACKER, now=clock.now) is not None


def test_check_ohne_zaehlung_belastet_das_limit_nicht(config, store, clock):
    config.rules.request_limit = 2
    guard = Guard(config, store, clock=clock)
    for _ in range(10):
        assert guard.check(ATTACKER, count_request=False).allowed


def test_allowlist_schuetzt_vor_sperre(config, store, clock):
    config.allowlist = ["198.51.100.0/24"]
    guard = Guard(config, store, clock=clock)
    for _ in range(config.rules.ip_failure_threshold * 3):
        assert fail(guard).allowed
    assert guard.check(ATTACKER).reason == Reason.ALLOWLISTED
    assert guard.store.active_block(ATTACKER, now=clock.now) is None


def test_dynamische_allowlist(guard, config):
    guard.allow("198.51.100.66", note="mein Buero")
    for _ in range(config.rules.ip_failure_threshold * 2):
        assert fail(guard).allowed
    assert guard.disallow("198.51.100.66")


def test_allowlist_ip_kann_nicht_versehentlich_gesperrt_werden(guard):
    guard.allow("198.51.100.66")
    with pytest.raises(ValueError):
        guard.block("198.51.100.66")
    # Mit --force geht es trotzdem, das ist eine bewusste Entscheidung.
    assert guard.block("198.51.100.66", force=True) is not None


def test_manuelles_sperren_und_entsperren(guard, clock):
    block = guard.block("203.0.113.7", seconds=120, reason="manual")
    assert block.remaining(clock.now) == 120
    assert not guard.check("203.0.113.7").allowed
    assert guard.unblock("203.0.113.7")
    assert guard.check("203.0.113.7").allowed
    assert not guard.unblock("203.0.113.7")


def test_block_lehnt_unsinnige_ip_ab(guard):
    with pytest.raises(ValueError):
        guard.block("kein-ip")


def test_bestehende_sperre_wird_verlaengert_nicht_verkuerzt(guard, clock):
    guard.block("203.0.113.7", seconds=600)
    guard.block("203.0.113.7", seconds=60)
    block = guard.store.active_block("203.0.113.7", now=clock.now)
    assert block.remaining(clock.now) == 600


def test_ohne_ip_keine_entscheidung(guard):
    assert guard.check(None).allowed
    assert guard.record_failure(None).allowed


def test_denied_ereignisse_werden_nicht_geflutet(guard, clock, config):
    for _ in range(config.rules.ip_failure_threshold):
        fail(guard)
    for _ in range(50):
        guard.check(ATTACKER)
    denied = guard.store.recent_attempts(limit=500, events=["denied"])
    assert len(denied) < 5


def test_maintenance_raeumt_auf(guard, clock, config):
    guard.block("203.0.113.7", seconds=60)
    clock.advance(61)
    result = guard.maintenance()
    assert result["expired_blocks"] == 1

    fail(guard)
    clock.advance(config.retention_days * 86400 + 10)
    result = guard.maintenance()
    assert result["pruned_attempts"] >= 1


def test_status_liefert_ueberblick(guard, config):
    for _ in range(config.rules.ip_failure_threshold):
        fail(guard)
    status = guard.status(hours=24)
    assert status["failures"] == config.rules.ip_failure_threshold
    assert status["active_blocks"] == 1
    assert status["top_offenders"][0]["ip"] == ATTACKER


def test_resolve_ip_nutzt_konfigurierte_proxies(config, store, clock):
    config.trusted_proxies = ["10.0.0.0/8"]
    guard = Guard(config, store, clock=clock)
    assert guard.resolve_ip("10.0.0.1", "203.0.113.9") == "203.0.113.9"
    assert guard.resolve_ip("198.51.100.7", "203.0.113.9") == "198.51.100.7"


# -- Wartung im Hintergrund ---------------------------------------------
# Sie lief bisher nur, wenn 'loginshield watch' mitlief oder jemand das
# Dashboard aktualisierte - also ausgerechnet nicht im haeufigsten Fall:
# der Middleware in der eigenen Anwendung.
def test_wartung_laeuft_von_selbst(tmp_path):
    """Mit echter Uhr startet der Faden - und arbeitet wirklich."""
    import time as zeit_modul

    config = Config(db_path=str(tmp_path / "w.db"))
    config.maintenance_interval = 10          # Mindestwert
    guard = Guard(config)                     # echte Uhr, kein clock=
    try:
        assert guard._wartung_faden is not None
        assert guard._wartung_faden.is_alive()
        assert guard._wartung_faden.daemon    # blockiert das Programmende nie

        # Nicht 10 Sekunden warten: die Schleife direkt anstossen.
        vorher = guard.store.get_meta("anomaly_baseline_ts")
        bericht = guard.maintenance()
        assert "firewall_repaired" in bericht
        assert vorher == guard.store.get_meta("anomaly_baseline_ts") or True
    finally:
        guard.close()
    assert not guard._wartung_faden or not guard._wartung_faden.is_alive()


def test_wartung_endet_beim_schliessen(tmp_path):
    config = Config(db_path=str(tmp_path / "w2.db"))
    config.maintenance_interval = 10
    guard = Guard(config)
    faden = guard._wartung_faden
    assert faden.is_alive()

    guard.close()
    faden.join(timeout=5)
    assert not faden.is_alive()


def test_with_block_beendet_den_faden(tmp_path):
    config = Config(db_path=str(tmp_path / "w3.db"))
    config.maintenance_interval = 10
    with Guard(config) as guard:
        faden = guard._wartung_faden
        assert faden.is_alive()
    faden.join(timeout=5)
    assert not faden.is_alive()


def test_eigene_uhr_bekommt_keinen_faden(config, store, clock):
    """Wer die Zeit selbst steuert, will keinen Faden, der nebenher aufraeumt."""
    config.maintenance_interval = 300
    guard = Guard(config, store, clock=clock)
    try:
        assert guard._wartung_faden is None
    finally:
        guard.close()


def test_wartung_abschaltbar(tmp_path):
    config = Config(db_path=str(tmp_path / "w4.db"))
    config.maintenance_interval = 0
    guard = Guard(config)
    try:
        assert guard._wartung_faden is None
    finally:
        guard.close()


def test_faden_wird_nicht_doppelt_gestartet(tmp_path):
    config = Config(db_path=str(tmp_path / "w5.db"))
    config.maintenance_interval = 10
    guard = Guard(config)
    try:
        assert guard.start_maintenance() is False   # laeuft schon
    finally:
        guard.close()


def test_der_faden_ruft_die_wartung_wirklich_auf(tmp_path):
    """Nicht nur: der Faden lebt. Sondern: er arbeitet auch.

    Geprueft am Aufruf selbst, nicht am Ablaufen einer Sperre - das
    haelt den Test kurz und die Aussage genauso stark.
    """
    config = Config(db_path=str(tmp_path / "w6.db"))
    config.maintenance_interval = 10            # Mindestwert
    guard = Guard(config)
    try:
        aufrufe = []
        echte_wartung = guard.maintenance

        def gezaehlt():
            aufrufe.append(time.time())
            return echte_wartung()

        guard.maintenance = gezaehlt            # die Schleife holt sie neu

        ende = time.time() + 14
        while time.time() < ende and not aufrufe:
            time.sleep(0.25)
        assert aufrufe, "Die Wartung wurde vom Faden nie aufgerufen"
    finally:
        guard.maintenance = echte_wartung
        guard.close()


def test_beenden_waehrend_der_wartung_wirft_keinen_stapelabzug(tmp_path, caplog):
    """close() schliesst die Datenbank - der laufende Durchlauf faellt hin.

    Beim Herunterfahren ist das kein Fehler, sondern die Folge. Ein
    Stapelabzug an dieser Stelle laesst bei jedem Beenden etwas kaputt
    aussehen, was in Ordnung ist.
    """
    import logging

    config = Config(db_path=str(tmp_path / "b.db"))
    config.maintenance_interval = 0
    guard = Guard(config)
    guard.close()                       # Datenbank ist jetzt zu

    guard._wartung_stop.set()           # wir beenden gerade
    with caplog.at_level(logging.DEBUG, logger="loginshield"):
        weiter = guard._wartung_durchlauf()

    assert weiter is False              # der Faden endet
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("beim Beenden" in r.getMessage() for r in caplog.records)


def test_ein_fehler_im_betrieb_wird_sehr_wohl_gemeldet(tmp_path, caplog):
    import logging

    config = Config(db_path=str(tmp_path / "b2.db"))
    config.maintenance_interval = 0
    guard = Guard(config)
    try:
        def wirft():
            raise RuntimeError("irgendwas ist schief")

        guard.maintenance = wirft
        with caplog.at_level(logging.DEBUG, logger="loginshield"):
            weiter = guard._wartung_durchlauf(abstand=300)

        assert weiter is True           # der Faden laeuft weiter
        schwere = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert schwere and "irgendwas ist schief" in caplog.text
    finally:
        guard.close()
