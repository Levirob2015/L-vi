import time

from loginshield.models import Event
from loginshield.store import Store


def test_identity_wird_gehasht(store):
    key = store.identity_key("Anna")
    assert key.startswith("user:")
    assert "anna" not in key
    # Gross-/Kleinschreibung darf keine zwei Identitaeten erzeugen
    assert key == store.identity_key("anna ")


def test_identity_modi(tmp_path):
    plain = Store(str(tmp_path / "p.db"), identity_mode="plain")
    assert plain.identity_key("anna") == "anna"
    plain.close()

    none = Store(str(tmp_path / "n.db"), identity_mode="none")
    assert none.identity_key("anna") == ""
    none.close()


def test_hmac_schluessel_aendert_hash(tmp_path):
    a = Store(str(tmp_path / "a.db"), identity_hmac_key="key-a")
    b = Store(str(tmp_path / "b.db"), identity_hmac_key="key-b")
    assert a.identity_key("anna") != b.identity_key("anna")
    a.close()
    b.close()


def test_zaehler_ab_letztem_erfolg(store):
    store.record_attempt("1.2.3.4", Event.LOGIN_FAILURE, ts=100)
    store.record_attempt("1.2.3.4", Event.LOGIN_FAILURE, ts=101)
    assert store.count_failures_by_ip("1.2.3.4", since=0) == 2

    store.record_attempt("1.2.3.4", Event.LOGIN_SUCCESS, ts=102)
    store.record_attempt("1.2.3.4", Event.LOGIN_FAILURE, ts=103)
    assert store.count_failures_by_ip("1.2.3.4", since=0) == 1


def test_distinct_identities(store):
    for name in ("a", "b", "c", "a"):
        store.record_attempt("1.2.3.4", Event.LOGIN_FAILURE, identity=name, ts=100)
    assert store.distinct_identities_by_ip("1.2.3.4", since=0) == 3


def test_sperre_wird_verlaengert_statt_dupliziert(store):
    store.add_block("1.2.3.4", seconds=60, reason="x", now=1000)
    store.add_block("1.2.3.4", seconds=600, reason="y", now=1000)
    blocks = store.list_blocks(now=1000)
    assert len(blocks) == 1
    assert blocks[0].expires_ts == 1600


def test_abgelaufene_sperre_ist_inaktiv(store):
    store.add_block("1.2.3.4", seconds=60, reason="x", now=1000)
    assert store.active_block("1.2.3.4", now=1030) is not None
    assert store.active_block("1.2.3.4", now=1100) is None
    assert store.expire_blocks(now=1100) == ["1.2.3.4"]
    assert store.expire_blocks(now=1100) == []


def test_prior_block_count(store):
    store.add_block("1.2.3.4", seconds=60, reason="x", now=1000)
    store.unblock("1.2.3.4")
    store.add_block("1.2.3.4", seconds=60, reason="x", now=2000)
    assert store.prior_block_count("1.2.3.4", since=0) == 2
    assert store.prior_block_count("1.2.3.4", since=1500) == 1


def test_allowlist_crud(store):
    store.allow_add("10.0.0.0/8", note="intern", now=1000)
    assert store.allow_list()[0]["cidr"] == "10.0.0.0/8"
    assert store.allow_remove("10.0.0.0/8")
    assert not store.allow_remove("10.0.0.0/8")
    assert store.allow_list() == []


def test_stats_und_timeline(store):
    for index in range(5):
        store.record_attempt("1.2.3.4", Event.LOGIN_FAILURE, ts=1000 + index)
    store.record_attempt("5.6.7.8", Event.LOGIN_SUCCESS, ts=1002)
    store.add_block("1.2.3.4", seconds=600, reason="brute", now=1005)

    stats = store.stats(since=0, now=1010)
    assert stats["failures"] == 5
    assert stats["successes"] == 1
    assert stats["attacking_ips"] == 1
    assert stats["active_blocks"] == 1

    timeline = store.failure_timeline(since=999, buckets=4, now=1011)
    assert sum(bucket["failures"] for bucket in timeline) == 5


def test_top_offenders_sortiert(store):
    for _ in range(3):
        store.record_attempt("1.1.1.1", Event.LOGIN_FAILURE, ts=1000)
    store.record_attempt("2.2.2.2", Event.LOGIN_FAILURE, ts=1000)
    top = store.top_offenders(since=0, limit=5)
    assert [row["ip"] for row in top] == ["1.1.1.1", "2.2.2.2"]
    assert top[0]["failures"] == 3


def test_prune_loescht_altes(store):
    store.record_attempt("1.1.1.1", Event.LOGIN_FAILURE, ts=100)
    store.record_attempt("1.1.1.1", Event.LOGIN_FAILURE, ts=5000)
    attempts, _ = store.prune(before=1000)
    assert attempts == 1
    assert len(store.recent_attempts(limit=10)) == 1


def test_recent_attempts_filter(store):
    store.record_attempt("1.1.1.1", Event.LOGIN_FAILURE, ts=100)
    store.record_attempt("2.2.2.2", Event.LOGIN_SUCCESS, ts=200)
    assert len(store.recent_attempts(limit=10, events=[Event.LOGIN_FAILURE])) == 1
    assert len(store.recent_attempts(limit=10, ip="2.2.2.2")) == 1
    assert len(store.recent_attempts(limit=10, since=150)) == 1


def test_datenbank_ist_nicht_world_readable(tmp_path):
    import os
    import stat

    path = str(tmp_path / "perm.db")
    store = Store(path)
    store.close()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0


# -- Aufraeumen in Haeppchen ---------------------------------------------
# Ein DELETE ueber alles haelt die einzige Datenbanksperre so lange, wie
# das Loeschen dauert - und in dieser Zeit wartet jede Anfrage. Gemessen
# an 60.000 Ereignissen: 175 ms, in denen ein Login stand.
def test_prune_loescht_vollstaendig_trotz_haeppchen(store):
    jetzt = 1_700_000_000.0
    for index in range(250):
        store.record_attempt(f"198.51.100.{index % 250}", Event.LOGIN_FAILURE,
                             ts=jetzt - 10_000)
    store.record_attempt("203.0.113.1", Event.LOGIN_FAILURE, ts=jetzt)

    attempts, _ = store.prune(jetzt - 5_000, batch=17)
    assert attempts == 250
    # Der neue Eintrag ist noch da.
    assert store.count_failures_by_ip("203.0.113.1", jetzt - 100) == 1


def test_prune_mit_haeppchengroesse_eins(store):
    jetzt = 1_700_000_000.0
    for _ in range(5):
        store.record_attempt("198.51.100.1", Event.LOGIN_FAILURE, ts=jetzt - 10_000)
    assert store.prune(jetzt - 5_000, batch=1)[0] == 5


class ZaehlendeSperre:
    """Zaehlt, wie oft die Datenbanksperre genommen wird."""

    def __init__(self, echt):
        self.echt = echt
        self.anzahl = 0

    def __enter__(self):
        self.anzahl += 1
        return self.echt.__enter__()

    def __exit__(self, *fehler):
        return self.echt.__exit__(*fehler)


def test_prune_gibt_die_sperre_je_haeppchen_ab(store):
    """Es gibt genau eine Datenbankverbindung mit einer Sperre. Wird sie
    einmal genommen und bis zum Ende gehalten, wartet jede Anfrage so
    lange, wie das Loeschen dauert.

    Geprueft wird deshalb der Mechanismus, nicht die Zeit: Wie oft wird die
    Sperre genommen und wieder abgegeben? Die beiden Vorlaeufer dieses
    Tests haben Zeiten gemessen - erst die Zahl der Zwischenzugriffe, dann
    die laengste Wartezeit. Beides scheiterte auf fremder Hardware, weil
    dort die Prozessverwaltung des Systems mitgemessen wird und nicht nur
    dieses Programm. Die Wirkung in Millisekunden steht als Messung in
    Store.prune; hier steht, was ueberpruefbar ist.
    """
    jetzt = 1_700_000_000.0
    for index in range(2000):
        store.record_attempt(f"198.51.100.{index % 250}", Event.LOGIN_FAILURE,
                             ts=jetzt - 10_000)

    zaehler = ZaehlendeSperre(store._lock)
    store._lock = zaehler
    try:
        entfernt, _ = store.prune(jetzt - 5_000, batch=200)
    finally:
        store._lock = zaehler.echt

    assert entfernt == 2000
    # 10 Haeppchen a 200, ein leerer Nachlauf, dazu das Loeschen der
    # Sperren - jedes Mal wird die Sperre neu genommen.
    assert zaehler.anzahl >= 10, (
        f"Sperre nur {zaehler.anzahl}x genommen - wird sie ueber das ganze "
        f"Loeschen gehalten?"
    )


def test_prune_in_einem_zug_waere_eine_einzige_sperre(store):
    """Zum Vergleich: Mit einem Haeppchen so gross wie alles bleibt es bei
    zwei Sperren - genau der Zustand, der die Anfragen aufhielt."""
    jetzt = 1_700_000_000.0
    for index in range(500):
        store.record_attempt("198.51.100.1", Event.LOGIN_FAILURE, ts=jetzt - 10_000)

    zaehler = ZaehlendeSperre(store._lock)
    store._lock = zaehler
    try:
        store.prune(jetzt - 5_000, batch=100_000)
    finally:
        store._lock = zaehler.echt
    assert zaehler.anzahl == 2


def test_pause_ist_eine_echte_pause():
    """sleep(0) genuegt nicht - auf Python 3.9 wirkt es gar nicht.

    Diese Zeile ist der Unterschied zwischen 17 ms und 517 ms Wartezeit
    auf 3.9. Sie soll nicht versehentlich wieder zu sleep(0) werden.
    """
    from loginshield.store import PRUNE_PAUSE

    assert PRUNE_PAUSE > 0
