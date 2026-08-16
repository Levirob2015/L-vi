"""Anomalie-Erkennung: lernt den Normalzustand, meldet Abweichungen.

Der wichtigste Teil dieser Tests ist nicht, dass Angriffe erkannt werden -
sondern dass normaler Verkehr in Ruhe gelassen wird und bei zu duenner
Datenlage gar nicht erst geurteilt wird.
"""

import random

import pytest

from loginshield import Guard
from loginshield.anomaly import (
    AnomalyDetector,
    Baseline,
    entropy,
    learn,
    mad,
    median,
    robust_z,
)
from loginshield.config import Config, ConfigError
from loginshield.models import Event

SEITEN = ["/", "/login", "/produkte", "/kontakt", "/impressum", "/blog"]
BROWSER = ["Mozilla/5.0 (Macintosh) Safari/605", "Mozilla/5.0 (Windows) Chrome/120"]


def normalbetrieb(store, jetzt, tage=7, rng=None):
    """Eine Woche unauffaelliger Verkehr: tagsueber, gemischte Seiten."""
    rng = rng or random.Random(42)
    for tag in range(tage):
        for stunde in range(8, 20):
            for _ in range(rng.randint(8, 16)):
                ts = jetzt - (tage - tag) * 86400 + stunde * 3600 + rng.random() * 3600
                erfolg = rng.random() > 0.12
                store.record_attempt(
                    f"203.0.113.{rng.randint(2, 90)}",
                    Event.LOGIN_SUCCESS if erfolg else Event.LOGIN_FAILURE,
                    identity=rng.choice(["anna", "ben", "clara"]),
                    route=rng.choice(SEITEN),
                    user_agent=rng.choice(BROWSER),
                    ts=ts,
                )


@pytest.fixture
def gelernt(config, store, clock):
    """Guard mit einer Woche gelerntem Normalbetrieb."""
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    guard.anomaly.learn_and_store(days=7)
    return guard


# -- Statistische Grundlagen --------------------------------------------
def test_median():
    assert median([1, 2, 3]) == 2
    assert median([1, 2, 3, 4]) == 2.5
    assert median([]) == 0.0


def test_mad_ist_robust_gegen_ausreisser():
    normal = [10, 11, 9, 10, 12, 10]
    mit_ausreisser = normal + [10000]
    # Genau darum geht es: ein einzelner Angriff darf die Grundlinie nicht
    # verschieben, sonst gilt er hinterher als normal.
    assert abs(mad(normal) - mad(mit_ausreisser)) <= 1


def test_robust_z():
    assert robust_z(10, 10, 2) == 0
    assert robust_z(20, 10, 2) > 3
    # Ohne Streuung darf der Wert nicht ins Unendliche laufen.
    assert robust_z(1000, 10, 0) <= 10


def test_entropy():
    assert entropy([1, 1, 1, 1]) == pytest.approx(2.0)   # gleichverteilt
    assert entropy([10, 0, 0, 0]) == 0.0                 # nur ein Wert
    assert entropy([]) == 0.0


# -- Lernen --------------------------------------------------------------
def test_lernt_den_normalzustand(config, store, clock):
    normalbetrieb(store, clock.now)
    baseline = learn(store, days=7, now=clock.now)

    assert baseline.ereignisse > 500
    assert baseline.adressen > 50
    assert set(baseline.bekannte_pfade) == set(SEITEN)
    assert 0.05 < baseline.fehlerquote < 0.2
    # Nachts passiert nichts - das muss die Grundlinie widerspiegeln.
    assert 3 not in baseline.aktive_stunden


def test_grundlinie_wird_gespeichert_und_gelesen(gelernt):
    gespeichert = gelernt.store.get_meta("anomaly_baseline")
    assert gespeichert

    # Ein frischer Detektor findet sie wieder.
    frisch = AnomalyDetector(gelernt.config.anomaly, gelernt)
    assert frisch.ready()


# -- Zurueckhaltung bei duenner Datenlage --------------------------------
def test_urteilt_nicht_ohne_grundlinie(config, store, clock):
    guard = Guard(config, store, clock=clock)
    assert not guard.anomaly.ready()
    status = guard.anomaly.status()
    assert status["ready"] is False
    assert "Noch keine Grundlinie" in status["reason"]
    assert guard.anomaly.scan() == []


def test_urteilt_nicht_bei_zu_wenig_daten(config, store, clock):
    guard = Guard(config, store, clock=clock)
    for index in range(20):                       # viel zu wenig
        store.record_attempt(f"203.0.113.{index}", Event.LOGIN_SUCCESS,
                             route="/", ts=clock.now - 100)
    guard.anomaly.learn_and_store(days=7)

    status = guard.anomaly.status()
    assert status["ready"] is False
    assert "zu duenn" in status["reason"]
    # Und es wird auch wirklich nichts gemeldet.
    assert guard.anomaly.scan() == []


# -- Erkennung -----------------------------------------------------------
def test_erkennt_langsames_abklappern(gelernt, clock):
    """Der Fall, den keine feste Regel sieht: 60 Zugriffe ueber 25 Minuten
    liegen unter jeder Schwelle."""
    for index in range(60):
        gelernt.store.record_attempt(
            "198.51.100.77", Event.LOGIN_FAILURE, route=f"/admin/panel{index}",
            user_agent=BROWSER[0], ts=clock.now - 1800 + index * 25,
        )
    berichte = gelernt.anomaly.scan(window=3600)
    treffer = [r for r in berichte if r.ip == "198.51.100.77"]
    assert treffer, "Abklappern nicht erkannt"
    assert treffer[0].verdict == "kritisch"

    namen = {s.name for s in treffer[0].signals}
    assert "pfadvielfalt" in namen
    assert "neue_pfade" in namen


def test_erkennt_maschinellen_takt_trotz_erfolgreicher_logins(gelernt, clock):
    # Erfolgreiche Logins - keine Fehlversuchsregel greift hier.
    for index in range(40):
        gelernt.store.record_attempt(
            "198.51.100.88", Event.LOGIN_SUCCESS, route="/", identity="anna",
            user_agent="Go-http-client/2.0", ts=clock.now - 600 + index * 1.2,
        )
    treffer = [r for r in gelernt.anomaly.scan(window=3600) if r.ip == "198.51.100.88"]
    assert treffer
    namen = {s.name for s in treffer[0].signals}
    assert "takt" in namen
    assert "kennung" in namen


def test_normaler_besucher_wird_nicht_gemeldet(gelernt, clock):
    for index in range(6):
        gelernt.store.record_attempt(
            "203.0.113.44", Event.LOGIN_SUCCESS, identity="ben",
            route=SEITEN[index % len(SEITEN)], user_agent=BROWSER[0],
            ts=clock.now - 900 + index * 120,
        )
    gemeldet = {r.ip for r in gelernt.anomaly.scan(window=3600)}
    assert "203.0.113.44" not in gemeldet


def test_ganzer_normalbetrieb_ohne_fehlalarm(config, store, clock):
    """Die harte Probe: derselbe Verkehr, aus dem gelernt wurde, darf
    hinterher nicht selbst auffallen."""
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now, rng=random.Random(7))
    guard.anomaly.learn_and_store(days=7)

    berichte = guard.anomaly.scan(window=12 * 3600)
    assert berichte == [], f"Fehlalarme: {[r.ip for r in berichte]}"


def test_allowlist_wird_uebergangen(config, store, clock):
    config.allowlist = ["198.51.100.0/24"]
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    guard.anomaly.learn_and_store(days=7)

    for index in range(60):
        store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                             route=f"/x{index}", ts=clock.now - 100)
    assert [r for r in guard.anomaly.scan(window=3600) if r.ip == "198.51.100.77"] == []


# -- Nachvollziehbarkeit -------------------------------------------------
def test_jede_meldung_ist_begruendet(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    for report in gelernt.anomaly.scan(window=3600):
        assert report.signals, "Punktwert ohne Begruendung"
        for signal in report.signals:
            assert signal.erklaerung
            assert signal.punkte > 0
        # Der Punktwert ist die Summe der Signale, nichts Verstecktes.
        summe = sum(s.punkte for s in report.signals)
        assert report.score == pytest.approx(min(100.0, summe))


def test_bericht_als_json(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    daten = gelernt.anomaly.scan(window=3600)[0].as_dict()
    assert daten["ip"] == "198.51.100.77"
    assert daten["verdict"] in ("auffaellig", "kritisch")
    assert daten["signals"] and daten["summary"]


# -- Handeln -------------------------------------------------------------
def test_meldet_standardmaessig_nur(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    gelernt.anomaly.evaluate()

    # Kein Sperren - eine statistische Abweichung ist ein Verdacht.
    assert gelernt.store.active_block("198.51.100.77", now=clock.now) is None
    vermerke = gelernt.store.recent_attempts(limit=10, events=[Event.SUSPICIOUS])
    assert any("Anomalie" in v.detail for v in vermerke)


def test_sperrt_wenn_ausdruecklich_gewuenscht(config, store, clock):
    config.anomaly.action = "block"
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    guard.anomaly.learn_and_store(days=7)

    for index in range(60):
        store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                             route=f"/admin/x{index}", ts=clock.now - 100)
    guard.anomaly.evaluate()
    assert guard.store.active_block("198.51.100.77", now=clock.now) is not None


def test_abschaltbar(config, store, clock):
    config.anomaly.enabled = False
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    guard.anomaly.learn_and_store(days=7)
    assert guard.anomaly.scan() == []


# -- Konfiguration -------------------------------------------------------
def test_ungueltige_konfiguration():
    with pytest.raises(ConfigError):
        Config.from_dict({"anomaly": {"action": "quatsch"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"anomaly": {"report_score": 0}})
    with pytest.raises(ConfigError):
        # Sperren unterhalb der Meldeschwelle waere widersinnig.
        Config.from_dict({"anomaly": {"report_score": 80, "block_score": 50}})
    with pytest.raises(ConfigError):
        Config.from_dict({"anomaly": {"learn_days": 0}})


def test_baseline_serialisierung():
    baseline = Baseline(created_ts=1.0, ereignisse=100, adressen=10)
    wieder = Baseline.from_dict(baseline.as_dict())
    assert wieder.ereignisse == 100
    # Unbekannte Felder aus einer aelteren Version stoeren nicht.
    assert Baseline.from_dict({"ereignisse": 5, "gibt_es_nicht": 1}).ereignisse == 5


# -- Automatischer Betrieb ----------------------------------------------
def test_maintenance_prueft_von_selbst(config, store, clock):
    """Der wichtigste Punkt: ohne diesen Weg liefe die Erkennung nur, wenn
    jemand von Hand nachsieht - action: block kaeme nie zustande."""
    config.anomaly.action = "block"
    config.anomaly.evaluate_interval = 300
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    guard.anomaly.learn_and_store(days=7)

    for index in range(60):
        store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                             route=f"/admin/x{index}", ts=clock.now - 100)

    ergebnis = guard.maintenance()
    assert ergebnis["anomalies"] >= 1
    assert guard.store.active_block("198.51.100.77", now=clock.now) is not None


def test_maintenance_haelt_das_intervall_ein(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    assert gelernt.maintenance()["anomalies"] >= 1
    # Direkt danach nicht noch einmal - das waere reine Rechenlast.
    assert gelernt.maintenance()["anomalies"] == 0

    clock.advance(gelernt.config.anomaly.evaluate_interval + 1)
    assert gelernt.maintenance()["anomalies"] >= 1


def test_grundlinie_wird_aufgefrischt(config, store, clock):
    config.anomaly.relearn_hours = 24
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)

    # Erster Lauf lernt selbst, ohne dass jemand 'learn' tippt.
    assert guard.maintenance()["baseline_relearned"] is True
    assert guard.anomaly.ready()

    # Innerhalb der 24 Stunden nicht erneut.
    assert guard.maintenance()["baseline_relearned"] is False
    clock.advance(24 * 3600 + 1)
    assert guard.maintenance()["baseline_relearned"] is True


def test_automatik_abschaltbar(config, store, clock):
    config.anomaly.evaluate_interval = 0
    config.anomaly.relearn_hours = 0
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)
    ergebnis = guard.maintenance()
    assert ergebnis["anomalies"] == 0
    assert ergebnis["baseline_relearned"] is False


def test_fehler_in_der_auswertung_stoppt_die_wartung_nicht(gelernt, monkeypatch):
    def kaputt(**kwargs):
        raise RuntimeError("absichtlich")

    monkeypatch.setattr(gelernt.anomaly, "maintain", kaputt)
    ergebnis = gelernt.maintenance()          # darf nicht durchschlagen
    assert "pruned_attempts" in ergebnis
    assert ergebnis["anomalies"] == 0


def test_zwischenspeicher_entlastet_das_dashboard(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    erste = gelernt.anomaly.cached_scan(window=3600)
    assert erste

    # Neue Ereignisse - der Zwischenspeicher liefert trotzdem das alte
    # Ergebnis, solange er gilt.
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.99", Event.LOGIN_FAILURE,
                                     route=f"/y{index}", ts=clock.now - 50)
    assert gelernt.anomaly.cached_scan(window=3600) is erste

    clock.advance(gelernt.config.anomaly.cache_seconds + 1)
    danach = gelernt.anomaly.cached_scan(window=3600)
    assert {r.ip for r in danach} == {"198.51.100.77", "198.51.100.99"}


def test_lernen_leert_den_zwischenspeicher(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 100)
    gelernt.anomaly.cached_scan(window=3600)
    gelernt.anomaly.learn_and_store(days=7)
    assert gelernt.anomaly._cache is None


# -- Gesamtsicht: verteilte Angriffe ------------------------------------
def test_verteilter_angriff_faellt_einzeln_nicht_auf(gelernt, clock):
    """Der blinde Fleck jeder Einzelbewertung: 200 Adressen mit je fuenf
    Fehlversuchen - keine davon ist auffaellig, die Summe sehr wohl."""
    for index in range(200):
        for versuch in range(5):
            gelernt.store.record_attempt(
                f"198.51.100.{index % 250}", Event.LOGIN_FAILURE,
                identity="admin", route="/login", user_agent=BROWSER[0],
                ts=clock.now - 1800 + index * 8 + versuch,
            )

    einzeln = gelernt.anomaly.scan(window=3600)
    assert einzeln == [], "Einzelbewertung sollte hier nichts finden"

    gesamt = gelernt.anomaly.global_report(window=3600)
    assert gesamt.verdict == "kritisch"
    namen = {s.name for s in gesamt.signals}
    assert "verteilte_last" in namen
    assert "gesamtlast" in namen


def test_gesamtsicht_schweigt_im_normalbetrieb(gelernt):
    gesamt = gelernt.anomaly.global_report(window=3600)
    assert gesamt.signals == []
    assert gesamt.score == 0


def test_gesamtsicht_ohne_grundlinie(config, store, clock):
    guard = Guard(config, store, clock=clock)
    assert guard.anomaly.global_report().signals == []


# -- Neue Einzelsignale -------------------------------------------------
def test_erkennt_langsamen_aber_exakten_takt(gelernt, clock):
    """Alle 30 Sekunden - viel zu langsam fuer die Geschwindigkeitspruefung,
    aber unmenschlich gleichmaessig."""
    for index in range(60):
        gelernt.store.record_attempt(
            "198.51.100.55", Event.LOGIN_SUCCESS, identity="anna", route="/",
            user_agent=BROWSER[1], ts=clock.now - 1800 + index * 30,
        )
    treffer = [r for r in gelernt.anomaly.scan(window=3600)
               if r.ip == "198.51.100.55"]
    assert treffer
    namen = {s.name for s in treffer[0].signals}
    assert "regelmaessigkeit" in namen
    # Die alte Geschwindigkeitspruefung haette hier nichts gesehen.
    assert "takt" not in namen


def test_regelmaessigkeit_verschont_menschliches_verhalten():
    import random as _random

    from loginshield.anomaly import regelmaessigkeit

    rng = _random.Random(4)
    # Ein Mensch: mal schnell, mal Pause.
    menschlich = [0.0]
    for _ in range(30):
        menschlich.append(menschlich[-1] + rng.choice([1, 2, 3, 20, 45, 90]))
    assert regelmaessigkeit(menschlich) > 0.5

    # Ein Programm: exakt alle 30 Sekunden.
    maschinell = [index * 30.0 for index in range(30)]
    assert regelmaessigkeit(maschinell) < 0.05

    assert regelmaessigkeit([1, 2]) is None       # zu wenig Daten


def test_pfadstreuung_unterscheidet_scan_von_besuch(gelernt, clock):
    # Scanner: 20 Pfade je einmal - gleichmaessig verteilt.
    for index in range(20):
        gelernt.store.record_attempt("198.51.100.61", Event.LOGIN_FAILURE,
                                     route=f"/{SEITEN[index % len(SEITEN)]}{index}",
                                     ts=clock.now - 600 + index * 20)
    treffer = [r for r in gelernt.anomaly.scan(window=3600)
               if r.ip == "198.51.100.61"]
    assert treffer


# -- Beweislast ----------------------------------------------------------
def test_wenige_ereignisse_koennen_nicht_kritisch_sein(gelernt, clock):
    """Drei sehr ungewoehnliche Zugriffe sind noch kein Angriff."""
    for index in range(3):
        gelernt.store.record_attempt(
            "198.51.100.66", Event.LOGIN_FAILURE, route=f"/geheim{index}",
            user_agent="Go-http-client/2.0", ts=clock.now - 100 + index,
        )
    treffer = [r for r in gelernt.anomaly.scan(window=3600)
               if r.ip == "198.51.100.66"]
    assert treffer == [], "Zu wenige Belege fuer eine Meldung"


def test_beweislast_waechst_mit_den_belegen(gelernt, clock):
    for index in range(60):
        gelernt.store.record_attempt("198.51.100.77", Event.LOGIN_FAILURE,
                                     route=f"/x{index}", ts=clock.now - 1000 + index)
    treffer = [r for r in gelernt.anomaly.scan(window=3600)
               if r.ip == "198.51.100.77"][0]
    assert treffer.evidence == 60
    assert treffer.confidence == 1.0


# -- Sauberes Lernen -----------------------------------------------------
def test_gesperrte_adressen_fliessen_nicht_in_die_grundlinie(config, store, clock):
    """Sonst lernt die Grundlinie den Angriff als normal - und erkennt ihn
    beim naechsten Mal nicht mehr."""
    guard = Guard(config, store, clock=clock)
    normalbetrieb(store, clock.now)

    sauber = guard.anomaly.learn_and_store(days=7)

    for index in range(300):
        store.record_attempt("203.0.113.250", Event.LOGIN_FAILURE,
                             route=f"/x{index}", ts=clock.now - 3 * 86400 + index * 10)
    guard.block("203.0.113.250", seconds=3600)
    danach = guard.anomaly.learn_and_store(days=7)

    assert danach.ausgeschlossen == 1
    # Der Angriff hat den Normalzustand nicht verschoben.
    assert danach.ereignisse_je_ip_median == sauber.ereignisse_je_ip_median
    assert "203.0.113.250" not in danach.bekannte_pfade
