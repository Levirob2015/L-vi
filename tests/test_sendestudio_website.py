"""Sendestudio als ganze Website: Startseite, Roboter-Designer, Leitstand."""

import http.client
import json
import os

import pytest

from sendestudio import website

from test_sendestudio import Client, wav_bytes
from test_sendestudio_sicherheit import Laufend


@pytest.fixture
def lauf(tmp_path):
    l = Laufend(tmp_path)
    yield l
    l.stoppen()


def test_startseite_und_sendungen(lauf):
    c = lauf.client()
    _, s = c.json("POST", "/api/sendungen", {"titel": "Nachtfunk", "art": "radio"})
    _, f = c.json("POST", f"/api/sendungen/{s['id']}/folgen", {"titel": "Erste Stunde"})
    c("PUT", f"/api/folgen/{f['id']}/medium?dauer=2", roh=wav_bytes(2.0))
    c.json("POST", f"/api/folgen/{f['id']}/veroeffentlichen")

    anonym = Client(lauf.basis)
    status, seite, kopf = anonym("GET", "/")
    text = seite.decode()
    assert status == 200
    for erwartet in ('href="sendungen/"', 'href="roboter/"', 'href="studio"', "Erste Stunde",
                     'href="s/nachtfunk/radio/"', 'aria-label="Website"'):
        assert erwartet in text, erwartet
    assert "script-src 'self'" in kopf["Content-Security-Policy"]

    status, seite, _ = anonym("GET", "/sendungen/")
    assert status == 200 and b'href="../s/nachtfunk/"' in seite and b'aria-current="page"' in seite
    assert anonym("GET", "/sendungen")[0] in (200, 301)
    # Die Sendungsseiten tragen die Navigation der Website
    assert b'class="nav"' in anonym("GET", "/s/nachtfunk/")[1]


def test_ohne_website_nur_sendungen(tmp_path):
    l = Laufend(tmp_path, website=False)
    try:
        anonym = Client(l.basis)
        assert b"Roboter" not in anonym("GET", "/")[1]
        assert anonym("GET", "/roboter/")[0] == 404
        assert anonym("GET", "/leitstand/")[0] == 404
        assert l.studio.leitstand is None
    finally:
        l.stoppen()


def test_roboter_designer_abgeschottet(lauf):
    if website.roboter_seite() is None:
        pytest.skip("roboter.html fehlt")
    status, seite, kopf = Client(lauf.basis)("GET", "/roboter/")
    assert status == 200 and b"ProBot" in seite
    csp = kopf["Content-Security-Policy"]
    # Eigener, fremder Ursprung: kein Zugriff auf Studio-Cookie und -API
    assert csp.startswith("sandbox ") and "allow-same-origin" not in csp
    assert "frame-ancestors 'none'" in csp
    assert b"\xe2\x86\x90 Startseite" in seite  # der Weg zurueck


def test_leitstand_nur_angemeldet(lauf):
    anonym = Client(lauf.basis)
    status, seite, _ = anonym("GET", "/leitstand/")
    assert status == 401 and b"/studio" in seite
    assert anonym("GET", "/leitstand/api/summary")[0] == 401

    c = lauf.client()
    status, seite, kopf = c("GET", "/leitstand/")
    assert status == 200 and b"LoginShield" in seite and b'href="/studio"' in seite
    # Der Zugangsschluessel des Dashboards erscheint nie im Browser
    assert lauf.studio.leitstand.token.encode() not in seite
    assert "script-src 'unsafe-inline'" in kopf["Content-Security-Policy"]

    status, daten = c.json("GET", "/leitstand/api/summary?hours=24")
    assert status == 200 and "stats" in daten

    # Aendern nur mit der Kennung, die die Leitstand-Seite immer mitschickt
    assert c("POST", "/leitstand/api/block", {"ip": "203.0.113.9"},
             kopf={"X-Studio": ""})[0] == 403
    status, inhalt, _ = c("POST", "/leitstand/api/block", {"ip": "203.0.113.9", "seconds": 60},
                          kopf={"X-Auth-Token": ""})
    assert status == 200, inhalt
    assert lauf.studio.guard.check("203.0.113.9", count_request=False).allowed is False


def test_leitstand_lauscht_nur_lokal(lauf):
    host, port = lauf.studio.leitstand.basis[len("http://"):].split(":")
    assert host == "127.0.0.1"
    # Ohne Schluessel gibt das Dashboard selbst nichts heraus
    v = http.client.HTTPConnection(host, int(port), timeout=5)
    v.request("GET", "/api/summary")
    assert v.getresponse().status == 401


def test_studio_status_kennt_die_website(lauf):
    c = lauf.client()
    w = c.json("GET", "/api/status")[1]["website"]
    assert w["aktiv"] and w["leitstand"]
