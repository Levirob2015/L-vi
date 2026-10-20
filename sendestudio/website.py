"""Die ganze Website unter einer Adresse.

    /                  Startseite: Sendungen, Roboter-Designer, Studio, Leitstand
    /sendungen/        alle Sendungen (oeffentlich)
    /zeitung/          die Zeitung: alle Ausgaben, zum Drucken (oeffentlich)
    /s/<sendung>/...   Sendungen, Folgen, Radio, Feeds (oeffentlich)
    /roboter/          ProBot Roboter-Designer (oeffentlich, abgeschottet)
    /studio            Sendestudio (Anmeldung)
    /leitstand/        Hack-Schutz-Leitstand von LoginShield (Anmeldung)

**Roboter-Designer, abgeschottet.** Die Seite bringt eigene Skripte mit und
speichert den Anthropic-Schluessel des Besuchers im Browser. Sie laeuft
deshalb mit ``Content-Security-Policy: sandbox``: Der Browser behandelt sie
wie eine fremde Website - sie kommt weder an das Anmelde-Cookie noch an die
Studio-Schnittstelle. Der Preis: Sie kann im Browser nichts dauerhaft
speichern (Schluessel und letztes Projekt muessen neu eingegeben werden).
Wer das moechte, gibt dem Designer eine eigene Unteradresse (siehe
``deploy/Caddyfile``).

**Leitstand.** Der LoginShield-Leitstand laeuft im selben Prozess, lauscht
nur auf 127.0.0.1 und ist von aussen nicht erreichbar. Das Studio reicht
Anfragen an ``/leitstand/`` nur nach Anmeldung durch und setzt den
Zugangsschluessel selbst ein - im Browser taucht er nie auf. Eine Anmeldung
(Passwort, ggf. Zwei-Faktor) gilt damit fuer die ganze Website.
"""

from __future__ import annotations

import html
import logging
import os
import re
import secrets
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import radio
from .feed import dauer_text
from .site import datum

log = logging.getLogger("sendestudio.website")

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ROBOTER_DATEI = os.path.join(STATIC, "roboter.html")

#: Navigation der oeffentlichen Seiten - Pfade relativ zur Wurzel.
NAVIGATION: List[Tuple[str, str]] = [
    ("Start", ""), ("Sendungen", "sendungen/"), ("Zeitung", "zeitung/"), ("Roboter-Designer", "roboter/"),
    ("Studio", "studio"),
]

#: Was der Roboter-Designer laden darf. ``sandbox`` ohne ``allow-same-origin``
#: gibt der Seite einen eigenen, fremden Ursprung (siehe oben).
CSP_ROBOTER = (
    "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox "
    "allow-downloads allow-modals allow-top-navigation-by-user-activation; "
    "default-src 'none'; "
    "script-src 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "
    "style-src 'unsafe-inline'; img-src data: blob: https:; font-src data:; "
    "connect-src https://api.anthropic.com https://de.wikipedia.org https://cdn.jsdelivr.net "
    "https://huggingface.co https://*.huggingface.co https://*.hf.co https://raw.githubusercontent.com; "
    "worker-src blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_ZURUECK = (
    '<a href="/" target="_top" style="position:fixed;z-index:2147483647;left:12px;bottom:12px;'
    'font:600 14px system-ui,sans-serif;background:#1c1a17;color:#fff;text-decoration:none;'
    'padding:8px 14px;border-radius:999px;box-shadow:0 2px 10px rgba(0,0,0,.25)">← Startseite</a>'
)


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


# ----------------------------------------------------------------------
# Roboter-Designer
# ----------------------------------------------------------------------
_roboter_cache: Dict[str, Any] = {}


def roboter_seite() -> Optional[bytes]:
    """Die Seite des Roboter-Designers mit Zurueck-Knopf, oder ``None``."""
    try:
        stand = os.path.getmtime(ROBOTER_DATEI)
    except OSError:
        return None
    if _roboter_cache.get("stand") != stand:
        with open(ROBOTER_DATEI, encoding="utf-8") as f:
            text = f.read()
        # Nach dem <body>-Tag einen Weg zurueck zur Startseite einfuegen.
        text = re.sub(r"(<body[^>]*>)", lambda m: m.group(1) + _ZURUECK, text, count=1)
        _roboter_cache.update(stand=stand, inhalt=text.encode("utf-8"))
    return _roboter_cache["inhalt"]


_RUECKWEG_LEITSTAND = (
    '<nav style="display:flex;gap:16px;padding:8px 16px;font:600 14px system-ui,sans-serif;'
    'background:#1c1a17"><a href="/studio" style="color:#fb923c;text-decoration:none">← Studio</a>'
    '<a href="/" style="color:#d6d0c4;text-decoration:none">Startseite</a></nav>'
)


def mit_rueckweg(seite: bytes) -> bytes:
    """Fuegt in die Leitstand-Seite Links zurueck zu Studio und Startseite ein."""
    return re.sub(rb"(<body[^>]*>)", lambda m: m.group(1) + _RUECKWEG_LEITSTAND.encode(), seite,
                  count=1)


# ----------------------------------------------------------------------
# Leitstand (LoginShield-Dashboard im selben Prozess)
# ----------------------------------------------------------------------
class Leitstand:
    def __init__(self, guard: Any) -> None:
        from loginshield.config import DashboardConfig
        from loginshield.dashboard import Dashboard

        self.token = secrets.token_urlsafe(32)
        self._dashboard = Dashboard(guard, DashboardConfig(
            host="127.0.0.1", port=0, token=self.token, allow_mutations=True))
        self._dashboard.start_background()
        self.basis = f"http://127.0.0.1:{self._dashboard.port}"

    def stop(self) -> None:
        self._dashboard.stop()

    def weiterreichen(self, methode: str, pfad: str, koerper: Optional[bytes],
                      typ: Optional[str]) -> Tuple[int, str, bytes]:
        """Reicht eine Anfrage an das Dashboard durch. Gibt (Status, Typ, Inhalt)."""
        kopf = {"X-Auth-Token": self.token}
        if typ:
            kopf["Content-Type"] = typ
        req = urllib.request.Request(self.basis + pfad, data=koerper, headers=kopf, method=methode)
        # Kein Proxy - das Dashboard lauscht nur lokal.
        oeffner = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with oeffner.open(req, timeout=30) as antwort:
                return antwort.status, antwort.headers.get("Content-Type", ""), antwort.read()
        except urllib.error.HTTPError as f:
            return f.code, f.headers.get("Content-Type", ""), f.read()


# ----------------------------------------------------------------------
# Startseite
# ----------------------------------------------------------------------
def portal(seitentitel: str, beschreibung: str, eintraege: List[Dict[str, Any]],
           *, roboter: bool, leitstand: bool) -> str:
    """Die Startseite der Website. ``eintraege``: Sendungen mit veroeffentlichten Folgen."""
    neueste = sorted(((s, f) for s in eintraege for f in s["folgen"]),
                     key=lambda sf: sf[1]["veroeffentlicht"], reverse=True)[:5]
    radio_sendung = next((s for s in eintraege if s["art"] == "radio" and radio.programm(s["folgen"])),
                         None)
    folgen_html = "".join(
        f'<li><a href="s/{_e(s["slug"])}/{_e(f["slug"])}/">{_e(f["titel"])}</a>'
        f'<span class="leise">{_e(s["titel"])} · {datum(f["veroeffentlicht"])}'
        f'{" · " + dauer_text(f["dauer"]) if f["dauer"] else ""}</span></li>'
        for s, f in neueste)
    bereiche = [
        f"""<div class="karte bereich"><span class="symbol" aria-hidden="true">🎙</span>
<h2>Sendungen</h2><p>Podcasts, Radio und Dokumentationen – zum Hören, Ansehen und Abonnieren.</p>
<a class="knopf" href="sendungen/">Alle Sendungen</a>
{f'<a class="knopf zweit" href="s/{_e(radio_sendung["slug"])}/radio/">Radio live hören</a>' if radio_sendung else ""}
</div>"""]
    bereiche.append("""<div class="karte bereich"><span class="symbol" aria-hidden="true">📰</span>
<h2>Zeitung</h2><p>Artikel mit Bildern, gesetzt wie eine richtige Zeitung – zum Lesen und mit einem Knopf zum Ausdrucken.</p>
<a class="knopf" href="zeitung/">Zeitung lesen</a></div>""")
    if roboter:
        bereiche.append("""<div class="karte bereich"><span class="symbol" aria-hidden="true">🤖</span>
<h2>Roboter-Designer</h2><p>Roboter beschreiben – und Zeichnung, Teileliste, Bauanleitung, Code und 3D-Druckteile bekommen.</p>
<a class="knopf" href="roboter/">Roboter entwerfen</a></div>""")
    bereiche.append(f"""<div class="karte bereich"><span class="symbol" aria-hidden="true">🎛</span>
<h2>Studio</h2><p>Aufnehmen, mit Musik und KI bearbeiten und veröffentlichen{" – und im Leitstand sehen, wer versucht einzubrechen" if leitstand else ""}. Nur nach Anmeldung.</p>
<a class="knopf zweit" href="studio">Anmelden</a></div>""")
    inhalt = f"""<div class="portal-kopf"><h1>{_e(seitentitel)}</h1>
{f"<p>{_e(beschreibung)}</p>" if beschreibung else ""}</div>
<div class="bereiche">{"".join(bereiche)}</div>
<h2>Neu</h2>
{f'<ul class="neu">{folgen_html}</ul>' if folgen_html else '<p class="leise">Hier erscheinen die neuesten Folgen, sobald etwas veröffentlicht ist.</p>'}"""
    from .site import _rahmen  # gemeinsamer Seitenrahmen
    return _rahmen(seitentitel, inhalt, 0, seitentitel=seitentitel, beschreibung=beschreibung,
                   nav=NAVIGATION, nav_aktiv="")
