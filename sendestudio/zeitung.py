"""Die Zeitung: Ausgaben gesetzt wie eine gedruckte Zeitung.

Eine Ausgabe hat einen Kopf (Name, Untertitel, Nummer, Datum) und Artikel.
Der erste Artikel ist der Aufmacher und steht gross oben, die uebrigen
laufen in Spalten darunter. Dasselbe HTML zeigt das Studio als Vorschau,
die Website als Seite - und der Drucker als Zeitung auf A4: Beim Drucken
verschwinden Kopfleiste, Knoepfe und Fusszeile.

Alles hier wird aus dem Inhalt der Ausgabe gebaut und immer maskiert; Bilder
sind nur die vom Studio vergebenen Namen (``store.ZEITUNG_BILD``).
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

#: Aussehen der Zeitung - in ``stil.css`` (Website) und ``/zeitung.css`` (Studio).
STIL = """\
/* Zeitung: wie Papier, auch im dunklen Modus */
.zeitung{--papier:#fbf8f1;--tinte:#151310;--grau:#5d574d;--strich:#1e1b17;
background:var(--papier);color:var(--tinte);padding:28px 30px 34px;border-radius:4px;
box-shadow:0 1px 3px rgba(0,0,0,.18),0 10px 30px rgba(0,0,0,.08);
font:16px/1.5 Georgia,"Times New Roman",Times,serif;text-align:left}
.zeitung *{color:inherit}
.zeitung .z-kopf{text-align:center;border-bottom:4px double var(--strich);padding-bottom:8px;margin-bottom:18px}
.zeitung .z-zeile{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
font:600 .78rem/1.3 system-ui,sans-serif;letter-spacing:.08em;text-transform:uppercase;
color:var(--grau);border-bottom:1px solid var(--strich);padding-bottom:6px}
.zeitung .z-name{font:900 clamp(2.1rem,7vw,4rem)/1 "Old English Text MT","UnifrakturMaguntia",
Georgia,"Times New Roman",serif;margin:12px 0 6px;letter-spacing:.01em;overflow-wrap:anywhere}
.zeitung .z-untertitel{font-style:italic;color:var(--grau);margin:0}
.zeitung article{margin:0 0 18px}
.zeitung .z-rubrik{font:700 .72rem/1.2 system-ui,sans-serif;letter-spacing:.12em;
text-transform:uppercase;color:#9a3412;margin:0 0 4px}
.zeitung h2{font:800 1.35rem/1.15 Georgia,"Times New Roman",serif;margin:0 0 6px;break-after:avoid}
.zeitung .z-unterzeile{font-style:italic;margin:0 0 6px;color:var(--grau);break-after:avoid}
.zeitung .z-autor{font:600 .78rem/1.3 system-ui,sans-serif;color:var(--grau);margin:0 0 8px}
.zeitung .z-text p{margin:0 0 .55em;text-align:justify;hyphens:auto;-webkit-hyphens:auto}
.zeitung .z-text p+p{text-indent:1.2em}
.zeitung figure{margin:0 0 10px;break-inside:avoid}
.zeitung figure img{display:block;width:100%;height:auto;border:1px solid #d6d0c4}
.zeitung figcaption{font:.78rem/1.35 system-ui,sans-serif;color:var(--grau);margin-top:4px}
.zeitung .z-aufmacher{border-bottom:1px solid var(--strich);padding-bottom:16px;margin-bottom:18px}
.zeitung .z-aufmacher h2{font-size:clamp(1.7rem,4.5vw,2.6rem);line-height:1.08}
.zeitung .z-aufmacher .z-unterzeile{font-size:1.12rem}
.zeitung .z-aufmacher .z-text{columns:3 15em;column-gap:22px;column-rule:1px solid #cfc8bb}
.zeitung .z-aufmacher .z-text p:first-child::first-letter{float:left;font-size:3.3em;
line-height:.8;padding:.06em .08em 0 0;font-weight:800}
.zeitung .z-spalten{columns:3 14em;column-gap:22px;column-rule:1px solid #cfc8bb}
.zeitung .z-spalten article{break-inside:avoid-column;border-bottom:1px solid #cfc8bb;padding-bottom:12px}
.zeitung .z-spalten article:last-child{border-bottom:0}
.zeitung .z-ende{border-top:4px double var(--strich);margin-top:6px;padding-top:6px;
font:.72rem/1.3 system-ui,sans-serif;color:var(--grau);text-align:center}
.zeitung .z-leer{color:var(--grau);font-style:italic;text-align:center}
.drucken-leiste{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.ausgaben{list-style:none;padding:0;margin:0}
.ausgaben li{border-top:1px solid var(--linie);padding:12px 0}
.ausgaben a{font-weight:700;font-size:1.1rem;color:var(--text);text-decoration:none}
.ausgaben a:hover{color:var(--akzent)}
@media (max-width:560px){.zeitung{padding:18px 14px 22px}}
@page{size:A4;margin:12mm 12mm 14mm}
@media print{
body{background:#fff!important;color:#000}
header.kopf,footer,.nicht-drucken,.drucken-leiste{display:none!important}
.huelle{max-width:none;padding:0;margin:0}
.zeitung{box-shadow:none;border-radius:0;padding:0;background:#fff;font-size:10.5pt}
.zeitung .z-name{font-size:40pt}
.zeitung .z-aufmacher h2{font-size:24pt}
.zeitung h2{font-size:14pt}
.zeitung .z-aufmacher .z-text,.zeitung .z-spalten{columns:3;column-gap:6mm}
.zeitung figure img{max-height:90mm;object-fit:cover}
a{color:inherit;text-decoration:none}
}
"""


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _absaetze(text: str) -> str:
    teile = [t.strip() for t in (text or "").replace("\r\n", "\n").split("\n\n") if t.strip()]
    return "".join("<p>" + _e(t).replace("\n", "<br>") + "</p>" for t in teile)


def _artikel(a: Dict[str, Any], bild_pfad: str, aufmacher: bool) -> str:
    teile: List[str] = []
    if a["rubrik"]:
        teile.append(f'<p class="z-rubrik">{_e(a["rubrik"])}</p>')
    if a["ueberschrift"]:
        teile.append(f'<h2>{_e(a["ueberschrift"])}</h2>')
    if a["unterzeile"]:
        teile.append(f'<p class="z-unterzeile">{_e(a["unterzeile"])}</p>')
    if a["autor"]:
        teile.append(f'<p class="z-autor">Von {_e(a["autor"])}</p>')
    if a["bild"]:
        unterschrift = f'<figcaption>{_e(a["bildtext"])}</figcaption>' if a["bildtext"] else ""
        teile.append(f'<figure><img src="{_e(bild_pfad)}{_e(a["bild"])}" alt="{_e(a["bildtext"])}">'
                     f'{unterschrift}</figure>')
    if a["text"]:
        teile.append(f'<div class="z-text">{_absaetze(a["text"])}</div>')
    klasse = ' class="z-aufmacher"' if aufmacher else ""
    return f"<article{klasse}>{''.join(teile)}</article>"


def ausgabe(inhalt: Dict[str, Any], *, bild_pfad: str = "medien/") -> str:
    """Die Ausgabe als HTML-Baustein (``inhalt`` wie ``store.zeitung_pruefen``)."""
    zeile = [x for x in (inhalt.get("nummer"), inhalt.get("datum")) if x]
    kopf = (f'<header class="z-kopf"><div class="z-zeile"><span>{_e(zeile[0]) if zeile else ""}</span>'
            f'<span>{_e(zeile[1]) if len(zeile) > 1 else ""}</span></div>'
            f'<div class="z-name">{_e(inhalt["name"])}</div>'
            + (f'<p class="z-untertitel">{_e(inhalt["untertitel"])}</p>' if inhalt.get("untertitel") else "")
            + "</header>")
    artikel = inhalt.get("artikel") or []
    if not artikel:
        rumpf = '<p class="z-leer">Noch keine Artikel – im Studio links „Artikel hinzufügen“.</p>'
    else:
        rumpf = _artikel(artikel[0], bild_pfad, True)
        if len(artikel) > 1:
            rumpf += ('<div class="z-spalten">'
                      + "".join(_artikel(a, bild_pfad, False) for a in artikel[1:]) + "</div>")
    ende = f'<div class="z-ende">{_e(inhalt["name"])}{" · " + _e(" · ".join(zeile)) if zeile else ""}</div>'
    return f'<div class="zeitung">{kopf}{rumpf}{ende}</div>'


def _titel(inhalt: Dict[str, Any]) -> str:
    zusatz = " – ".join(x for x in (inhalt.get("nummer"), inhalt.get("datum")) if x)
    return inhalt["name"] + (f" – {zusatz}" if zusatz else "")


def ausgabe_seite(z: Dict[str, Any], seitentitel: str, *, nav: Optional[list] = None) -> str:
    """Oeffentliche Seite einer Ausgabe unter ``zeitung/<slug>/``."""
    from .site import _rahmen  # gemeinsamer Seitenrahmen

    w = "../../"
    inhalt = z["inhalt"]
    leiste = ('<div class="drucken-leiste"><a href="../">← Alle Ausgaben</a>'
              '<button class="knopf" type="button" data-drucken>🖨 Drucken</button>'
              '<span class="leise">oder im Druckfenster „Als PDF speichern“</span></div>')
    erster = inhalt["artikel"][0] if inhalt["artikel"] else {}
    return _rahmen(_titel(inhalt), leiste + ausgabe(inhalt, bild_pfad=w + "medien/"), 2,
                   seitentitel=seitentitel, nav=nav, nav_aktiv="zeitung/",
                   beschreibung=erster.get("ueberschrift", ""))


def uebersicht(zeitungen: List[Dict[str, Any]], seitentitel: str, *,
               nav: Optional[list] = None) -> str:
    """Alle veroeffentlichten Ausgaben (``store.zeitungen(nur_online=True)``)."""
    from .site import _rahmen, datum

    if zeitungen:
        punkte = []
        for z in zeitungen:
            k = z["kopf"]
            unter = " · ".join(x for x in (k["nummer"], k["datum"] or datum(z["veroeffentlicht"]),
                                           f'{z["artikel_anzahl"]} Artikel') if x)
            punkte.append(f'<li><a href="{_e(z["slug"])}/">{_e(k["name"])}</a>'
                          f'<div class="leise">{_e(unter)}</div></li>')
        liste = f'<ul class="ausgaben">{"".join(punkte)}</ul>'
    else:
        liste = '<p class="leise">Noch keine Ausgabe erschienen.</p>'
    inhalt = (f"<h1>Zeitung</h1><p class=\"leise\">Jede Ausgabe zum Lesen – und mit einem Knopf "
              f"zum Ausdrucken.</p>{liste}")
    return _rahmen(f"Zeitung – {seitentitel}", inhalt, 1, seitentitel=seitentitel,
                   nav=nav, nav_aktiv="zeitung/")
