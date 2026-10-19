"""Die oeffentliche Seite: Uebersicht, Sendungen, Folgen, Radio.

Alle Seiten verlinken relativ. Dadurch laeuft dieselbe Ausgabe direkt aus
dem Studio-Server, als statischer Export auf einem Webspace oder unter
einem Unterpfad wie ``https://name.github.io/projekt/``.

Skripte liegen in einer eigenen Datei (``seite.js``), damit die Seiten mit
einer strengen Content-Security-Policy ohne ``unsafe-inline`` auskommen.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import radio
from .feed import dauer_text
from .store import ARTEN

_MONATE = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August",
           "September", "Oktober", "November", "Dezember"]

STIL = """\
:root{--bg:#f6f4ef;--karte:#fff;--text:#1d1b18;--leise:#6b665e;--akzent:#c2410c;
--akzent2:#9a3412;--linie:#e4dfd5}
@media (prefers-color-scheme:dark){:root{--bg:#161412;--karte:#211e1b;--text:#f1ede6;
--leise:#a59e93;--akzent:#fb923c;--akzent2:#fdba74;--linie:#36312b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:17px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--akzent)}a:hover{color:var(--akzent2)}
.huelle{max-width:860px;margin:0 auto;padding:24px 16px 64px}
header.kopf{display:flex;align-items:center;gap:12px;margin-bottom:28px}
header.kopf a{text-decoration:none;color:var(--text);font-weight:700;letter-spacing:.02em}
.punkt{width:12px;height:12px;border-radius:50%;background:var(--akzent);display:inline-block}
h1{font-size:2rem;line-height:1.2;margin:.2em 0}
h2{font-size:1.25rem;margin:1.6em 0 .6em}
.leise{color:var(--leise)}
.karte{background:var(--karte);border:1px solid var(--linie);border-radius:14px;padding:18px;
margin:0 0 14px}
.sendung{display:flex;gap:18px;align-items:flex-start}
.cover{width:120px;height:120px;border-radius:12px;object-fit:cover;flex:none;
background:var(--linie)}
.cover.gross{width:180px;height:180px}
.marke{display:inline-block;font-size:.75rem;font-weight:700;text-transform:uppercase;
letter-spacing:.06em;color:var(--akzent);border:1px solid currentColor;border-radius:999px;
padding:1px 9px}
.folge h3{margin:.1em 0 .2em;font-size:1.1rem}
.folge h3 a{color:var(--text);text-decoration:none}
audio,video{width:100%;margin:12px 0;border-radius:10px}
video{background:#000}
.kapitel{list-style:none;padding:0;margin:0}
.kapitel li{border-top:1px solid var(--linie)}
.kapitel button{all:unset;cursor:pointer;display:flex;gap:14px;width:100%;padding:9px 2px}
.kapitel button:hover{color:var(--akzent)}
.kapitel .zeit{font-variant-numeric:tabular-nums;color:var(--leise);min-width:5.5em}
.knopf{display:inline-block;background:var(--akzent);color:#fff;border:0;border-radius:999px;
padding:10px 20px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.knopf:hover{background:var(--akzent2);color:#fff}
.feed{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.feed input{flex:1;min-width:220px;padding:8px 10px;border-radius:8px;border:1px solid var(--linie);
background:var(--bg);color:var(--text);font:inherit;font-size:.9rem}
.live{display:inline-flex;align-items:center;gap:8px;font-weight:700;color:var(--akzent)}
.live::before{content:"";width:10px;height:10px;border-radius:50%;background:currentColor;
animation:puls 1.4s infinite}
@keyframes puls{50%{opacity:.25}}
.programm li.laeuft{font-weight:700;color:var(--akzent)}
.text p{margin:.6em 0}
h2.eng{margin:.2em 0 .4em}
footer{margin-top:48px;font-size:.85rem;color:var(--leise)}
@media (max-width:560px){.sendung{flex-direction:column}.cover.gross{width:100%;height:auto;
aspect-ratio:1}h1{font-size:1.6rem}}
"""

SEITE_JS = """\
(function () {
  "use strict";
  // Kapitel anspringen
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-zeit]");
    if (!b) return;
    var m = document.querySelector("audio, video");
    if (!m) return;
    m.currentTime = parseFloat(b.getAttribute("data-zeit"));
    m.play();
  });

  // Feed-Adresse kopieren
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-kopieren]");
    if (!b) return;
    var feld = document.getElementById(b.getAttribute("data-kopieren"));
    feld.select();
    (navigator.clipboard ? navigator.clipboard.writeText(feld.value) : Promise.reject())
      .catch(function () { document.execCommand("copy"); })
      .then(function () { b.textContent = "Kopiert"; });
  });

  // Radio: dieselbe Rechnung wie sendestudio/radio.py
  var daten = document.getElementById("programm");
  if (!daten) return;
  var p = JSON.parse(daten.textContent);
  var player = document.getElementById("radio");
  var knopf = document.getElementById("einschalten");
  var anzeige = document.getElementById("laeuft");
  var danach = document.getElementById("danach");
  var an = false;

  function jetzt() {
    var gesamt = 0;
    p.folgen.forEach(function (f) { gesamt += f.dauer; });
    if (gesamt <= 0) return null;
    var t = Date.now() / 1000 - p.anker;
    var pos = ((t % gesamt) + gesamt) % gesamt;
    for (var i = 0; i < p.folgen.length; i++) {
      if (pos < p.folgen[i].dauer) return { index: i, offset: pos };
      pos -= p.folgen[i].dauer;
    }
    return { index: 0, offset: 0 };
  }

  function zeigen(i) {
    var f = p.folgen[i];
    anzeige.textContent = f.titel;
    danach.textContent = p.folgen[(i + 1) % p.folgen.length].titel;
    document.querySelectorAll(".programm li").forEach(function (li, j) {
      li.classList.toggle("laeuft", j === i);
    });
  }

  function senden() {
    var j = jetzt();
    if (!j) return;
    var f = p.folgen[j.index];
    zeigen(j.index);
    if (player.getAttribute("src") !== f.url) player.src = f.url;
    var springen = function () {
      try { player.currentTime = j.offset; } catch (e) {}
    };
    if (player.readyState >= 1) springen();
    else player.addEventListener("loadedmetadata", springen, { once: true });
    // play() direkt im Klick - iOS erlaubt Ton nur so.
    var v = player.play();
    if (v && v.catch) v.catch(function () {});
  }

  var start = jetzt();
  if (start) zeigen(start.index);

  knopf.addEventListener("click", function () {
    an = !an;
    knopf.textContent = an ? "Ausschalten" : "Einschalten";
    if (an) senden(); else player.pause();
  });
  player.addEventListener("ended", function () { if (an) senden(); });
  // Wer pausiert und wieder einschaltet, ist wieder live - wie im Radio.
  player.addEventListener("play", function () {
    var j = jetzt();
    if (an && j && Math.abs(player.currentTime - j.offset) > 5 &&
        p.folgen[j.index].url === player.getAttribute("src")) {
      player.currentTime = j.offset;
    }
  });
})();
"""


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def datum(zeitstempel: Optional[float]) -> str:
    if not zeitstempel:
        return ""
    d = datetime.fromtimestamp(zeitstempel, tz=timezone.utc)
    return f"{d.day}. {_MONATE[d.month - 1]} {d.year}"


def absaetze(text: str) -> str:
    teile = [t.strip() for t in (text or "").split("\n\n") if t.strip()]
    return "".join(f"<p>{_e(t).replace(chr(10), '<br>')}</p>" for t in teile)


def _rahmen(titel: str, inhalt: str, tiefe: int, *, seitentitel: str,
            beschreibung: str = "", bild: str = "", feed: str = "") -> str:
    w = "../" * tiefe
    meta = [f'<meta property="og:title" content="{_e(titel)}">']
    if beschreibung:
        kurz = beschreibung.strip().split("\n")[0][:200]
        meta.append(f'<meta name="description" content="{_e(kurz)}">')
        meta.append(f'<meta property="og:description" content="{_e(kurz)}">')
    if bild:
        meta.append(f'<meta property="og:image" content="{_e(bild)}">')
    if feed:
        meta.append(f'<link rel="alternate" type="application/rss+xml" title="{_e(titel)}" '
                    f'href="{_e(feed)}">')
    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(titel)}</title>
{chr(10).join(meta)}
<link rel="stylesheet" href="{w}stil.css">
</head>
<body>
<div class="huelle">
<header class="kopf"><span class="punkt"></span><a href="{w}">{_e(seitentitel)}</a></header>
{inhalt}
<footer>Gemacht mit Sendestudio</footer>
</div>
<script src="{w}seite.js"></script>
</body>
</html>
"""


def _cover(sendung: Dict[str, Any], w: str, gross: bool = False) -> str:
    klasse = "cover gross" if gross else "cover"
    if sendung["cover"]:
        return f'<img class="{klasse}" src="{w}medien/{_e(sendung["cover"])}" alt="">'
    return f'<div class="{klasse}" aria-hidden="true"></div>'


def _player(folge: Dict[str, Any], w: str, element_id: str = "") -> str:
    tag = "video" if folge["mime"].startswith("video/") else "audio"
    attr = f' id="{element_id}"' if element_id else ""
    return (f'<{tag}{attr} controls preload="metadata" src="{w}medien/{_e(folge["datei"])}">'
            f"Dein Browser kann das nicht abspielen.</{tag}>")


def startseite(eintraege: List[Dict[str, Any]], seitentitel: str) -> str:
    """``eintraege``: Sendungen mit Schluessel ``folgen`` (nur veroeffentlichte)."""
    karten = []
    for s in eintraege:
        if not s["folgen"]:
            continue
        neueste = s["folgen"][0]
        karten.append(f"""<div class="karte sendung">
{_cover(s, "")}
<div><span class="marke">{_e(ARTEN[s["art"]])}</span>
<h2 class="eng"><a href="s/{_e(s["slug"])}/">{_e(s["titel"])}</a></h2>
<div class="leise">{len(s["folgen"])} {"Folge" if len(s["folgen"]) == 1 else "Folgen"} ·
neu: {_e(neueste["titel"])}</div></div></div>""")
    if not karten:
        karten.append('<p class="leise">Hier ist noch nichts veröffentlicht.</p>')
    return _rahmen(seitentitel, f"<h1>{_e(seitentitel)}</h1>\n" + "\n".join(karten), 0,
                   seitentitel=seitentitel)


def sendung_seite(s: Dict[str, Any], folgen: List[Dict[str, Any]], seitentitel: str,
                  basis_url: str = "") -> str:
    w = "../../"
    feed_rel = "feed.xml"
    feed_abs = f"{basis_url.rstrip('/')}/s/{s['slug']}/feed.xml" if basis_url else ""
    radio_teil = ""
    if s["art"] == "radio" and radio.programm(folgen):
        radio_teil = ('<p><a class="knopf" href="radio/">Live hören</a> '
                      '<span class="leise">Das Programm läuft rund um die Uhr.</span></p>')
    abo = ""
    if feed_abs:
        abo = f"""<div class="feed"><input id="feedurl" readonly value="{_e(feed_abs)}"
aria-label="Feed-Adresse"><button class="knopf" data-kopieren="feedurl">Kopieren</button></div>
<p class="leise">Diese Adresse in jeder Podcast-App unter „Per URL hinzufügen“ einfügen.</p>"""
    else:
        abo = f'<p><a href="{feed_rel}">RSS-Feed</a></p>'

    liste = []
    for f in folgen:
        kapitel = f" · {len(f['kapitel'])} Kapitel" if f["kapitel"] else ""
        liste.append(f"""<div class="karte folge">
<div class="leise">{datum(f["veroeffentlicht"])} · {dauer_text(f["dauer"]) if f["dauer"] else ""}{kapitel}</div>
<h3><a href="{_e(f["slug"])}/">{_e(f["titel"])}</a></h3>
{_player(f, w)}
</div>""")
    if not liste:
        liste.append('<p class="leise">Noch keine Folgen.</p>')

    inhalt = f"""<div class="sendung">{_cover(s, w, gross=True)}
<div><span class="marke">{_e(ARTEN[s["art"]])}</span>
<h1>{_e(s["titel"])}</h1>
{f'<div class="leise">{_e(s["autor"])}</div>' if s["autor"] else ""}
<div class="text">{absaetze(s["beschreibung"])}</div>
{radio_teil}</div></div>
<h2>Abonnieren</h2>
{abo}
<h2>Folgen</h2>
{"".join(liste)}"""
    bild = f"{basis_url.rstrip('/')}/medien/{s['cover']}" if basis_url and s["cover"] else ""
    return _rahmen(s["titel"], inhalt, 2, seitentitel=seitentitel,
                   beschreibung=s["beschreibung"], bild=bild, feed=feed_rel)


def folge_seite(s: Dict[str, Any], f: Dict[str, Any], seitentitel: str,
                basis_url: str = "") -> str:
    w = "../../../"
    kapitel = ""
    if f["kapitel"]:
        punkte = "".join(
            f'<li><button data-zeit="{k["zeit"]}"><span class="zeit">{dauer_text(int(k["zeit"]))}'
            f'</span><span>{_e(k["titel"])}</span></button></li>' for k in f["kapitel"])
        kapitel = f'<h2>Kapitel</h2><ul class="kapitel">{punkte}</ul>'
    inhalt = f"""<p><a href="../">← {_e(s["titel"])}</a></p>
<span class="marke">{_e(ARTEN[s["art"]])}</span>
<h1>{_e(f["titel"])}</h1>
<div class="leise">{datum(f["veroeffentlicht"])}{" · " + dauer_text(f["dauer"]) if f["dauer"] else ""}</div>
{_player(f, w)}
<div class="text">{absaetze(f["beschreibung"])}</div>
{kapitel}
<p><a href="{w}medien/{_e(f["datei"])}" download>Datei herunterladen</a></p>"""
    bild = f"{basis_url.rstrip('/')}/medien/{s['cover']}" if basis_url and s["cover"] else ""
    return _rahmen(f"{f['titel']} – {s['titel']}", inhalt, 3, seitentitel=seitentitel,
                   beschreibung=f["beschreibung"], bild=bild, feed="../feed.xml")


def radio_seite(s: Dict[str, Any], folgen: List[Dict[str, Any]], seitentitel: str) -> str:
    w = "../../../"
    liste = radio.programm(folgen)
    daten = {
        "anker": radio.ANKER,
        "folgen": [{"titel": f["titel"], "dauer": f["dauer"], "url": f"{w}medien/{f['datei']}"}
                   for f in liste],
    }
    # "</script>" im Titel darf den Block nicht beenden.
    json_text = json.dumps(daten, ensure_ascii=False).replace("<", "\\u003c")
    if liste:
        programm_html = "".join(
            f"<li>{_e(f['titel'])} <span class='leise'>({dauer_text(f['dauer'])})</span></li>"
            for f in liste)
        hauptteil = f"""<p class="live">Live</p>
<div class="karte">
<div class="leise">Jetzt läuft</div>
<h2 id="laeuft" class="eng">…</h2>
<div class="leise">Danach: <span id="danach">…</span></div>
<audio id="radio" preload="none"></audio>
<button class="knopf" id="einschalten">Einschalten</button>
</div>
<h2>Programm</h2>
<ol class="programm">{programm_html}</ol>
<script type="application/json" id="programm">{json_text}</script>"""
    else:
        hauptteil = '<p class="leise">Der Sender hat noch kein Programm.</p>'
    inhalt = f"""<p><a href="../">← {_e(s["titel"])}</a></p>
<h1>{_e(s["titel"])}</h1>
{hauptteil}"""
    return _rahmen(f"{s['titel']} – Live", inhalt, 3, seitentitel=seitentitel)
