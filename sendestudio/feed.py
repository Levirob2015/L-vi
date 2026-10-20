"""RSS-Feed fuer Podcast-Apps (Apple Podcasts, Spotify, AntennaPod, ...)."""

from __future__ import annotations

from email.utils import formatdate
from typing import Any, Dict, List
from xml.sax.saxutils import escape, quoteattr

from .store import ARTEN, ki_text, musik_text

#: Kategorie fuer Apple Podcasts, falls keine angegeben ist.
STANDARD_KATEGORIE = {"podcast": "Society & Culture", "radio": "Music", "doku": "Documentary"}


def dauer_text(sekunden: float) -> str:
    s = int(round(sekunden))
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def kapitel_zeit(sekunden: float) -> str:
    ganz = int(sekunden)
    ms = int(round((sekunden - ganz) * 1000))
    return f"{ganz // 3600:02d}:{ganz % 3600 // 60:02d}:{ganz % 60:02d}.{ms:03d}"


def feed(sendung: Dict[str, Any], folgen: List[Dict[str, Any]], basis_url: str) -> str:
    """Erzeugt den Feed. ``basis_url`` ist die oeffentliche Adresse der Seite."""
    basis = basis_url.rstrip("/")
    seite = f"{basis}/s/{sendung['slug']}/"
    medien = f"{basis}/medien/"
    kategorie = sendung["kategorie"] or STANDARD_KATEGORIE.get(sendung["art"], "Society & Culture")
    autor = sendung["autor"] or sendung["titel"]

    t = []
    t.append('<?xml version="1.0" encoding="UTF-8"?>')
    t.append('<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd" '
             'xmlns:atom="http://www.w3.org/2005/Atom" '
             'xmlns:content="http://purl.org/rss/1.0/modules/content/" '
             'xmlns:psc="http://podlove.org/simple-chapters" '
             'xmlns:podcast="https://podcastindex.org/namespace/1.0">')
    t.append("<channel>")
    t.append(f"<title>{escape(sendung['titel'])}</title>")
    t.append(f"<link>{escape(seite)}</link>")
    t.append(f'<atom:link href={quoteattr(seite + "feed.xml")} rel="self" type="application/rss+xml"/>')
    t.append(f"<description>{escape(sendung['beschreibung'] or sendung['titel'])}</description>")
    t.append(f"<language>{escape(sendung['sprache'])}</language>")
    t.append(f"<generator>Sendestudio ({ARTEN[sendung['art']]})</generator>")
    t.append(f"<itunes:author>{escape(autor)}</itunes:author>")
    t.append(f"<itunes:summary>{escape(sendung['beschreibung'] or sendung['titel'])}</itunes:summary>")
    t.append(f"<itunes:category text={quoteattr(kategorie)}/>")
    t.append("<itunes:explicit>false</itunes:explicit>")
    t.append("<itunes:type>episodic</itunes:type>")
    if sendung["cover"]:
        bild = medien + sendung["cover"]
        t.append(f"<itunes:image href={quoteattr(bild)}/>")
        t.append(f"<image><url>{escape(bild)}</url><title>{escape(sendung['titel'])}</title>"
                 f"<link>{escape(seite)}</link></image>")
    if folgen:
        t.append(f"<lastBuildDate>{formatdate(max(f['veroeffentlicht'] for f in folgen), usegmt=True)}"
                 "</lastBuildDate>")

    for f in folgen:
        url = medien + f["datei"]
        link = f"{seite}{f['slug']}/"
        t.append("<item>")
        t.append(f"<title>{escape(f['titel'])}</title>")
        t.append(f"<link>{escape(link)}</link>")
        t.append(f'<guid isPermaLink="false">sendestudio-{sendung["slug"]}-{f["id"]}</guid>')
        t.append(f"<pubDate>{formatdate(f['veroeffentlicht'], usegmt=True)}</pubDate>")
        beschreibung = f["beschreibung"] or f["titel"]
        if f.get("ki"):
            # Kennzeichnung KI-generierter Inhalte (EU-KI-Verordnung, Art. 50) -
            # auch in Podcast-Apps, die nur den Feed sehen.
            beschreibung += f"\n\nHinweis: Diese Folge enthält KI-generierte Inhalte ({ki_text(f['ki'])})."
        if f.get("musik"):
            beschreibung += "\n\nMusik: " + "; ".join(musik_text(f["musik"]))
        t.append(f"<description>{escape(beschreibung)}</description>")
        t.append(f"<enclosure url={quoteattr(url)} length=\"{int(f['groesse'])}\" "
                 f"type={quoteattr(f['mime'])}/>")
        if f["dauer"]:
            t.append(f"<itunes:duration>{dauer_text(f['dauer'])}</itunes:duration>")
        t.append("<itunes:episodeType>full</itunes:episodeType>")
        if f["kapitel"]:
            t.append('<psc:chapters version="1.2">')
            for k in f["kapitel"]:
                t.append(f"<psc:chapter start=\"{kapitel_zeit(k['zeit'])}\" "
                         f"title={quoteattr(k['titel'])}/>")
            t.append("</psc:chapters>")
        if f.get("sprechtext", "").strip():
            t.append(f'<podcast:transcript url={quoteattr(link + "text.txt")} type="text/plain" '
                     f'language={quoteattr(sendung["sprache"])}/>')
        t.append("</item>")
    t.append("</channel>")
    t.append("</rss>")
    return "\n".join(t) + "\n"
