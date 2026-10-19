"""Speicher fuer Sendungen und Folgen (SQLite, Standardbibliothek)."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import unicodedata
from typing import Any, Dict, List, Optional

#: Die drei Arten von Sendungen und ihr Anzeigename.
ARTEN = {
    "podcast": "Podcast",
    "radio": "Radio",
    "doku": "Dokumentation",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sendungen (
    id            INTEGER PRIMARY KEY,
    slug          TEXT NOT NULL UNIQUE,
    titel         TEXT NOT NULL,
    art           TEXT NOT NULL,
    beschreibung  TEXT NOT NULL DEFAULT '',
    autor         TEXT NOT NULL DEFAULT '',
    sprache       TEXT NOT NULL DEFAULT 'de',
    kategorie     TEXT NOT NULL DEFAULT '',
    cover         TEXT NOT NULL DEFAULT '',
    erstellt      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS folgen (
    id               INTEGER PRIMARY KEY,
    sendung_id       INTEGER NOT NULL REFERENCES sendungen(id) ON DELETE CASCADE,
    slug             TEXT NOT NULL,
    titel            TEXT NOT NULL,
    beschreibung     TEXT NOT NULL DEFAULT '',
    datei            TEXT NOT NULL DEFAULT '',
    mime             TEXT NOT NULL DEFAULT '',
    groesse          INTEGER NOT NULL DEFAULT 0,
    dauer            REAL NOT NULL DEFAULT 0,
    kapitel          TEXT NOT NULL DEFAULT '[]',
    veroeffentlicht  REAL,
    erstellt         REAL NOT NULL,
    UNIQUE (sendung_id, slug)
);
CREATE INDEX IF NOT EXISTS folgen_sendung ON folgen (sendung_id, veroeffentlicht);
"""

_SENDUNG_FELDER = ("titel", "art", "beschreibung", "autor", "sprache", "kategorie", "cover")
_FOLGE_FELDER = ("titel", "beschreibung", "datei", "mime", "groesse", "dauer", "kapitel")

_UMLAUTE = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
                          "Ä": "ae", "Ö": "oe", "Ü": "ue"})


def slugify(text: str, fallback: str = "sendung") -> str:
    """Macht aus einem Titel einen Pfadnamen: ``"Über Bäume"`` -> ``"ueber-baeume"``."""
    text = text.translate(_UMLAUTE)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text[:60].strip("-") or fallback


def kapitel_pruefen(kapitel: Any) -> List[Dict[str, Any]]:
    """Kapitelmarken normalisieren: Liste von ``{"zeit": Sekunden, "titel": ...}``."""
    if isinstance(kapitel, str):
        try:
            kapitel = json.loads(kapitel or "[]")
        except ValueError:
            raise ValueError("Kapitel sind kein gueltiges JSON")
    if not isinstance(kapitel, list):
        raise ValueError("Kapitel muessen eine Liste sein")
    sauber = []
    for eintrag in kapitel[:500]:
        if not isinstance(eintrag, dict):
            raise ValueError("Jedes Kapitel braucht Zeit und Titel")
        try:
            zeit = float(eintrag.get("zeit", 0))
        except (TypeError, ValueError):
            raise ValueError("Kapitelzeit ist keine Zahl")
        if zeit < 0 or zeit != zeit:
            raise ValueError("Kapitelzeit darf nicht negativ sein")
        titel = str(eintrag.get("titel", "")).strip()[:200] or "Kapitel"
        sauber.append({"zeit": round(zeit, 2), "titel": titel})
    sauber.sort(key=lambda k: k["zeit"])
    return sauber


class Store:
    """Duenne Schicht ueber SQLite. Threadsicher ueber eine Sperre."""

    def __init__(self, pfad: str, *, clock=time.time) -> None:
        self.pfad = pfad
        self.clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(pfad, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if pfad != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------
    # Sendungen
    # ------------------------------------------------------------------
    def sendungen(self) -> List[Dict[str, Any]]:
        with self._lock:
            zeilen = self._db.execute(
                "SELECT s.*, "
                " (SELECT COUNT(*) FROM folgen f WHERE f.sendung_id = s.id) AS folgen_gesamt, "
                " (SELECT COUNT(*) FROM folgen f WHERE f.sendung_id = s.id "
                "    AND f.veroeffentlicht IS NOT NULL) AS folgen_online "
                "FROM sendungen s ORDER BY s.titel COLLATE NOCASE"
            ).fetchall()
        return [dict(z) for z in zeilen]

    def sendung(self, sendung_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            z = self._db.execute("SELECT * FROM sendungen WHERE id = ?", (sendung_id,)).fetchone()
        return dict(z) if z else None

    def sendung_nach_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            z = self._db.execute("SELECT * FROM sendungen WHERE slug = ?", (slug,)).fetchone()
        return dict(z) if z else None

    def sendung_anlegen(self, titel: str, art: str = "podcast", **felder: Any) -> Dict[str, Any]:
        titel = (titel or "").strip()
        if not titel:
            raise ValueError("Die Sendung braucht einen Titel")
        werte = self._sendung_werte(dict(felder, titel=titel, art=art))
        with self._lock:
            slug = self._freier_slug("SELECT 1 FROM sendungen WHERE slug = ?", (),
                                     slugify(titel))
            spalten = ["slug", "erstellt"] + list(werte)
            cur = self._db.execute(
                f"INSERT INTO sendungen ({', '.join(spalten)}) "
                f"VALUES ({', '.join('?' for _ in spalten)})",
                [slug, self.clock()] + list(werte.values()),
            )
            self._db.commit()
            neu = cur.lastrowid
        return self.sendung(neu)  # type: ignore[return-value]

    def sendung_aendern(self, sendung_id: int, **felder: Any) -> Dict[str, Any]:
        werte = self._sendung_werte(felder)
        if "titel" in werte and not werte["titel"]:
            raise ValueError("Die Sendung braucht einen Titel")
        if werte:
            with self._lock:
                self._db.execute(
                    f"UPDATE sendungen SET {', '.join(k + ' = ?' for k in werte)} WHERE id = ?",
                    list(werte.values()) + [sendung_id],
                )
                self._db.commit()
        s = self.sendung(sendung_id)
        if s is None:
            raise KeyError(sendung_id)
        return s

    def sendung_loeschen(self, sendung_id: int) -> List[str]:
        """Loescht die Sendung samt Folgen. Gibt die nun verwaisten Dateien zurueck."""
        s = self.sendung(sendung_id)
        if s is None:
            return []
        dateien = [f["datei"] for f in self.folgen(sendung_id) if f["datei"]]
        if s["cover"]:
            dateien.append(s["cover"])
        with self._lock:
            self._db.execute("DELETE FROM sendungen WHERE id = ?", (sendung_id,))
            self._db.commit()
        return dateien

    @staticmethod
    def _sendung_werte(felder: Dict[str, Any]) -> Dict[str, Any]:
        werte = {}
        for k in _SENDUNG_FELDER:
            if k in felder and felder[k] is not None:
                werte[k] = str(felder[k]).strip()
        if "art" in werte and werte["art"] not in ARTEN:
            raise ValueError(f"Unbekannte Art: {werte['art']!r} (erlaubt: {', '.join(ARTEN)})")
        if "titel" in werte:
            werte["titel"] = werte["titel"][:200]
        if "beschreibung" in werte:
            werte["beschreibung"] = werte["beschreibung"][:10000]
        if "sprache" in werte:
            if not re.fullmatch(r"[a-zA-Z]{2,3}(-[a-zA-Z]{2})?", werte["sprache"]):
                raise ValueError("Sprache bitte als Kuerzel, z.B. 'de' oder 'en-US'")
        for k in ("autor", "kategorie", "cover"):
            if k in werte:
                werte[k] = werte[k][:200]
        return werte

    # ------------------------------------------------------------------
    # Folgen
    # ------------------------------------------------------------------
    def folgen(self, sendung_id: int, *, nur_online: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM folgen WHERE sendung_id = ?"
        if nur_online:
            sql += " AND veroeffentlicht IS NOT NULL AND datei != ''"
        # Neueste zuerst; Entwuerfe (noch ohne Datum) nach ihrem Anlegen.
        sql += " ORDER BY COALESCE(veroeffentlicht, erstellt) DESC, id DESC"
        with self._lock:
            zeilen = self._db.execute(sql, (sendung_id,)).fetchall()
        return [self._folge_dict(z) for z in zeilen]

    def folge(self, folge_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            z = self._db.execute("SELECT * FROM folgen WHERE id = ?", (folge_id,)).fetchone()
        return self._folge_dict(z) if z else None

    def folge_nach_slug(self, sendung_id: int, slug: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            z = self._db.execute("SELECT * FROM folgen WHERE sendung_id = ? AND slug = ?",
                                 (sendung_id, slug)).fetchone()
        return self._folge_dict(z) if z else None

    def folge_anlegen(self, sendung_id: int, titel: str, **felder: Any) -> Dict[str, Any]:
        if self.sendung(sendung_id) is None:
            raise KeyError(sendung_id)
        titel = (titel or "").strip()
        if not titel:
            raise ValueError("Die Folge braucht einen Titel")
        werte = self._folge_werte(dict(felder, titel=titel))
        with self._lock:
            slug = self._freier_slug(
                "SELECT 1 FROM folgen WHERE slug = ? AND sendung_id = ?", (sendung_id,),
                slugify(titel, "folge"))
            spalten = ["sendung_id", "slug", "erstellt"] + list(werte)
            cur = self._db.execute(
                f"INSERT INTO folgen ({', '.join(spalten)}) "
                f"VALUES ({', '.join('?' for _ in spalten)})",
                [sendung_id, slug, self.clock()] + list(werte.values()),
            )
            self._db.commit()
            neu = cur.lastrowid
        return self.folge(neu)  # type: ignore[return-value]

    def folge_aendern(self, folge_id: int, **felder: Any) -> Dict[str, Any]:
        werte = self._folge_werte(felder)
        if "titel" in werte and not werte["titel"]:
            raise ValueError("Die Folge braucht einen Titel")
        if werte:
            with self._lock:
                self._db.execute(
                    f"UPDATE folgen SET {', '.join(k + ' = ?' for k in werte)} WHERE id = ?",
                    list(werte.values()) + [folge_id],
                )
                self._db.commit()
        f = self.folge(folge_id)
        if f is None:
            raise KeyError(folge_id)
        return f

    def veroeffentlichen(self, folge_id: int, zeitpunkt: Optional[float] = None) -> Dict[str, Any]:
        f = self.folge(folge_id)
        if f is None:
            raise KeyError(folge_id)
        if not f["datei"]:
            raise ValueError("Ohne Aufnahme gibt es nichts zu veroeffentlichen")
        with self._lock:
            self._db.execute("UPDATE folgen SET veroeffentlicht = ? WHERE id = ?",
                             (zeitpunkt if zeitpunkt is not None else self.clock(), folge_id))
            self._db.commit()
        return self.folge(folge_id)  # type: ignore[return-value]

    def zurueckziehen(self, folge_id: int) -> Dict[str, Any]:
        with self._lock:
            self._db.execute("UPDATE folgen SET veroeffentlicht = NULL WHERE id = ?", (folge_id,))
            self._db.commit()
        f = self.folge(folge_id)
        if f is None:
            raise KeyError(folge_id)
        return f

    def folge_loeschen(self, folge_id: int) -> Optional[str]:
        """Loescht die Folge. Gibt ihre nun verwaiste Datei zurueck."""
        f = self.folge(folge_id)
        if f is None:
            return None
        with self._lock:
            self._db.execute("DELETE FROM folgen WHERE id = ?", (folge_id,))
            self._db.commit()
        return f["datei"] or None

    def datei_in_benutzung(self, name: str) -> bool:
        with self._lock:
            z = self._db.execute(
                "SELECT 1 FROM folgen WHERE datei = ? UNION SELECT 1 FROM sendungen WHERE cover = ?",
                (name, name)).fetchone()
        return z is not None

    @staticmethod
    def _folge_werte(felder: Dict[str, Any]) -> Dict[str, Any]:
        werte: Dict[str, Any] = {}
        for k in _FOLGE_FELDER:
            if k in felder and felder[k] is not None:
                werte[k] = felder[k]
        if "titel" in werte:
            werte["titel"] = str(werte["titel"]).strip()[:200]
        if "beschreibung" in werte:
            werte["beschreibung"] = str(werte["beschreibung"]).strip()[:20000]
        if "kapitel" in werte:
            werte["kapitel"] = json.dumps(kapitel_pruefen(werte["kapitel"]), ensure_ascii=False)
        if "dauer" in werte:
            dauer = float(werte["dauer"])
            werte["dauer"] = dauer if 0 <= dauer < 10 * 24 * 3600 else 0.0
        if "groesse" in werte:
            werte["groesse"] = max(0, int(werte["groesse"]))
        return werte

    @staticmethod
    def _folge_dict(z: sqlite3.Row) -> Dict[str, Any]:
        d = dict(z)
        d["kapitel"] = json.loads(d["kapitel"] or "[]")
        d["online"] = d["veroeffentlicht"] is not None
        return d

    def _freier_slug(self, sql: str, extra: tuple, basis: str) -> str:
        slug, n = basis, 2
        while self._db.execute(sql, (slug,) + extra).fetchone():
            slug = f"{basis}-{n}"
            n += 1
        return slug
