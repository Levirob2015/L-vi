"""Speicher fuer Sendungen und Folgen (SQLite, Standardbibliothek)."""

from __future__ import annotations

import json
import re
import secrets
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
CREATE TABLE IF NOT EXISTS einstellungen (
    schluessel  TEXT PRIMARY KEY,
    wert        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS musik (
    id         INTEGER PRIMARY KEY,
    titel      TEXT NOT NULL,
    kuenstler  TEXT NOT NULL DEFAULT '',
    lizenz     TEXT NOT NULL DEFAULT '',
    quelle     TEXT NOT NULL DEFAULT '',
    datei      TEXT NOT NULL DEFAULT '',
    mime       TEXT NOT NULL DEFAULT '',
    dauer      REAL NOT NULL DEFAULT 0,
    ki         INTEGER NOT NULL DEFAULT 0,
    erstellt   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ki_nutzung (
    tag     TEXT PRIMARY KEY,
    anzahl  INTEGER NOT NULL
);
"""

#: Spalten, die spaeter dazukamen - aeltere Datenbanken bekommen sie beim Start.
_NACHTRAEGE = (
    ("folgen", "ki", "TEXT NOT NULL DEFAULT '[]'"),
    ("sendungen", "cover_ki", "INTEGER NOT NULL DEFAULT 0"),
    ("folgen", "musik", "TEXT NOT NULL DEFAULT '[]'"),
)

#: Was an einer Folge KI-generiert sein kann - fuer die Kennzeichnung.
KI_ARTEN = {"text": "Text", "stimme": "Stimme", "bild": "Bilder", "musik": "Musik", "video": "Video"}

_SENDUNG_FELDER = ("titel", "art", "beschreibung", "autor", "sprache", "kategorie", "cover",
                   "cover_ki")
_FOLGE_FELDER = ("titel", "beschreibung", "datei", "mime", "groesse", "dauer", "kapitel", "ki",
                 "musik")
_MUSIK_FELDER = ("titel", "kuenstler", "lizenz", "quelle", "datei", "mime", "dauer", "ki")

#: Diese Felder einer Folge liegen, solange sie nicht veroeffentlicht ist,
#: verschluesselt in der Datenbank (sofern ein offener Tresor da ist).
GEHEIM = ("titel", "beschreibung", "kapitel", "musik")
#: Was ein verschlossener Entwurf statt seines Titels zeigt.
VERSCHLOSSEN = "(verschlossen)"
#: Pfadnamen von Entwuerfen verraten nichts ueber den Titel.
ENTWURF_PRAEFIX = "entwurf-"

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


def ki_text(ki: List[str]) -> str:
    """``["stimme", "bild"]`` -> ``"Stimme, Bilder"``."""
    return ", ".join(KI_ARTEN[k] for k in KI_ARTEN if k in ki)


#: Angebotene Lizenzen - frei eintragbar, das hier sind nur Vorschlaege.
LIZENZEN = ("Eigene Musik", "CC0 / gemeinfrei", "CC BY", "CC BY-SA", "Pixabay-Lizenz",
            "GEMA-frei, lizenziert", "KI-generiert")


def musik_angaben_pruefen(angaben: Any) -> List[Dict[str, str]]:
    """Musik-Angaben einer Folge: ``[{"titel", "kuenstler", "lizenz", "quelle"}]``.

    Sie erscheinen oeffentlich an der Folge und im Feed - viele freie
    Lizenzen (CC BY) verlangen genau diese Nennung.
    """
    if isinstance(angaben, str):
        try:
            angaben = json.loads(angaben or "[]")
        except ValueError:
            raise ValueError("Musik-Angaben sind kein gueltiges JSON")
    if not isinstance(angaben, list) or len(angaben) > 50:
        raise ValueError("Musik-Angaben muessen eine Liste sein (hoechstens 50)")
    sauber = []
    for a in angaben:
        if not isinstance(a, dict):
            raise ValueError("Jede Musik-Angabe braucht Titel, Kuenstler und Lizenz")
        eintrag = {k: str(a.get(k) or "").strip()[:200] for k in ("titel", "kuenstler", "lizenz", "quelle")}
        if not eintrag["titel"]:
            continue
        if eintrag["quelle"] and not re.match(r"https?://", eintrag["quelle"]):
            raise ValueError("Die Quelle der Musik bitte als Link (https://...)")
        sauber.append(eintrag)
    return sauber


def musik_text(angaben: List[Dict[str, str]]) -> List[str]:
    """``"Titel – Kuenstler (Lizenz)"`` je Angabe."""
    zeilen = []
    for a in angaben:
        z = a["titel"] + (f" – {a['kuenstler']}" if a.get("kuenstler") else "")
        if a.get("lizenz"):
            z += f" ({a['lizenz']})"
        zeilen.append(z)
    return zeilen


def ki_pruefen(ki: Any) -> List[str]:
    """Liste der KI-Anteile einer Folge, z.B. ``["text", "stimme"]``."""
    if isinstance(ki, str):
        try:
            ki = json.loads(ki or "[]")
        except ValueError:
            raise ValueError("KI-Angabe ist kein gueltiges JSON")
    if not isinstance(ki, list) or any(k not in KI_ARTEN for k in ki):
        raise ValueError(f"KI-Angabe: erlaubt sind {', '.join(KI_ARTEN)}")
    return [k for k in KI_ARTEN if k in ki]


class Store:
    """Duenne Schicht ueber SQLite. Threadsicher ueber eine Sperre."""

    def __init__(self, pfad: str, *, clock=time.time, tresor: Any = None) -> None:
        self.pfad = pfad
        self.clock = clock
        self.tresor = tresor
        self._lock = threading.Lock()
        self._db = sqlite3.connect(pfad, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if pfad != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self._db.executescript(_SCHEMA)
        for tabelle, spalte, art in _NACHTRAEGE:
            vorhanden = {z[1] for z in self._db.execute(f"PRAGMA table_info({tabelle})")}
            if spalte not in vorhanden:
                self._db.execute(f"ALTER TABLE {tabelle} ADD COLUMN {spalte} {art}")
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
                werte[k] = (1 if felder[k] else 0) if k == "cover_ki" else str(felder[k]).strip()
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
        geheim = self._geheim()
        if geheim:
            self._einschliessen(werte)
        with self._lock:
            slug = self._freier_slug(
                "SELECT 1 FROM folgen WHERE slug = ? AND sendung_id = ?", (sendung_id,),
                ENTWURF_PRAEFIX + secrets.token_hex(4) if geheim else slugify(titel, "folge"))
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
        if any(k in werte for k in GEHEIM) and self._geheim():
            with self._lock:
                z = self._db.execute("SELECT veroeffentlicht FROM folgen WHERE id = ?",
                                     (folge_id,)).fetchone()
            if z is not None and z[0] is None:
                self._einschliessen(werte)
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
        if f.get("verschlossen"):
            raise ValueError("Tresor verschlossen - bitte neu anmelden")
        with self._lock:
            # Ab jetzt oeffentlich: Texte im Klartext, ein lesbarer Pfadname.
            slug = f["slug"]
            if slug.startswith(ENTWURF_PRAEFIX):
                slug = self._freier_slug("SELECT 1 FROM folgen WHERE slug = ? AND sendung_id = ?",
                                         (f["sendung_id"],), slugify(f["titel"], "folge"))
            self._db.execute(
                "UPDATE folgen SET veroeffentlicht = ?, slug = ?, titel = ?, beschreibung = ?, "
                "kapitel = ?, musik = ? WHERE id = ?",
                (zeitpunkt if zeitpunkt is not None else self.clock(), slug, f["titel"],
                 f["beschreibung"], json.dumps(f["kapitel"], ensure_ascii=False),
                 json.dumps(f["musik"], ensure_ascii=False), folge_id))
            self._db.commit()
        return self.folge(folge_id)  # type: ignore[return-value]

    def zurueckziehen(self, folge_id: int) -> Dict[str, Any]:
        with self._lock:
            self._db.execute("UPDATE folgen SET veroeffentlicht = NULL WHERE id = ?", (folge_id,))
            self._db.commit()
        self.entwuerfe_einschliessen()
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
                "SELECT 1 FROM folgen WHERE datei = ? UNION SELECT 1 FROM sendungen WHERE cover = ? "
                "UNION SELECT 1 FROM musik WHERE datei = ?", (name, name, name)).fetchone()
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
        if "ki" in werte:
            werte["ki"] = json.dumps(ki_pruefen(werte["ki"]))
        if "musik" in werte:
            werte["musik"] = json.dumps(musik_angaben_pruefen(werte["musik"]), ensure_ascii=False)
        return werte

    def _folge_dict(self, z: sqlite3.Row) -> Dict[str, Any]:
        d = dict(z)
        d["verschlossen"] = False
        for k in GEHEIM:
            if self.tresor is not None and self.tresor.ist_verschluesselt(d[k]):
                if self.tresor.offen:
                    d[k] = self.tresor.text_entschluesseln(d[k])
                else:
                    d[k] = {"titel": VERSCHLOSSEN, "beschreibung": "", "kapitel": "[]",
                            "musik": "[]"}[k]
                    d["verschlossen"] = True
        d["kapitel"] = json.loads(d["kapitel"] or "[]")
        d["ki"] = json.loads(d.get("ki") or "[]")
        d["musik"] = json.loads(d.get("musik") or "[]")
        d["online"] = d["veroeffentlicht"] is not None
        return d

    def _geheim(self) -> bool:
        return self.tresor is not None and self.tresor.offen

    def _einschliessen(self, werte: Dict[str, Any]) -> None:
        for k in GEHEIM:
            if k in werte and not self.tresor.ist_verschluesselt(werte[k]):
                werte[k] = self.tresor.text_verschluesseln(str(werte[k]))

    def entwuerfe_einschliessen(self) -> int:
        """Verschluesselt Texte aller Entwuerfe, die noch im Klartext liegen.

        Fuer zurueckgezogene Folgen und fuer Daten aus der Zeit vor dem
        Tresor. Ohne offenen Tresor passiert nichts.
        """
        if not self._geheim():
            return 0
        with self._lock:
            zeilen = self._db.execute(
                "SELECT id, titel, beschreibung, kapitel, musik FROM folgen "
                "WHERE veroeffentlicht IS NULL").fetchall()
        n = 0
        for z in zeilen:
            werte = {k: z[k] for k in GEHEIM if not self.tresor.ist_verschluesselt(z[k])}
            if not werte:
                continue
            self._einschliessen(werte)
            with self._lock:
                self._db.execute(
                    f"UPDATE folgen SET {', '.join(k + ' = ?' for k in werte)} "
                    "WHERE id = ? AND veroeffentlicht IS NULL",
                    list(werte.values()) + [z["id"]])
                self._db.commit()
            n += 1
        return n

    def _freier_slug(self, sql: str, extra: tuple, basis: str) -> str:
        slug, n = basis, 2
        while self._db.execute(sql, (slug,) + extra).fetchone():
            slug = f"{basis}-{n}"
            n += 1
        return slug

    # ------------------------------------------------------------------
    # Kleinkram, der einen Neustart ueberdauern muss
    # ------------------------------------------------------------------
    def einstellung(self, schluessel: str, standard: str = "") -> str:
        with self._lock:
            z = self._db.execute("SELECT wert FROM einstellungen WHERE schluessel = ?",
                                 (schluessel,)).fetchone()
        return z[0] if z else standard

    def einstellung_setzen(self, schluessel: str, wert: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO einstellungen (schluessel, wert) VALUES (?, ?) "
                             "ON CONFLICT(schluessel) DO UPDATE SET wert = excluded.wert",
                             (schluessel, wert))
            self._db.commit()

    def ki_zaehlen(self, tag: str, limit: int) -> bool:
        """Zaehlt einen KI-Auftrag. ``False``, wenn das Tageslimit erreicht ist."""
        with self._lock:
            z = self._db.execute("SELECT anzahl FROM ki_nutzung WHERE tag = ?", (tag,)).fetchone()
            anzahl = z[0] if z else 0
            if anzahl >= limit:
                return False
            self._db.execute("INSERT INTO ki_nutzung (tag, anzahl) VALUES (?, 1) "
                             "ON CONFLICT(tag) DO UPDATE SET anzahl = anzahl + 1", (tag,))
            self._db.commit()
        return True

    def ki_heute(self, tag: str) -> int:
        with self._lock:
            z = self._db.execute("SELECT anzahl FROM ki_nutzung WHERE tag = ?", (tag,)).fetchone()
        return z[0] if z else 0

    # ------------------------------------------------------------------
    # Musikbibliothek
    # ------------------------------------------------------------------
    def musik_liste(self) -> List[Dict[str, Any]]:
        with self._lock:
            zeilen = self._db.execute("SELECT * FROM musik ORDER BY erstellt DESC, id DESC").fetchall()
        return [dict(z) for z in zeilen]

    def musik(self, musik_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            z = self._db.execute("SELECT * FROM musik WHERE id = ?", (musik_id,)).fetchone()
        return dict(z) if z else None

    def musik_anlegen(self, titel: str, **felder: Any) -> Dict[str, Any]:
        werte = self._musik_werte(dict(felder, titel=titel))
        if not werte.get("titel"):
            raise ValueError("Das Musikstueck braucht einen Titel")
        spalten = ["erstellt"] + list(werte)
        with self._lock:
            cur = self._db.execute(
                f"INSERT INTO musik ({', '.join(spalten)}) VALUES ({', '.join('?' for _ in spalten)})",
                [self.clock()] + list(werte.values()))
            self._db.commit()
            neu = cur.lastrowid
        return self.musik(neu)  # type: ignore[return-value]

    def musik_aendern(self, musik_id: int, **felder: Any) -> Dict[str, Any]:
        werte = self._musik_werte(felder)
        if "titel" in werte and not werte["titel"]:
            raise ValueError("Das Musikstueck braucht einen Titel")
        if werte:
            with self._lock:
                self._db.execute(f"UPDATE musik SET {', '.join(k + ' = ?' for k in werte)} WHERE id = ?",
                                 list(werte.values()) + [musik_id])
                self._db.commit()
        m = self.musik(musik_id)
        if m is None:
            raise KeyError(musik_id)
        return m

    def musik_loeschen(self, musik_id: int) -> Optional[str]:
        m = self.musik(musik_id)
        if m is None:
            return None
        with self._lock:
            self._db.execute("DELETE FROM musik WHERE id = ?", (musik_id,))
            self._db.commit()
        return m["datei"] or None

    @staticmethod
    def _musik_werte(felder: Dict[str, Any]) -> Dict[str, Any]:
        werte: Dict[str, Any] = {}
        for k in _MUSIK_FELDER:
            if k in felder and felder[k] is not None:
                werte[k] = felder[k]
        for k in ("titel", "kuenstler", "lizenz", "quelle"):
            if k in werte:
                werte[k] = str(werte[k]).strip()[:200]
        if werte.get("quelle") and not re.match(r"https?://", werte["quelle"]):
            raise ValueError("Die Quelle bitte als Link (https://...)")
        if "ki" in werte:
            werte["ki"] = 1 if werte["ki"] else 0
        if "dauer" in werte:
            werte["dauer"] = max(0.0, float(werte["dauer"]))
        return werte
