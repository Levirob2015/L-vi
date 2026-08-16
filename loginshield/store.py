"""Persistenz (SQLite).

Bewusst eine einzelne Datei ohne Server: laesst sich mitkopieren, sichern und
im Zweifel mit ``sqlite3`` von Hand inspizieren. WAL-Modus, damit Dashboard,
CLI und Anwendung gleichzeitig zugreifen koennen.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Attempt, Block, Event

SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    ip         TEXT NOT NULL,
    event      TEXT NOT NULL,
    identity   TEXT NOT NULL DEFAULT '',
    route      TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT 'app',
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_attempts_ts        ON attempts(ts);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts     ON attempts(ip, ts);
CREATE INDEX IF NOT EXISTS idx_attempts_ident_ts  ON attempts(identity, ts);
CREATE INDEX IF NOT EXISTS idx_attempts_event_ts  ON attempts(event, ts);

CREATE TABLE IF NOT EXISTS blocks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    created_ts REAL NOT NULL,
    expires_ts REAL NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    strikes    INTEGER NOT NULL DEFAULT 0,
    active     INTEGER NOT NULL DEFAULT 1,
    detail     TEXT NOT NULL DEFAULT '',
    is_network INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_blocks_ip_active ON blocks(ip, active);
CREATE INDEX IF NOT EXISTS idx_blocks_created   ON blocks(created_ts);

CREATE TABLE IF NOT EXISTS allowlist (
    cidr       TEXT PRIMARY KEY,
    note       TEXT NOT NULL DEFAULT '',
    created_ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    """Thread-sicherer Zugriff auf die SQLite-Datenbank."""

    def __init__(self, path: str = "loginshield.db", *, identity_mode: str = "hashed",
                 identity_hmac_key: str = "") -> None:
        self.path = path
        self.identity_mode = identity_mode
        self._identity_key = (identity_hmac_key or "").encode("utf-8")
        self._lock = threading.RLock()

        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)

        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()
        if path != ":memory:":
            try:
                os.chmod(path, 0o600)  # enthaelt Angriffsdaten - nicht world-readable
            except OSError:  # pragma: no cover - plattformabhaengig
                pass

    def _migrate(self) -> None:
        """Ergaenzt Spalten, die in aelteren Datenbanken fehlen.

        Ein bestehendes loginshield.db soll nach einem Update einfach
        weiterlaufen, ohne dass jemand es von Hand anfassen muss.
        """
        columns = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(blocks)").fetchall()
        }
        if "is_network" not in columns:
            self._conn.execute(
                "ALTER TABLE blocks ADD COLUMN is_network INTEGER NOT NULL DEFAULT 0"
            )
            self._conn.commit()

    # -- Lebenszyklus --------------------------------------------------
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- Identitaeten --------------------------------------------------
    def identity_key(self, identity: Optional[str]) -> str:
        """Wandelt einen Benutzernamen in die Speicherform um.

        ``hashed`` (Default) speichert nur einen HMAC - im Dashboard sieht man
        dann ``user:1f3a9c02``. Damit taucht in der Angriffsdatenbank kein
        Klartext-Benutzername auf, Korrelation bleibt aber moeglich.
        """
        if not identity:
            return ""
        if self.identity_mode == "none":
            return ""
        if self.identity_mode == "plain":
            return identity[:200]
        raw = identity.strip().lower().encode("utf-8")
        if self._identity_key:
            digest = hmac.new(self._identity_key, raw, hashlib.sha256).hexdigest()
        else:
            digest = hashlib.sha256(raw).hexdigest()
        return "user:" + digest[:16]

    # -- Schreiben -----------------------------------------------------
    def record_attempt(
        self,
        ip: str,
        event: str,
        *,
        identity: Optional[str] = None,
        route: str = "",
        user_agent: str = "",
        source: str = "app",
        detail: str = "",
        ts: Optional[float] = None,
        prehashed_identity: bool = False,
    ) -> int:
        key = identity or "" if prehashed_identity else self.identity_key(identity)
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO attempts(ts, ip, event, identity, route, user_agent, source, detail)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    float(ts if ts is not None else time.time()),
                    ip or "",
                    event,
                    key,
                    (route or "")[:300],
                    (user_agent or "")[:300],
                    source,
                    (detail or "")[:500],
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    # -- Zaehler fuer die Erkennung ------------------------------------
    def last_success_ts(self, *, ip: Optional[str] = None,
                        identity_key: Optional[str] = None) -> float:
        """Zeitpunkt des letzten erfolgreichen Logins.

        Fehlversuche vor einem erfolgreichen Login zaehlen nicht mehr - sonst
        wuerde ein Nutzer, der sich morgens vertippt hat, abends gesperrt.
        """
        clauses = ["event = ?"]
        params: List[object] = [Event.LOGIN_SUCCESS]
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if identity_key:
            clauses.append("identity = ?")
            params.append(identity_key)
        sql = "SELECT MAX(ts) AS ts FROM attempts WHERE " + " AND ".join(clauses)
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return float(row["ts"]) if row and row["ts"] is not None else 0.0

    def count_failures_by_ip(self, ip: str, since: float) -> int:
        floor = max(since, self.last_success_ts(ip=ip))
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM attempts WHERE ip = ? AND event = ? AND ts > ?",
                (ip, Event.LOGIN_FAILURE, floor),
            ).fetchone()
        return int(row["n"])

    def count_failures_by_identity(self, identity_key: str, since: float) -> int:
        if not identity_key:
            return 0
        floor = max(since, self.last_success_ts(identity_key=identity_key))
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM attempts"
                " WHERE identity = ? AND event = ? AND ts > ?",
                (identity_key, Event.LOGIN_FAILURE, floor),
            ).fetchone()
        return int(row["n"])

    def distinct_identities_by_ip(self, ip: str, since: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT identity) AS n FROM attempts"
                " WHERE ip = ? AND event = ? AND ts > ? AND identity <> ''",
                (ip, Event.LOGIN_FAILURE, since),
            ).fetchone()
        return int(row["n"])

    def count_events(self, ip: str, event: str, since: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM attempts WHERE ip = ? AND event = ? AND ts > ?",
                (ip, event, since),
            ).fetchone()
        return int(row["n"])

    # -- Sperren -------------------------------------------------------
    def active_block(self, ip: str, now: Optional[float] = None) -> Optional[Block]:
        now = time.time() if now is None else now
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM blocks WHERE ip = ? AND active = 1 AND expires_ts > ?"
                " ORDER BY expires_ts DESC LIMIT 1",
                (ip, now),
            ).fetchone()
        return _row_to_block(row) if row else None

    def add_block(
        self,
        ip: str,
        *,
        seconds: float,
        reason: str,
        strikes: int = 0,
        detail: str = "",
        now: Optional[float] = None,
        is_network: bool = False,
    ) -> Block:
        now = time.time() if now is None else now
        expires = now + float(seconds)
        with self._lock:
            # Eine bestehende, kuerzere Sperre wird verlaengert statt dupliziert.
            existing = self._conn.execute(
                "SELECT * FROM blocks WHERE ip = ? AND active = 1 AND expires_ts > ?"
                " ORDER BY expires_ts DESC LIMIT 1",
                (ip, now),
            ).fetchone()
            if existing is not None:
                if expires <= float(existing["expires_ts"]):
                    return _row_to_block(existing)
                self._conn.execute(
                    "UPDATE blocks SET expires_ts = ?, reason = ?, strikes = ?, detail = ?,"
                    " is_network = ? WHERE id = ?",
                    (expires, reason, strikes, detail[:500],
                     1 if is_network else 0, existing["id"]),
                )
                self._conn.commit()
                row = self._conn.execute(
                    "SELECT * FROM blocks WHERE id = ?", (existing["id"],)
                ).fetchone()
                return _row_to_block(row)

            cursor = self._conn.execute(
                "INSERT INTO blocks(ip, created_ts, expires_ts, reason, strikes, active,"
                " detail, is_network) VALUES(?,?,?,?,?,1,?,?)",
                (ip, now, expires, reason, strikes, detail[:500],
                 1 if is_network else 0),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM blocks WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        return _row_to_block(row)

    def unblock(self, ip: str) -> int:
        """Hebt alle aktiven Sperren einer IP auf. Gibt die Anzahl zurueck."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE blocks SET active = 0 WHERE ip = ? AND active = 1", (ip,)
            )
            self._conn.commit()
            return int(cursor.rowcount)

    def expire_blocks(self, now: Optional[float] = None) -> List[str]:
        """Markiert abgelaufene Sperren als inaktiv, liefert die betroffenen IPs."""
        now = time.time() if now is None else now
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT ip FROM blocks WHERE active = 1 AND expires_ts <= ?",
                (now,),
            ).fetchall()
            if rows:
                self._conn.execute(
                    "UPDATE blocks SET active = 0 WHERE active = 1 AND expires_ts <= ?",
                    (now,),
                )
                self._conn.commit()
        return [row["ip"] for row in rows]

    def active_network_blocks(self, now: Optional[float] = None) -> List[Block]:
        """Alle aktiven Netzsperren. Wird gegen jede Anfrage geprueft und
        deshalb im Guard kurz zwischengespeichert."""
        now = time.time() if now is None else now
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM blocks WHERE active = 1 AND is_network = 1"
                " AND expires_ts > ? ORDER BY created_ts DESC",
                (now,),
            ).fetchall()
        return [_row_to_block(row) for row in rows]

    def blocked_ips_since(self, since: float,
                          include_networks: bool = False) -> List[str]:
        """Adressen, die seit ``since`` gesperrt wurden - Grundlage der
        Netzsperre."""
        sql = "SELECT DISTINCT ip FROM blocks WHERE created_ts > ?"
        if not include_networks:
            sql += " AND is_network = 0"
        with self._lock:
            rows = self._conn.execute(sql, (since,)).fetchall()
        return [row["ip"] for row in rows]

    def prior_block_count(self, ip: str, since: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM blocks WHERE ip = ? AND created_ts > ?",
                (ip, since),
            ).fetchone()
        return int(row["n"])

    def list_blocks(self, *, active_only: bool = True, limit: int = 200,
                    now: Optional[float] = None) -> List[Block]:
        now = time.time() if now is None else now
        sql = "SELECT * FROM blocks"
        params: List[object] = []
        if active_only:
            sql += " WHERE active = 1 AND expires_ts > ?"
            params.append(now)
        sql += " ORDER BY created_ts DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_block(row) for row in rows]

    # -- Allowlist -----------------------------------------------------
    def allow_add(self, cidr: str, note: str = "", now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO allowlist(cidr, note, created_ts) VALUES(?,?,?)",
                (cidr, note[:200], now),
            )
            self._conn.commit()

    def allow_remove(self, cidr: str) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM allowlist WHERE cidr = ?", (cidr,))
            self._conn.commit()
            return cursor.rowcount > 0

    def allow_list(self) -> List[Dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT cidr, note, created_ts FROM allowlist ORDER BY cidr"
            ).fetchall()
        return [dict(row) for row in rows]

    # -- Auswertung ----------------------------------------------------
    def recent_attempts(
        self,
        *,
        limit: int = 100,
        events: Optional[Sequence[str]] = None,
        ip: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[Attempt]:
        clauses: List[str] = []
        params: List[object] = []
        if events:
            clauses.append("event IN (%s)" % ",".join("?" for _ in events))
            params.extend(events)
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if since is not None:
            clauses.append("ts > ?")
            params.append(since)
        sql = "SELECT * FROM attempts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_attempt(row) for row in rows]

    def top_offenders(self, since: float, limit: int = 10) -> List[Dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, COUNT(*) AS failures, MAX(ts) AS last_seen,"
                "       COUNT(DISTINCT identity) AS identities"
                " FROM attempts WHERE event = ? AND ts > ?"
                " GROUP BY ip ORDER BY failures DESC, last_seen DESC LIMIT ?",
                (Event.LOGIN_FAILURE, since, int(limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, since: float, now: Optional[float] = None) -> Dict[str, object]:
        now = time.time() if now is None else now
        with self._lock:
            counts = self._conn.execute(
                "SELECT event, COUNT(*) AS n FROM attempts WHERE ts > ? GROUP BY event",
                (since,),
            ).fetchall()
            unique_ips = self._conn.execute(
                "SELECT COUNT(DISTINCT ip) AS n FROM attempts WHERE ts > ? AND event = ?",
                (since, Event.LOGIN_FAILURE),
            ).fetchone()
            active = self._conn.execute(
                "SELECT COUNT(*) AS n FROM blocks WHERE active = 1 AND expires_ts > ?",
                (now,),
            ).fetchone()
            new_blocks = self._conn.execute(
                "SELECT COUNT(*) AS n FROM blocks WHERE created_ts > ?", (since,)
            ).fetchone()
            total = self._conn.execute("SELECT COUNT(*) AS n FROM attempts").fetchone()

        by_event = {row["event"]: int(row["n"]) for row in counts}
        return {
            "window_start": since,
            "now": now,
            "failures": by_event.get(Event.LOGIN_FAILURE, 0),
            "successes": by_event.get(Event.LOGIN_SUCCESS, 0),
            "requests": by_event.get(Event.REQUEST, 0),
            "denied": by_event.get(Event.DENIED, 0),
            "honeypot": by_event.get(Event.HONEYPOT, 0),
            "suspicious": by_event.get(Event.SUSPICIOUS, 0),
            "attacking_ips": int(unique_ips["n"]),
            "active_blocks": int(active["n"]),
            "new_blocks": int(new_blocks["n"]),
            "events_total": int(total["n"]),
        }

    def failure_timeline(self, since: float, buckets: int = 24,
                         now: Optional[float] = None) -> List[Dict[str, float]]:
        """Fehlversuche pro Zeitfenster - Datenbasis fuer das Balkendiagramm."""
        now = time.time() if now is None else now
        buckets = max(1, int(buckets))
        span = max(1.0, now - since)
        width = span / buckets
        result = [
            {"start": since + index * width, "width": width, "failures": 0, "denied": 0}
            for index in range(buckets)
        ]
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, event FROM attempts WHERE ts > ? AND event IN (?, ?)",
                (since, Event.LOGIN_FAILURE, Event.DENIED),
            ).fetchall()
        for row in rows:
            index = int((float(row["ts"]) - since) / width)
            index = min(max(index, 0), buckets - 1)
            key = "failures" if row["event"] == Event.LOGIN_FAILURE else "denied"
            result[index][key] += 1
        return result

    # -- Merkmale fuer die Anomalie-Erkennung --------------------------
    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value)
            )
            self._conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def profile_by_ip(self, since: float, until: Optional[float] = None) -> Dict[str, dict]:
        """Fasst je Adresse zusammen, was sie im Zeitraum getan hat.

        Grundlage sowohl fuer das Lernen des Normalzustands als auch fuer
        die Bewertung einzelner Adressen.
        """
        clauses = ["ts > ?"]
        params: List[object] = [since]
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        sql = ("SELECT ip, event, route, user_agent, identity, ts FROM attempts"
               " WHERE " + " AND ".join(clauses))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        profile: Dict[str, dict] = {}
        for row in rows:
            entry = profile.setdefault(row["ip"], {
                "events": 0, "failures": 0, "successes": 0,
                "routes": set(), "agents": set(), "identities": set(),
                "hours": set(), "first_ts": row["ts"], "last_ts": row["ts"],
            })
            entry["events"] += 1
            if row["event"] == Event.LOGIN_FAILURE:
                entry["failures"] += 1
            elif row["event"] == Event.LOGIN_SUCCESS:
                entry["successes"] += 1
            if row["route"]:
                entry["routes"].add(row["route"])
            if row["user_agent"]:
                entry["agents"].add(row["user_agent"][:120])
            if row["identity"]:
                entry["identities"].add(row["identity"])
            entry["hours"].add(time.gmtime(row["ts"]).tm_hour)
            entry["first_ts"] = min(entry["first_ts"], row["ts"])
            entry["last_ts"] = max(entry["last_ts"], row["ts"])
        return profile

    def hourly_counts(self, since: float, event: Optional[str] = None,
                      now: Optional[float] = None) -> List[int]:
        """Ereignisse je voller Stunde - fuer die Erkennung von Lastspitzen."""
        now = time.time() if now is None else now
        sql = "SELECT ts FROM attempts WHERE ts > ?"
        params: List[object] = [since]
        if event:
            sql += " AND event = ?"
            params.append(event)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        buckets = max(1, int((now - since) // 3600))
        counts = [0] * buckets
        for row in rows:
            index = int((row["ts"] - since) // 3600)
            if 0 <= index < buckets:
                counts[index] += 1
        return counts

    def route_counts(self, since: float) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT route, COUNT(*) AS n FROM attempts"
                " WHERE ts > ? AND route <> '' GROUP BY route",
                (since,),
            ).fetchall()
        return {row["route"]: int(row["n"]) for row in rows}

    def agent_counts(self, since: float) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT user_agent, COUNT(*) AS n FROM attempts"
                " WHERE ts > ? AND user_agent <> '' GROUP BY user_agent",
                (since,),
            ).fetchall()
        return {row["user_agent"][:120]: int(row["n"]) for row in rows}

    # -- Pflege --------------------------------------------------------
    def prune(self, before: float) -> Tuple[int, int]:
        """Loescht alte Ereignisse und abgelaufene Sperren."""
        with self._lock:
            attempts = self._conn.execute(
                "DELETE FROM attempts WHERE ts < ?", (before,)
            ).rowcount
            blocks = self._conn.execute(
                "DELETE FROM blocks WHERE active = 0 AND expires_ts < ?", (before,)
            ).rowcount
            self._conn.commit()
        return int(attempts), int(blocks)

    def vacuum(self) -> None:
        with self._lock:
            self._conn.execute("VACUUM")
            self._conn.commit()

    def iter_attempts(self, since: float) -> Iterable[Attempt]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM attempts WHERE ts > ? ORDER BY ts", (since,)
            ).fetchall()
        for row in rows:
            yield _row_to_attempt(row)


def _row_to_attempt(row: sqlite3.Row) -> Attempt:
    return Attempt(
        id=int(row["id"]),
        ts=float(row["ts"]),
        ip=row["ip"],
        event=row["event"],
        identity=row["identity"],
        route=row["route"],
        user_agent=row["user_agent"],
        source=row["source"],
        detail=row["detail"],
    )


def _row_to_block(row: sqlite3.Row) -> Block:
    return Block(
        id=int(row["id"]),
        ip=row["ip"],
        created_ts=float(row["created_ts"]),
        expires_ts=float(row["expires_ts"]),
        reason=row["reason"],
        strikes=int(row["strikes"]),
        active=bool(row["active"]),
        detail=row["detail"],
        is_network=bool(row["is_network"]) if "is_network" in row.keys() else False,
    )
