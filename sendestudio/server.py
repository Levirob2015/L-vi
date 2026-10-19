"""Der Studio-Server: Studio-Oberflaeche, API und oeffentliche Seite in einem.

Oeffentlich (ohne Anmeldung):

    /                         Uebersicht aller Sendungen
    /s/<sendung>/             Sendung mit Folgen und Feed-Adresse
    /s/<sendung>/feed.xml     RSS-Feed fuer Podcast-Apps
    /s/<sendung>/<folge>/     einzelne Folge mit Player und Kapiteln
    /s/<sendung>/radio/       Radio: das Programm laeuft nach der Uhr
    /medien/<datei>           Audio/Video/Cover (nur Veroeffentlichtes)

Studio (mit Anmeldung): ``/studio`` und ``/api/...``.

Der Login ist mit LoginShield gegen Passwort-Raten geschuetzt: nach
mehreren Fehlversuchen wird die IP mit ansteigender Dauer gesperrt.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from loginshield.netutils import ip_in_networks, parse_networks

from . import feed, media, publish, radio, site, zweifaktor
from .config import Config, passwort_pruefen
from .store import Store
from .tresor import ENDUNG, Tresor, TresorFehler
from .version import __version__
from .ki import KiFehler
from .werkstatt import Werkstatt

log = logging.getLogger("sendestudio")

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
COOKIE = "studio_sitzung"
#: Mit HTTPS: Der Praefix verbietet dem Browser, das Cookie ohne Secure,
#: fuer Unterdomains oder einen anderen Pfad zu setzen.
COOKIE_SICHER = "__Host-studio"
SITZUNG_DAUER = 12 * 3600
_JSON_MAX = 1024 * 1024
_BLOCK = 256 * 1024

CSP_OEFFENTLICH = ("default-src 'self'; img-src 'self' data:; media-src 'self'; "
                   "script-src 'self'; style-src 'self'; base-uri 'none'; "
                   "form-action 'none'; frame-ancestors 'none'")
CSP_STUDIO = ("default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob: mediastream:; "
              "script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; "
              "form-action 'none'; frame-ancestors 'none'")


class ApiFehler(Exception):
    def __init__(self, status: int, meldung: str, **extra: Any) -> None:
        super().__init__(meldung)
        self.status = status
        self.meldung = meldung
        self.extra = extra


class Studio:
    """Alles, was der Server zur Laufzeit braucht."""

    def __init__(self, cfg: Config, *, guard: Any = "auto", clock=time.time,
                 tresor_iterationen: Optional[int] = None) -> None:
        self.cfg = cfg
        self.clock = clock
        os.makedirs(cfg.medienordner, exist_ok=True)
        # Datenbank, Schluessel und Aufnahmen gehen nur den Besitzer etwas an.
        for ordner in (cfg.datenordner, cfg.medienordner):
            os.chmod(ordner, 0o700)
        tresor_pfad = os.path.join(cfg.datenordner, "tresor.json")
        self.tresor = (Tresor(tresor_pfad) if tresor_iterationen is None
                       else Tresor(tresor_pfad, iterationen=tresor_iterationen))
        self.store = Store(os.path.join(cfg.datenordner, "sendestudio.db"), tresor=self.tresor)
        #: Sitzung -> (absolutes Ende, letzte Aktivitaet)
        self._sitzungen: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._abgleich_lock = threading.Lock()
        self.studio_netze = parse_networks(cfg.studio_netze)
        if guard == "auto":
            guard = self._loginshield()
        self.guard = guard
        self.werkstatt = Werkstatt(self)

    def _loginshield(self) -> Any:
        try:
            from loginshield import Config as SchutzConfig, Guard
        except ImportError:  # pragma: no cover - im selben Repository immer da
            log.warning("LoginShield nicht gefunden - Login ohne Schutz gegen Passwort-Raten")
            return None
        schutz = SchutzConfig()
        schutz.db_path = os.path.join(self.cfg.datenordner, "loginschutz.db")
        schutz.identity_hmac_key = self.cfg.geheimnis or secrets.token_hex(16)
        schutz.trusted_proxies = list(self.cfg.vertraute_proxys)
        return Guard(schutz)

    def close(self) -> None:
        self.werkstatt.schliessen()
        self.tresor.sperren()
        if self.guard is not None:
            self.guard.close()
        self.store.close()

    # -- Sitzungen -----------------------------------------------------
    def anmelden(self) -> str:
        token = secrets.token_urlsafe(32)
        jetzt = self.clock()
        with self._lock:
            # Erst eintragen, dann aufraeumen - sonst saehe das Aufraeumen
            # niemanden angemeldet und schloesse den Tresor gleich wieder.
            self._sitzungen[token] = (jetzt + SITZUNG_DAUER, jetzt)
            self._aufraeumen(jetzt)
        return token

    def gueltig(self, token: Optional[str]) -> bool:
        jetzt = self.clock()
        with self._lock:
            self._aufraeumen(jetzt)
            eintrag = self._sitzungen.get(token or "")
            if eintrag is None:
                return False
            self._sitzungen[token] = (eintrag[0], jetzt)  # type: ignore[index]
            return True

    def abmelden(self, token: Optional[str]) -> None:
        with self._lock:
            self._sitzungen.pop(token or "", None)
            self._aufraeumen(self.clock())

    def _aufraeumen(self, jetzt: float) -> None:
        """Abgelaufene Sitzungen weg. Ist niemand mehr da, schliesst der Tresor."""
        leerlauf = self.cfg.leerlauf_minuten * 60
        for t, (ende, zuletzt) in list(self._sitzungen.items()):
            if ende <= jetzt or zuletzt + leerlauf <= jetzt:
                del self._sitzungen[t]
        if not self._sitzungen and self.tresor.offen:
            self.tresor.sperren()
            log.info("Niemand mehr angemeldet - Tresor verschlossen")

    def totp_pruefen(self, eingabe: str) -> bool:
        zaehler = zweifaktor.pruefen(self.cfg.totp_geheimnis, eingabe, self.clock())
        with self._lock:
            # Ein Code gilt nur einmal - auch ein mitgelesener nuetzt nichts.
            # Gespeichert, damit das auch nach einem Neustart gilt.
            letzter = int(self.store.einstellung("totp_zaehler", "-1"))
            if zaehler is None or zaehler <= letzter:
                return False
            self.store.einstellung_setzen("totp_zaehler", str(zaehler))
        return True

    def studio_erlaubt(self, ip: Optional[str]) -> bool:
        return not self.studio_netze or ip_in_networks(ip, self.studio_netze)

    # -- Dateien -------------------------------------------------------
    def medium_pfad(self, name: str) -> Optional[Tuple[str, bool]]:
        """``(pfad, verschluesselt)`` der Datei hinter ``name`` - oder ``None``."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}", name) or name.endswith(ENDUNG):
            return None
        pfad = os.path.join(self.cfg.medienordner, name)
        if os.path.isfile(pfad):
            return pfad, False
        if os.path.isfile(pfad + ENDUNG):
            return pfad + ENDUNG, True
        return None

    def datei_weg(self, name: Optional[str]) -> None:
        if name and not self.store.datei_in_benutzung(name) and self.medium_pfad(name):
            pfad = os.path.join(self.cfg.medienordner, name)
            _weg(pfad)
            _weg(pfad + ENDUNG)

    def abgleichen(self) -> Dict[str, int]:
        """Oeffentliches im Klartext, alles andere verschluesselt.

        Laeuft nach jeder Aenderung und beim Entsperren. Ist der Tresor zu,
        bleibt alles, wie es ist - dann hat sich auch nichts geaendert.
        """
        ergebnis = {"verschluesselt": 0, "entschluesselt": 0}
        if not self.tresor.offen:
            return ergebnis
        with self._abgleich_lock:
            ergebnis["texte"] = self.store.entwuerfe_einschliessen()
            oeffentlich = set(publish.medien(self.store))
            ordner = self.cfg.medienordner
            for name in sorted(os.listdir(ordner)):
                if name.startswith(".") or name.endswith(".neu"):
                    continue
                pfad = os.path.join(ordner, name)
                if name.endswith(ENDUNG):
                    klar = name[:-len(ENDUNG)]
                    if klar in oeffentlich and not os.path.exists(os.path.join(ordner, klar)):
                        self.tresor.entschluesseln(pfad, os.path.join(ordner, klar))
                        ergebnis["entschluesselt"] += 1
                    if klar in oeffentlich:
                        _weg(pfad)
                elif name not in oeffentlich:
                    if not os.path.exists(pfad + ENDUNG):
                        self.tresor.verschluesseln(pfad, pfad + ENDUNG)
                        ergebnis["verschluesselt"] += 1
                    _weg(pfad)
        return ergebnis

    def basis_url(self, host_header: str = "") -> str:
        if self.cfg.basis_url:
            return self.cfg.basis_url
        # Ohne Einstellung: so, wie der Browser uns gerade erreicht.
        if host_header and re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", host_header):
            schema = "https" if self.cfg.sicheres_cookie else "http"
            return f"{schema}://{host_header}"
        return ""


def handler_fuer(studio: Studio):
    cookie_name = COOKIE_SICHER if studio.cfg.sicheres_cookie else COOKIE

    class Handler(BaseHTTPRequestHandler):
        # Keine Versionsnummern nach aussen - sie helfen nur Angreifern.
        server_version = "Sendestudio"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        #: Wer nach 60 Sekunden noch nichts geschickt hat, fliegt raus -
        #: sonst kann ein Angreifer mit halb offenen Verbindungen alle
        #: Faeden belegen (Slowloris).
        timeout = 60

        # -- Grundgeruest ---------------------------------------------
        def log_message(self, fmt: str, *args: Any) -> None:
            log.info("%s %s", self.client_address[0], fmt % args)

        def do_HEAD(self) -> None:
            self._verteilen("GET", nur_kopf=True)

        def do_GET(self) -> None:
            self._verteilen("GET")

        def do_POST(self) -> None:
            self._verteilen("POST")

        def do_PUT(self) -> None:
            self._verteilen("PUT")

        def do_DELETE(self) -> None:
            self._verteilen("DELETE")

        def _verteilen(self, methode: str, nur_kopf: bool = False) -> None:
            self._nur_kopf = nur_kopf
            teile = urlsplit(self.path)
            pfad = unquote(teile.path)
            self._query = parse_qs(teile.query)
            try:
                if self.headers.get("Transfer-Encoding"):
                    # Versteht dieser Server nicht - und uneinig gelesene
                    # Anfragegrenzen sind hinter einem Proxy ein Einfallstor
                    # (Request Smuggling). Lieber gar nicht.
                    raise ApiFehler(400, "Transfer-Encoding wird nicht unterstützt")
                if methode == "GET" and self.headers.get("Content-Length", "0") != "0":
                    self.close_connection = True  # ungelesener Koerper
                if pfad.startswith("/api/") or pfad.startswith("/studio"):
                    # Das Studio gibt es fuer fremde Netze gar nicht.
                    if not studio.studio_erlaubt(self._ip()):
                        raise ApiFehler(404, "Nicht gefunden")
                if pfad.startswith("/api/"):
                    self._api(methode, pfad[5:].strip("/").split("/"))
                elif methode != "GET":
                    raise ApiFehler(405, "Methode nicht erlaubt")
                elif pfad in ("/studio", "/studio/"):
                    self._statisch("studio.html", "text/html; charset=utf-8", CSP_STUDIO)
                elif pfad in ("/studio.js", "/studio.css"):
                    self._statisch(pfad[1:], "text/javascript; charset=utf-8"
                                   if pfad.endswith(".js") else "text/css; charset=utf-8", CSP_STUDIO)
                else:
                    self._oeffentlich(pfad)
            except ApiFehler as f:
                # Ein abgelehnter Upload hat seinen Koerper nicht gelesen -
                # die Verbindung ist danach nicht mehr verwendbar.
                self.close_connection = True
                if pfad.startswith("/api/"):
                    kopf = {}
                    if f.status == 429 and f.extra.get("retry_after"):
                        kopf["Retry-After"] = str(f.extra["retry_after"])
                    self._json(dict({"fehler": f.meldung}, **f.extra), f.status, kopf)
                else:
                    self._senden(f.status, f"<h1>{f.status}</h1><p>{f.meldung}</p>".encode(),
                                 "text/html; charset=utf-8")
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                log.exception("Fehler bei %s %s", methode, self.path)
                try:
                    self._json({"fehler": "Interner Fehler"}, 500)
                except OSError:
                    pass

        def _senden(self, status: int, inhalt: bytes, typ: str,
                    kopf: Optional[Dict[str, str]] = None, csp: str = CSP_OEFFENTLICH) -> None:
            self.send_response(status)
            self.send_header("Content-Type", typ)
            self.send_header("Content-Length", str(len(inhalt)))
            self._sicherheitskopf(csp)
            for k, v in (kopf or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if not self._nur_kopf:
                self.wfile.write(inhalt)

        def _sicherheitskopf(self, csp: str) -> None:
            self.send_header("Content-Security-Policy", csp)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            if studio.cfg.sicheres_cookie:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if csp is CSP_STUDIO:
                self.send_header("Permissions-Policy",
                                 "camera=(self), microphone=(self), display-capture=(self)")
                self.send_header("Cache-Control", "no-store")

        def _json(self, daten: Any, status: int = 200,
                  kopf: Optional[Dict[str, str]] = None) -> None:
            inhalt = json.dumps(daten, ensure_ascii=False).encode()
            self._senden(status, inhalt, "application/json; charset=utf-8",
                         dict({"Cache-Control": "no-store"}, **(kopf or {})), CSP_STUDIO)

        def _statisch(self, name: str, typ: str, csp: str) -> None:
            with open(os.path.join(STATIC, name), "rb") as f:
                self._senden(200, f.read(), typ, {"Cache-Control": "no-cache"}, csp)

        # -- Anmeldung ------------------------------------------------
        def _ip(self) -> Optional[str]:
            peer = self.client_address[0]
            if studio.guard is None:
                return peer
            return studio.guard.resolve_ip(peer, self.headers.get("X-Forwarded-For"))

        def _cookie(self) -> Optional[str]:
            for teil in (self.headers.get("Cookie") or "").split(";"):
                name, _, wert = teil.strip().partition("=")
                if name == cookie_name:
                    return wert
            return None

        def _angemeldet(self) -> bool:
            return studio.gueltig(self._cookie())

        def _login(self) -> None:
            ip = self._ip()
            if studio.guard is not None:
                entscheidung = studio.guard.check(ip, route="/api/login")
                if not entscheidung.allowed:
                    raise ApiFehler(429, "Zu viele Fehlversuche - bitte später erneut versuchen",
                                    retry_after=entscheidung.retry_after)
            daten = self._json_body()
            passwort = str(daten.get("passwort", ""))
            if not studio.cfg.passwort_hash:
                raise ApiFehler(503, "Kein Passwort eingerichtet - 'sendestudio passwort' ausführen")
            passt = passwort_pruefen(passwort, studio.cfg.passwort_hash)
            # Der Code wird immer geprueft, auch bei falschem Passwort - so
            # verraet die Antwort nicht, welcher der beiden Teile stimmte.
            code_ok = (not studio.cfg.totp_geheimnis
                       or studio.totp_pruefen(str(daten.get("code", ""))))
            if not (passt and code_ok):
                if studio.guard is not None:
                    e = studio.guard.record_failure(ip, identity="studio", route="/api/login",
                                                    user_agent=self.headers.get("User-Agent", ""))
                    if not e.allowed:
                        raise ApiFehler(429, "Zu viele Fehlversuche - die Adresse ist vorübergehend gesperrt",
                                        retry_after=e.retry_after)
                raise ApiFehler(401, "Passwort oder Code falsch" if studio.cfg.totp_geheimnis
                                else "Falsches Passwort")
            if studio.guard is not None:
                studio.guard.record_success(ip, identity="studio", route="/api/login")
            token = studio.anmelden()
            try:
                self._tresor_oeffnen(passwort)
            except BaseException:
                studio.abmelden(token)
                raise
            cookie = (f"{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; "
                      f"Max-Age={SITZUNG_DAUER}")
            if studio.cfg.sicheres_cookie:
                cookie += "; Secure"
            self._json({"ok": True}, kopf={"Set-Cookie": cookie})

        def _tresor_oeffnen(self, passwort: str) -> None:
            tresor = studio.tresor
            if not tresor.existiert:
                # Aeltere Installation: Der Tresor entsteht bei der ersten
                # Anmeldung, und alle Entwuerfe werden gleich verschluesselt.
                tresor.anlegen(passwort)
                log.warning("Tresor angelegt. Fuer einen Wiederherstellungsschluessel "
                            "'sendestudio passwort' ausfuehren.")
            elif not tresor.offen:
                try:
                    tresor.entsperren(passwort)
                except TresorFehler:
                    log.error("Passwort stimmt, Tresor laesst sich damit aber nicht oeffnen - "
                              "wurde das Passwort an der Konfiguration vorbei geaendert?")
                    raise ApiFehler(500, "Der Tresor lässt sich mit diesem Passwort nicht öffnen. "
                                    "'sendestudio passwort' mit dem Wiederherstellungsschlüssel ausführen.")
            erg = studio.abgleichen()
            if erg["verschluesselt"]:
                log.info("%d Datei(en) in den Tresor gelegt", erg["verschluesselt"])

        # -- API ------------------------------------------------------
        def _api(self, methode: str, teile: list) -> None:
            if methode != "GET":
                # Ein eigener Kopf laesst sich von fremden Seiten nicht ohne
                # CORS-Freigabe setzen - das genuegt gegen CSRF, zusammen mit
                # SameSite=Strict am Cookie.
                if self.headers.get("X-Studio") != "1":
                    raise ApiFehler(403, "Anfrage ohne Studio-Kennung")
                if teile[-1:] not in (["medium"], ["cover"]):
                    # Den Koerper immer ganz lesen, auch wo er nicht gebraucht
                    # wird. Bliebe ein Rest im Strom, laese der Server ihn bei
                    # wiederverwendeter Verbindung als naechste Anfrage.
                    self._daten = self._json_lesen()
            if teile == ["login"] and methode == "POST":
                return self._login()
            if teile == ["status"] and methode == "GET":
                if not self._angemeldet():
                    # Vor der Anmeldung nur, was das Login-Formular braucht.
                    return self._json({"angemeldet": False,
                                       "zweifaktor": bool(studio.cfg.totp_geheimnis)})
                return self._json({
                    "angemeldet": True,
                    "version": __version__,
                    "ffmpeg": media.ffmpeg_verfuegbar(),
                    "basis_url": studio.basis_url(self.headers.get("Host", "")),
                    "seitentitel": studio.cfg.seitentitel,
                    "ftp": bool(studio.cfg.ftp.host),
                    "export_ziel": studio.cfg.pfad(studio.cfg.export_ziel),
                    "zweifaktor": bool(studio.cfg.totp_geheimnis),
                    "tresor": studio.tresor.offen,
                    "leerlauf_minuten": studio.cfg.leerlauf_minuten,
                    "ki": studio.werkstatt.status(),
                })
            if studio.guard is not None:
                e = studio.guard.check(self._ip(), route="/api", count_request=False)
                if not e.allowed:
                    raise ApiFehler(429, "Adresse gesperrt", retry_after=e.retry_after)
            if not self._angemeldet():
                raise ApiFehler(401, "Bitte anmelden")
            if teile == ["logout"] and methode == "POST":
                studio.abmelden(self._cookie())
                weg = f"{cookie_name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                if studio.cfg.sicheres_cookie:
                    weg += "; Secure"
                return self._json({"ok": True}, kopf={"Set-Cookie": weg})

            st = studio.store
            if teile[0] == "sendungen":
                if len(teile) == 1:
                    if methode == "GET":
                        return self._json(st.sendungen())
                    if methode == "POST":
                        d = self._json_body()
                        return self._json(self._wert(lambda: st.sendung_anlegen(
                            d.pop("titel", ""), d.pop("art", "podcast"), **_nur(d))), 201)
                sid = _id(teile[1])
                if st.sendung(sid) is None:
                    raise ApiFehler(404, "Sendung nicht gefunden")
                if len(teile) == 2:
                    if methode == "GET":
                        return self._json(st.sendung(sid))
                    if methode == "PUT":
                        d = self._json_body()
                        return self._json(self._wert(lambda: st.sendung_aendern(sid, **_nur(d))))
                    if methode == "DELETE":
                        for name in st.sendung_loeschen(sid):
                            studio.datei_weg(name)
                        studio.abgleichen()
                        return self._json({"ok": True})
                if teile[2:] == ["cover"] and methode == "PUT":
                    return self._cover(sid)
                if teile[2:] == ["folgen"]:
                    if methode == "GET":
                        return self._json(st.folgen(sid))
                    if methode == "POST":
                        d = self._json_body()
                        return self._json(self._wert(lambda: st.folge_anlegen(
                            sid, d.pop("titel", ""), **_nur(d, ("beschreibung", "kapitel", "ki")))),
                            201)
            if teile[0] == "folgen" and len(teile) >= 2:
                fid = _id(teile[1])
                if st.folge(fid) is None:
                    raise ApiFehler(404, "Folge nicht gefunden")
                rest = teile[2:]
                if not rest:
                    if methode == "GET":
                        return self._json(st.folge(fid))
                    if methode == "PUT":
                        d = self._json_body()
                        return self._json(self._wert(lambda: st.folge_aendern(
                            fid, **_nur(d, ("titel", "beschreibung", "kapitel", "ki")))))
                    if methode == "DELETE":
                        studio.datei_weg(st.folge_loeschen(fid))
                        studio.abgleichen()
                        return self._json({"ok": True})
                if rest == ["medium"] and methode == "PUT":
                    return self._medium(fid)
                if rest == ["veroeffentlichen"] and methode == "POST":
                    neu = self._wert(lambda: st.veroeffentlichen(fid))
                    studio.abgleichen()  # erst jetzt entsteht die lesbare Datei
                    return self._json(neu)
                if rest == ["zurueckziehen"] and methode == "POST":
                    neu = st.zurueckziehen(fid)
                    studio.abgleichen()  # zurueck in den Tresor
                    return self._json(neu)
            if teile[0] == "ki":
                return self._ki(methode, teile[1:])
            if teile == ["export"] and methode == "POST":
                return self._json(publish.exportieren(
                    st, studio.cfg.medienordner, studio.cfg.pfad(studio.cfg.export_ziel),
                    basis_url=studio.cfg.basis_url, seitentitel=studio.cfg.seitentitel))
            if teile == ["ftp"] and methode == "POST":
                return self._ftp()
            raise ApiFehler(404, "Unbekannte Schnittstelle")

        def _ki(self, methode: str, teile: list) -> None:
            werkstatt = studio.werkstatt
            try:
                if teile == [] and methode == "GET":
                    return self._json(werkstatt.status())
                if teile == ["auftraege"] and methode == "POST":
                    return self._json(werkstatt.starten(self._json_body()), 202)
                if len(teile) == 2 and teile[0] == "auftraege" and methode == "GET":
                    auftrag = werkstatt.auftrag(teile[1])
                    if auftrag is None:
                        raise ApiFehler(404, "Auftrag nicht gefunden")
                    return self._json(auftrag)
            except KiFehler as f:
                raise ApiFehler(f.status, str(f))
            raise ApiFehler(404, "Unbekannte Schnittstelle")

        def _wert(self, aufruf):
            try:
                return aufruf()
            except ValueError as f:
                raise ApiFehler(400, str(f))
            except TypeError as f:
                raise ApiFehler(400, f"Ungültige Felder: {f}")

        def _json_body(self) -> Dict[str, Any]:
            return dict(self._daten)

        def _json_lesen(self) -> Dict[str, Any]:
            try:
                laenge = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ApiFehler(400, "Ungültige Länge")
            if laenge < 0 or laenge > _JSON_MAX:
                raise ApiFehler(413, "Anfrage zu groß")
            try:
                daten = json.loads(self.rfile.read(laenge) or b"{}")
            except ValueError:
                raise ApiFehler(400, "Kein gültiges JSON")
            if not isinstance(daten, dict):
                raise ApiFehler(400, "JSON-Objekt erwartet")
            return daten

        def _hochladen(self) -> Tuple[str, bytes]:
            """Nimmt den Rohkoerper der Anfrage als Datei entgegen."""
            try:
                laenge = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ApiFehler(400, "Ungültige Länge")
            if laenge <= 0:
                raise ApiFehler(400, "Leere Datei")
            if laenge > studio.cfg.max_upload_mb * 1024 * 1024:
                raise ApiFehler(413, f"Datei größer als {studio.cfg.max_upload_mb} MB")
            tmp = os.path.join(studio.cfg.medienordner, f".hochladen-{secrets.token_hex(8)}")
            kopf = b""
            try:
                with open(tmp, "wb") as f:
                    rest = laenge
                    while rest:
                        block = self.rfile.read(min(_BLOCK, rest))
                        if not block:
                            raise ApiFehler(400, "Übertragung abgebrochen")
                        if len(kopf) < 64:
                            kopf += block[:64 - len(kopf)]
                        f.write(block)
                        rest -= len(block)
            except BaseException:
                _weg(tmp)
                raise
            return tmp, kopf

        def _medium(self, fid: int) -> None:
            st = studio.store
            folge = st.folge(fid)
            tmp, kopf = self._hochladen()
            q = self._query
            normalisieren = q.get("normalisieren", ["0"])[0] == "1"
            # Zufaelliger Name: Er soll vor der Veroeffentlichung nichts verraten.
            basis = f"m-{secrets.token_hex(10)}"
            try:
                info = media.aufbereiten(tmp, studio.cfg.medienordner, basis,
                                         normalisieren=normalisieren, kopf=kopf)
            except ValueError as f:
                _weg(tmp)
                raise ApiFehler(415, str(f))
            dauer = info["dauer"]
            if not dauer:
                # Ohne ffprobe: was der Browser gemessen hat.
                try:
                    dauer = float(q.get("dauer", ["0"])[0])
                except ValueError:
                    dauer = 0.0
            alt = folge["datei"]
            neu = st.folge_aendern(fid, datei=info["datei"], mime=info["mime"],
                                   groesse=info["groesse"], dauer=dauer)
            studio.datei_weg(alt)
            studio.abgleichen()  # ein Entwurf verschwindet sofort im Tresor
            self._json(neu)

        def _cover(self, sid: int) -> None:
            tmp, _ = self._hochladen()
            s = studio.store.sendung(sid)
            try:
                name = media.bild_speichern(tmp, studio.cfg.medienordner,
                                            f"cover-{secrets.token_hex(10)}")
            except ValueError as f:
                raise ApiFehler(415, str(f))
            alt = s["cover"]
            neu = studio.store.sendung_aendern(sid, cover=name, cover_ki=False)
            studio.datei_weg(alt)
            studio.abgleichen()
            self._json(neu)

        def _ftp(self) -> None:
            ftp = studio.cfg.ftp
            if not ftp.host:
                raise ApiFehler(400, "Kein FTP-Zugang eingerichtet (sendestudio.json → ftp)")
            if not studio.cfg.basis_url:
                raise ApiFehler(400, "Bitte zuerst basis_url einstellen - sonst gibt es keinen Feed")
            ziel = studio.cfg.pfad(studio.cfg.export_ziel)
            export = publish.exportieren(studio.store, studio.cfg.medienordner, ziel,
                                         basis_url=studio.cfg.basis_url,
                                         seitentitel=studio.cfg.seitentitel)
            try:
                ergebnis = publish.ftp_hochladen(ziel, host=ftp.host, benutzer=ftp.benutzer,
                                                 passwort=ftp.passwort, pfad=ftp.pfad,
                                                 port=ftp.port, tls=ftp.tls)
            except Exception as f:
                raise ApiFehler(502, f"FTP-Fehler: {f}")
            self._json(dict(export, **ergebnis))

        # -- Oeffentliche Seite ---------------------------------------
        def _oeffentlich(self, pfad: str) -> None:
            cfg = studio.cfg
            st = studio.store
            titel = cfg.seitentitel
            html_typ = "text/html; charset=utf-8"
            seite_kopf = {"Cache-Control": "no-cache"}
            if pfad in ("/", "/index.html"):
                return self._senden(200, site.startseite(publish.oeffentlich(st), titel).encode(),
                                    html_typ, seite_kopf)
            if pfad == "/stil.css":
                return self._senden(200, site.STIL.encode(), "text/css; charset=utf-8", seite_kopf)
            if pfad == "/seite.js":
                return self._senden(200, site.SEITE_JS.encode(),
                                    "text/javascript; charset=utf-8", seite_kopf)
            if pfad.startswith("/medien/"):
                return self._medium_senden(pfad[len("/medien/"):])
            m = re.fullmatch(r"/s/([a-z0-9-]+)(/.*)?", pfad)
            if not m:
                raise ApiFehler(404, "Nicht gefunden")
            s = st.sendung_nach_slug(m.group(1))
            folgen = st.folgen(s["id"], nur_online=True) if s else []
            if not s or not folgen:
                raise ApiFehler(404, "Nicht gefunden")
            rest = m.group(2) or ""
            if rest == "":
                return self._umleiten(pfad + "/")
            if rest in ("/", "/index.html"):
                return self._senden(200, site.sendung_seite(
                    s, folgen, titel, studio.basis_url(self.headers.get("Host", ""))).encode(),
                    html_typ, seite_kopf)
            if rest == "/feed.xml":
                basis = studio.basis_url(self.headers.get("Host", ""))
                return self._senden(200, feed.feed(s, folgen, basis).encode(),
                                    "application/rss+xml; charset=utf-8", seite_kopf)
            if rest in ("/radio", "/radio/") and s["art"] == "radio" and radio.programm(folgen):
                if rest == "/radio":
                    return self._umleiten(pfad + "/")
                return self._senden(200, site.radio_seite(s, folgen, titel).encode(),
                                    html_typ, seite_kopf)
            m2 = re.fullmatch(r"/([a-z0-9-]+)(/?)(index\.html)?", rest)
            if m2:
                f = next((x for x in folgen if x["slug"] == m2.group(1)), None)
                if f:
                    if not m2.group(2):
                        return self._umleiten(pfad + "/")
                    return self._senden(200, site.folge_seite(
                        s, f, titel, studio.basis_url(self.headers.get("Host", ""))).encode(),
                        html_typ, seite_kopf)
            raise ApiFehler(404, "Nicht gefunden")

        def _umleiten(self, ziel: str) -> None:
            self._senden(301, b"", "text/plain", {"Location": ziel})

        def _medium_senden(self, name: str) -> None:
            gefunden = studio.medium_pfad(name)
            if gefunden is None:
                raise ApiFehler(404, "Nicht gefunden")
            pfad, verschluesselt = gefunden
            # Entwuerfe sieht nur das Studio.
            oeffentlich = name in publish.medien(studio.store)
            if not oeffentlich and not self._angemeldet():
                raise ApiFehler(404, "Nicht gefunden")
            if verschluesselt and not studio.tresor.offen:
                raise ApiFehler(423, "Tresor verschlossen - bitte neu anmelden")
            groesse = studio.tresor.klartext_groesse(pfad) if verschluesselt else os.path.getsize(pfad)
            start, ende, status = 0, groesse - 1, 200
            bereich = self.headers.get("Range", "")
            m = re.fullmatch(r"bytes=(\d{1,15})?-(\d{1,15})?", bereich.strip())
            if m and (m.group(1) or m.group(2)):
                if m.group(1):
                    start = int(m.group(1))
                    if m.group(2):
                        ende = min(int(m.group(2)), groesse - 1)
                else:
                    start = max(0, groesse - int(m.group(2)))
                if start > ende or start >= groesse:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{groesse}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                status = 206
            laenge = max(0, ende - start + 1)
            self.send_response(status)
            self.send_header("Content-Type", media.mime_fuer(name))
            self.send_header("Content-Length", str(laenge))
            self.send_header("Accept-Ranges", "bytes")
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{ende}/{groesse}")
            self.send_header("Last-Modified", self.date_time_string(int(os.path.getmtime(pfad))))
            # Dateinamen enthalten einen Zufallsteil - eine neue Aufnahme
            # bekommt einen neuen Namen. Lange zwischenspeichern ist sicher.
            self.send_header("Cache-Control", "public, max-age=604800" if oeffentlich else "private, no-store")
            self._sicherheitskopf(CSP_OEFFENTLICH)
            self.end_headers()
            if self._nur_kopf or not laenge:
                return
            if verschluesselt:
                for teil in studio.tresor.lesen(pfad, start, ende):
                    self.wfile.write(teil)
                return
            with open(pfad, "rb") as f:
                f.seek(start)
                rest = laenge
                while rest:
                    block = f.read(min(_BLOCK, rest))
                    if not block:
                        break
                    self.wfile.write(block)
                    rest -= len(block)

    return Handler


def _id(text: str) -> int:
    if not text.isdigit():
        raise ApiFehler(404, "Nicht gefunden")
    return int(text)


def _nur(d: Dict[str, Any], erlaubt: Tuple[str, ...] = (
        "titel", "art", "beschreibung", "autor", "sprache", "kategorie")) -> Dict[str, Any]:
    """Nur bekannte Felder - Datei, Cover usw. setzt die API nie direkt."""
    return {k: v for k, v in d.items() if k in erlaubt}


def _weg(pfad: str) -> None:
    try:
        os.remove(pfad)
    except OSError:
        pass


class _Server(ThreadingHTTPServer):
    """Wie ThreadingHTTPServer, aber mit Obergrenze fuer gleichzeitige Verbindungen.

    Sonst bekommt jede Verbindung einen eigenen Faden - wer tausende
    aufmacht, legt den Rechner lahm. Was ueber der Grenze liegt, wird sofort
    geschlossen; laufende Uploads und Hoerer bleiben unberuehrt.
    """

    daemon_threads = True
    max_verbindungen = 256

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._plaetze = threading.BoundedSemaphore(self.max_verbindungen)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._plaetze.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._plaetze.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._plaetze.release()


def server_starten(studio: Studio, host: Optional[str] = None,
                   port: Optional[int] = None) -> ThreadingHTTPServer:
    server = _Server((host or studio.cfg.host, studio.cfg.port if port is None else port),
                     handler_fuer(studio))
    return server
