"""Die KI-Werkstatt: KI-Auftraege im Hintergrund.

Ein Bild dauert eine halbe Minute, ein KI-Video mehrere Minuten - zu lang
fuer eine einzelne HTTP-Anfrage. Deshalb wird ein Auftrag angenommen, laeuft
in einem eigenen Faden, und das Studio fragt seinen Stand ab.

Alles, was dabei entsteht, wird ein **Entwurf** (also sofort verschluesselt
im Tresor) und ist als KI-generiert gekennzeichnet. Veroeffentlicht wird
nichts automatisch.
"""

from __future__ import annotations

import contextlib
import datetime
import logging
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterator, List, Optional

from . import media
from .ki import AUFGABEN, Ki, KiFehler, segmente_als_text
from .store import ARTEN

log = logging.getLogger("sendestudio.ki")

ARTEN_AUFTRAG = ("text", "aus_aufnahme", "cover", "stimme", "video_aufnahme", "video_ki",
                 "musik_ki", "musikbett")
_MAX_WARTEND = 4
_MAX_GEMERKT = 50


class Werkstatt:
    def __init__(self, studio: Any) -> None:
        self.studio = studio
        self.ki = Ki(studio.cfg.ki, zaehlen=self._zaehlen)
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ki")
        self._auftraege: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def schliessen(self) -> None:
        self._pool.shutdown(wait=False)

    def _zaehlen(self) -> bool:
        return self.studio.store.ki_zaehlen(datetime.date.today().isoformat(),
                                            self.studio.cfg.ki.tageslimit)

    def status(self) -> Dict[str, Any]:
        heute = self.studio.store.ki_heute(datetime.date.today().isoformat())
        return dict(self.ki.faehigkeiten(), heute=heute, tageslimit=self.studio.cfg.ki.tageslimit)

    # ------------------------------------------------------------------
    # Auftraege
    # ------------------------------------------------------------------
    def starten(self, daten: Dict[str, Any]) -> Dict[str, Any]:
        art = daten.get("art")
        if art not in ARTEN_AUFTRAG:
            raise KiFehler(f"Unbekannte Auftragsart: {art!r}", 400)
        pruefen = getattr(self, f"_pruefen_{art}")
        arbeit = getattr(self, f"_auftrag_{art}")
        pruefen(daten)  # Fehler in der Eingabe sofort melden, nicht erst im Hintergrund
        with self._lock:
            offen = [a for a in self._auftraege.values() if a["status"] == "laeuft"]
            if len(offen) >= _MAX_WARTEND:
                raise KiFehler("Es laufen schon mehrere KI-Aufträge – bitte warten", 429)
            auftrag = {"id": secrets.token_hex(8), "art": art, "status": "laeuft",
                       "schritt": "Wartet …", "ergebnis": None, "fehler": None,
                       "erstellt": time.time()}
            self._auftraege[auftrag["id"]] = auftrag
            # Alte, erledigte Auftraege vergessen
            for alt in sorted(self._auftraege.values(), key=lambda a: a["erstellt"])[
                    :max(0, len(self._auftraege) - _MAX_GEMERKT)]:
                if alt["status"] != "laeuft":
                    del self._auftraege[alt["id"]]
        self._pool.submit(self._ausfuehren, auftrag, arbeit, daten)
        return dict(auftrag)

    def auftrag(self, auftrag_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._auftraege.get(auftrag_id)
            return dict(a) if a else None

    def _ausfuehren(self, auftrag: Dict[str, Any], arbeit: Any, daten: Dict[str, Any]) -> None:
        def schritt(text: str) -> None:
            with self._lock:
                auftrag["schritt"] = text
        try:
            ergebnis = arbeit(daten, schritt)
            with self._lock:
                auftrag.update(status="fertig", ergebnis=ergebnis, schritt="Fertig")
        except (KiFehler, ValueError) as f:
            with self._lock:
                auftrag.update(status="fehler", fehler=str(f), schritt="Fehlgeschlagen")
        except Exception:
            log.exception("KI-Auftrag %s fehlgeschlagen", auftrag["art"])
            with self._lock:
                auftrag.update(status="fehler", fehler="Interner Fehler – siehe Server-Log",
                               schritt="Fehlgeschlagen")

    # ------------------------------------------------------------------
    # Hilfen
    # ------------------------------------------------------------------
    def _faehig(self, *was: str) -> None:
        f = self.ki.faehigkeiten()
        for w in was:
            if not f.get(w):
                hinweis = {
                    "text": "Für KI-Texte: Anthropic-Schlüssel (ANTHROPIC_API_KEY) und "
                            "'pip install anthropic'",
                    "video": "Für Videos: OpenAI-Schlüssel und ffmpeg",
                }.get(w, "Dafür fehlt ein OpenAI-Schlüssel (OPENAI_API_KEY)")
                raise KiFehler(f"Nicht eingerichtet. {hinweis}", 501)

    def _sendung(self, daten: Dict[str, Any]) -> Dict[str, Any]:
        try:
            s = self.studio.store.sendung(int(daten.get("sendung_id")))
        except (TypeError, ValueError):
            s = None
        if s is None:
            raise KiFehler("Sendung nicht gefunden", 404)
        return s

    def _folge(self, daten: Dict[str, Any], mit_datei: bool = True) -> Dict[str, Any]:
        try:
            f = self.studio.store.folge(int(daten.get("folge_id")))
        except (TypeError, ValueError):
            f = None
        if f is None:
            raise KiFehler("Folge nicht gefunden", 404)
        if mit_datei and not f["datei"]:
            raise KiFehler("Die Folge hat noch keine Aufnahme", 400)
        return f

    @staticmethod
    def _text(daten: Dict[str, Any], feld: str, name: str, laenge: int = 20000) -> str:
        wert = str(daten.get(feld) or "").strip()
        if not wert:
            raise KiFehler(f"Bitte {name} angeben", 400)
        return wert[:laenge]

    @staticmethod
    def _minuten(daten: Dict[str, Any], standard: float, hoechstens: float) -> float:
        try:
            m = float(daten.get("dauer_minuten") or standard)
        except (TypeError, ValueError):
            raise KiFehler("Die Länge bitte in Minuten angeben", 400)
        if not 0.5 <= m <= hoechstens:
            raise KiFehler(f"Länge zwischen 0,5 und {hoechstens:g} Minuten", 400)
        return m

    def _material(self, s: Dict[str, Any]) -> Dict[str, Any]:
        return {"sendung": s["titel"], "beschreibung_sendung": s["beschreibung"],
                "art": ARTEN[s["art"]]}

    def _arbeitsdatei(self, endung: str) -> str:
        return os.path.join(self.studio.cfg.medienordner,
                            f".ki-{secrets.token_hex(8)}{endung}")

    @contextlib.contextmanager
    def _klartext(self, name: str) -> Iterator[str]:
        """Pfad zu einer lesbaren Fassung der Datei - auch wenn sie im Tresor liegt."""
        gefunden = self.studio.medium_pfad(name)
        if gefunden is None:
            raise KiFehler("Datei nicht gefunden", 404)
        pfad, verschluesselt = gefunden
        if not verschluesselt:
            yield pfad
            return
        if not self.studio.tresor.offen:
            raise KiFehler("Tresor verschlossen – bitte neu anmelden", 423)
        tmp = self._arbeitsdatei(os.path.splitext(name)[1])
        try:
            self.studio.tresor.entschluesseln(pfad, tmp)
            yield tmp
        finally:
            _weg(tmp)

    def _neue_folge(self, sendung_id: int, titel: str, beschreibung: str, quelle: str,
                    ki: List[str], kapitel: Optional[list] = None,
                    musik: Optional[list] = None, sprechtext: str = "") -> Dict[str, Any]:
        """Legt aus einer erzeugten Datei einen Entwurf an (und schliesst ihn weg)."""
        st = self.studio.store
        folge = st.folge_anlegen(sendung_id, titel[:200], beschreibung=beschreibung,
                                 kapitel=kapitel or [], ki=ki, musik=musik or [],
                                 sprechtext=sprechtext)
        try:
            info = media.aufbereiten(quelle, self.studio.cfg.medienordner,
                                     f"m-{secrets.token_hex(10)}")
        except BaseException:
            st.folge_loeschen(folge["id"])
            _weg(quelle)
            raise
        folge = st.folge_aendern(folge["id"], datei=info["datei"], mime=info["mime"],
                                 groesse=info["groesse"], dauer=info["dauer"])
        self.studio.abgleichen()
        return folge

    # ------------------------------------------------------------------
    # 1. Text
    # ------------------------------------------------------------------
    def _pruefen_text(self, daten: Dict[str, Any]) -> None:
        self._faehig("text")
        if daten.get("aufgabe") not in AUFGABEN or daten.get("aufgabe") == "szenen":
            raise KiFehler("Unbekannte Text-Aufgabe", 400)
        if not isinstance(daten.get("eingaben", {}), dict):
            raise KiFehler("eingaben muss ein Objekt sein", 400)
        if daten.get("sendung_id") is not None:
            self._sendung(daten)

    def _auftrag_text(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        eingaben = dict(daten.get("eingaben") or {})
        sprache = "de"
        if daten.get("sendung_id") is not None:
            s = self._sendung(daten)
            eingaben = dict(self._material(s), **eingaben)
            sprache = s["sprache"]
        schritt("Claude schreibt …")
        return {"aufgabe": daten["aufgabe"],
                "antwort": self.ki.schreiben(daten["aufgabe"], eingaben, sprache)}

    # ------------------------------------------------------------------
    # 2. Aus der Aufnahme: Transkript -> Shownotes, Kapitel, Titel
    # ------------------------------------------------------------------
    def _pruefen_aus_aufnahme(self, daten: Dict[str, Any]) -> None:
        self._faehig("transkript", "text")
        self._folge(daten)

    def _auftrag_aus_aufnahme(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        f = self._folge(daten)
        s = self.studio.store.sendung(f["sendung_id"])
        schritt("Aufnahme wird abgeschrieben …")
        with self._klartext(f["datei"]) as pfad:
            transkript = self.ki.transkribieren(pfad, s["sprache"])
        if not transkript["text"].strip():
            raise KiFehler("In der Aufnahme wurde keine Sprache erkannt", 422)
        material = dict(self._material(s), titel=f["titel"],
                        transkript=segmente_als_text(transkript["segmente"])
                        if transkript["segmente"] else transkript["text"])
        schritt("Shownotes werden geschrieben …")
        shownotes = self.ki.schreiben("shownotes", material, s["sprache"])
        kapitel: list = []
        if transkript["segmente"]:
            schritt("Kapitel werden gesetzt …")
            dauer = f["dauer"] or transkript["segmente"][-1]["ende"]
            kapitel = [k for k in self.ki.schreiben("kapitel", material, s["sprache"])["kapitel"]
                       if 0 <= float(k["zeit"]) <= dauer]
        schritt("Titel werden vorgeschlagen …")
        titel = self.ki.schreiben("titel", material, s["sprache"])["vorschlaege"]
        return {"transkript": transkript["text"], "shownotes": shownotes,
                "kapitel": kapitel, "titel": titel[:8]}

    # ------------------------------------------------------------------
    # 3. Cover
    # ------------------------------------------------------------------
    def _pruefen_cover(self, daten: Dict[str, Any]) -> None:
        self._faehig("bild")
        self._sendung(daten)
        self._text(daten, "beschreibung", "eine Bildbeschreibung", 4000)

    def _auftrag_cover(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        s = self._sendung(daten)
        schritt("Bild wird gemalt …")
        bild = self.ki.bild(self._text(daten, "beschreibung", "eine Bildbeschreibung", 4000)
                            + "\nQuadratisches Podcast-Cover, keine Schrift im Bild.",
                            "1024x1024")
        # Vergroessern in der versteckten Arbeitsdatei, erst dann ablegen: Eine
        # halb geschriebene Datei im Medienordner koennte sonst gleichzeitig
        # vom Tresor-Abgleich weggeschlossen werden.
        tmp = self._arbeitsdatei(media.erkennen(bild[:64])[0])
        try:
            with open(tmp, "wb") as f:
                f.write(bild)
            media.bild_mindestgroesse(tmp)
        except BaseException:
            _weg(tmp)
            raise
        name = media.bild_speichern(tmp, self.studio.cfg.medienordner,
                                    f"cover-{secrets.token_hex(10)}")
        alt = s["cover"]
        neu = self.studio.store.sendung_aendern(s["id"], cover=name, cover_ki=True)
        self.studio.datei_weg(alt)
        self.studio.abgleichen()
        return {"sendung": neu}

    # ------------------------------------------------------------------
    # 4. Text -> KI-Stimme -> neue Folge
    # ------------------------------------------------------------------
    def _pruefen_stimme(self, daten: Dict[str, Any]) -> None:
        self._faehig("stimme")
        self._sendung(daten)
        self._text(daten, "titel", "einen Titel", 200)
        self._text(daten, "text", "den Text zum Vorlesen", 140000)

    def _auftrag_stimme(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        s = self._sendung(daten)
        text = self._text(daten, "text", "den Text zum Vorlesen", 140000)
        schritt("KI-Stimme spricht …")
        ton = self._arbeitsdatei(".mp3")
        try:
            self.ki.sprechen(text, ton, str(daten.get("anweisung") or "")[:1000])
        except BaseException:
            _weg(ton)
            raise
        schritt("Folge wird angelegt …")
        ki = ["stimme"] + (["text"] if daten.get("text_ki") else [])
        folge = self._neue_folge(s["id"], self._text(daten, "titel", "einen Titel", 200),
                                 str(daten.get("beschreibung") or ""), ton, ki, sprechtext=text)
        return {"folge": folge}

    # ------------------------------------------------------------------
    # 5. Aufnahme + Cover -> Video
    # ------------------------------------------------------------------
    def _pruefen_video_aufnahme(self, daten: Dict[str, Any]) -> None:
        if not media.ffmpeg_verfuegbar():
            raise KiFehler("Für Videos wird ffmpeg gebraucht", 501)
        f = self._folge(daten)
        if f["mime"].startswith("video/"):
            raise KiFehler("Das ist schon ein Video", 400)
        if not self.studio.store.sendung(f["sendung_id"])["cover"]:
            raise KiFehler("Die Sendung braucht zuerst ein Cover", 400)

    def _auftrag_video_aufnahme(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        f = self._folge(daten)
        s = self.studio.store.sendung(f["sendung_id"])
        schritt("Video wird gerendert …")
        ziel = self._arbeitsdatei(".mp4")
        try:
            with self._klartext(f["datei"]) as ton, self._klartext(s["cover"]) as bild:
                media.video_aus_bild(bild, ton, ziel)
        except BaseException:
            _weg(ziel)
            raise
        ki = sorted(set(f["ki"]) | {"video"} | ({"bild"} if s["cover_ki"] else set()))
        folge = self._neue_folge(s["id"], f"{f['titel']} (Video)", f["beschreibung"], ziel,
                                 ki, f["kapitel"], f["musik"], f["sprechtext"])
        return {"folge": folge}

    # ------------------------------------------------------------------
    # 6. Thema -> Szenen (Claude) -> Bilder + Stimme -> Video
    # ------------------------------------------------------------------
    def _pruefen_video_ki(self, daten: Dict[str, Any]) -> None:
        self._faehig("text", "video")
        self._sendung(daten)
        self._text(daten, "thema", "ein Thema", 4000)
        self._minuten(daten, 2, 10)

    def _auftrag_video_ki(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        s = self._sendung(daten)
        schritt("Claude plant die Szenen …")
        plan = self.ki.schreiben("szenen", dict(
            self._material(s), thema=self._text(daten, "thema", "ein Thema", 4000),
            stil=str(daten.get("stil") or ""), dauer_minuten=self._minuten(daten, 2, 10)),
            s["sprache"])
        szenen = [sz for sz in plan.get("szenen", []) if sz.get("sprechtext", "").strip()][:12]
        if not szenen:
            raise KiFehler("Die KI hat keine Szenen geliefert", 502)
        dateien: List[str] = []
        ziel = self._arbeitsdatei(".mp4")
        try:
            paare = []
            for i, sz in enumerate(szenen, 1):
                schritt(f"Szene {i} von {len(szenen)}: Bild …")
                bild = self._arbeitsdatei(".png")
                dateien.append(bild)
                with open(bild, "wb") as f:
                    f.write(self.ki.bild(sz["bild"] + "\nQuerformat, keine Schrift im Bild.",
                                         "1536x1024"))
                schritt(f"Szene {i} von {len(szenen)}: Stimme …")
                ton = self._arbeitsdatei(".mp3")
                dateien.append(ton)
                self.ki.sprechen(sz["sprechtext"], ton, str(daten.get("anweisung") or ""))
                paare.append((bild, ton))
            schritt("Video wird zusammengesetzt …")
            media.video_aus_szenen(paare, ziel)
        except BaseException:
            _weg(ziel)
            raise
        finally:
            for d in dateien:
                _weg(d)
        # Der gesprochene Text als Beschreibung - zugleich ein Transkript.
        text = "\n\n".join(sz["sprechtext"].strip() for sz in szenen)
        folge = self._neue_folge(s["id"], str(plan.get("titel") or daten["thema"])[:200], text,
                                 ziel, ["text", "stimme", "bild", "video"], sprechtext=text)
        return {"folge": folge}

    # ------------------------------------------------------------------
    # 7. KI-Musik -> Musikbibliothek
    # ------------------------------------------------------------------
    def _pruefen_musik_ki(self, daten: Dict[str, Any]) -> None:
        self._faehig("musik")
        self._text(daten, "beschreibung", "eine Beschreibung der Musik", 4000)
        self._sekunden(daten)

    @staticmethod
    def _sekunden(daten: Dict[str, Any]) -> float:
        try:
            sek = float(daten.get("sekunden") or 30)
        except (TypeError, ValueError):
            raise KiFehler("Die Länge bitte in Sekunden angeben", 400)
        if not 3 <= sek <= 600:
            raise KiFehler("Länge zwischen 3 Sekunden und 10 Minuten", 400)
        return sek

    def _auftrag_musik_ki(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        beschreibung = self._text(daten, "beschreibung", "eine Beschreibung der Musik", 4000)
        schritt("Musik wird komponiert …")
        ton = self.ki.musik(beschreibung, self._sekunden(daten),
                            instrumental=daten.get("instrumental", True) is not False)
        tmp = self._arbeitsdatei(".mp3")
        with open(tmp, "wb") as f:
            f.write(ton)
        info = media.aufbereiten(tmp, self.studio.cfg.medienordner, f"musik-{secrets.token_hex(10)}")
        titel = str(daten.get("titel") or "").strip() or beschreibung.split("\n")[0][:60]
        eintrag = self.studio.store.musik_anlegen(
            titel, kuenstler="KI (ElevenLabs)", lizenz="KI-generiert", datei=info["datei"],
            mime=info["mime"], dauer=info["dauer"], ki=True)
        self.studio.abgleichen()
        return {"musik": eintrag}

    # ------------------------------------------------------------------
    # 8. Musik unter eine Folge legen -> neuer Entwurf
    # ------------------------------------------------------------------
    def _pruefen_musikbett(self, daten: Dict[str, Any]) -> None:
        if not media.ffmpeg_verfuegbar():
            raise KiFehler("Zum Unterlegen von Musik wird ffmpeg gebraucht", 501)
        self._folge(daten)
        self._musik(daten)
        self._lautstaerke(daten)

    def _musik(self, daten: Dict[str, Any]) -> Dict[str, Any]:
        try:
            m = self.studio.store.musik(int(daten.get("musik_id")))
        except (TypeError, ValueError):
            m = None
        if m is None or not m["datei"]:
            raise KiFehler("Musikstück nicht gefunden", 404)
        return m

    @staticmethod
    def _lautstaerke(daten: Dict[str, Any]) -> float:
        try:
            l = float(daten.get("lautstaerke", 0.3))
        except (TypeError, ValueError):
            raise KiFehler("Lautstärke bitte als Zahl zwischen 0,05 und 1", 400)
        if not 0.05 <= l <= 1:
            raise KiFehler("Lautstärke bitte zwischen 0,05 und 1", 400)
        return l

    def _auftrag_musikbett(self, daten: Dict[str, Any], schritt: Any) -> Dict[str, Any]:
        f = self._folge(daten)
        m = self._musik(daten)
        schritt("Musik wird unterlegt …")
        endung = ".mp4" if f["mime"].startswith("video/") else ".mp3"
        ziel = self._arbeitsdatei(endung)
        try:
            with self._klartext(f["datei"]) as sprache, self._klartext(m["datei"]) as musik:
                media.musik_unterlegen(sprache, musik, ziel, lautstaerke=self._lautstaerke(daten),
                                       ducking=daten.get("ducking", True) is not False)
        except BaseException:
            _weg(ziel)
            raise
        angabe = {"titel": m["titel"], "kuenstler": m["kuenstler"], "lizenz": m["lizenz"],
                  "quelle": m["quelle"]}
        musik = f["musik"] + ([angabe] if angabe not in f["musik"] else [])
        ki = sorted(set(f["ki"]) | ({"musik"} if m["ki"] else set()))
        folge = self._neue_folge(f["sendung_id"], f"{f['titel']} (mit Musik)", f["beschreibung"],
                                 ziel, ki, f["kapitel"], musik, f["sprechtext"])
        return {"folge": folge}


def _weg(pfad: str) -> None:
    try:
        os.remove(pfad)
    except OSError:
        pass
