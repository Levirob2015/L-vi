"""Lernende Dateierkennung: Schaedlinge finden, die noch niemand kennt.

Die bisherigen Wege haben beide dieselbe Grenze. Eine **Signatur** erkennt
nur, was schon jemand gemeldet hat. Ein **Muster** erkennt nur, was jemand
vorher beschrieben hat. Der Schaedling, den es gestern noch nicht gab,
kommt an beidem vorbei.

Dieses Modul geht anders vor. Es sieht sich an, wie die Dateien auf
*diesem* Rechner normalerweise aussehen - und meldet, was aus der Reihe
faellt. Nicht "ich kenne dich", sondern "du bist hier fremd".

Woran man eine getarnte Datei erkennt, ohne sie zu kennen
---------------------------------------------------------
Schadcode muss sich verstecken, und genau das hinterlaesst Spuren, die
sich messen lassen:

* **Entropie.** Ein Mass fuer Unordnung, von 0 bis 8. Gewoehnlicher
  Quelltext liegt bei 4 bis 5,5 - er besteht aus wiederkehrenden Woertern.
  Verschluesselter oder gepackter Inhalt liegt bei 7,5 bis 8: dort ist
  jedes Byte gleich wahrscheinlich. Eine ``.php``-Datei mit Entropie 7,8
  enthaelt keinen PHP-Quelltext mehr, sondern eine versteckte Nutzlast.
* **Zeilenlaenge.** Verschleierter Code steht oft in *einer* Zeile mit
  40.000 Zeichen. In gewachsenem Quelltext kommt das nicht vor.
* **Druckbarer Anteil.** Eine Textdatei, die zu einem Drittel aus
  Steuerzeichen besteht, ist keine Textdatei.
* **Zusammenhaengende Bloecke** aus base64- oder Hex-Zeichen.

Was es **nicht** ist
--------------------
Kein neuronales Netz und kein Sprachmodell - dieselbe Entscheidung wie in
:mod:`loginshield.anomaly` und aus denselben Gruenden: Verzoegerung bei
jeder Pruefung, schwere Abhaengigkeiten, keine Trainingsdaten, und vor
allem Urteile, die niemand erklaeren kann. Wer wissen will, warum seine
Datei beiseitegelegt wurde, bekommt hier eine Antwort in Zahlen.

Gelernt wird unbeaufsichtigt aus dem, was ohnehin da ist: robuste
Statistik (Median und mittlere absolute Abweichung, MAD), getrennt nach
Dateiart. Robust heisst, dass einzelne Ausreisser die Grundlinie nicht
verziehen - waere schon eine Webshell im gelernten Bestand, wuerde ein
Mittelwert sie stillschweigend zur Normalitaet erklaeren, ein Median
nicht.

Drei Grundsaetze, dieselben wie bei der Anomalie-Erkennung
-----------------------------------------------------------
1. **Ohne genug Daten wird nicht geurteilt.** Solange die Grundlinie zu
   duenn ist, sagt das Modul das offen, statt zu raten.
2. **Statistik allein legt nichts beiseite.** Die Punktzahl ist nach oben
   gedeckelt und bleibt unter der Schwelle, ab der eine Datei in
   Quarantaene wandert. Eine Abweichung ist ein Verdacht, kein Beweis.
   Erst zusammen mit einem echten Merkmal wird ein Urteil daraus.
3. **Jedes Urteil ist begruendet.** Zu jedem Punkt gehoert ein Signal mit
   Beobachtung und Erwartung.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("loginshield.classifier")

#: Schluessel, unter dem die Grundlinie neben den anderen gelernten Daten
#: liegt (dieselbe Ablage wie bei der Anomalie-Erkennung).
GRUNDLINIE_KEY = "classifier_baseline"

#: So viel einer Datei wird angesehen.
#:
#: Die Zahl ist gemessen, nicht geraten. Bei 256 KB brauchte eine Datei
#: 20 ms - bei 20.000 Dateien waeren das allein hier vier Minuten, und der
#: Rechner soll ja nichts merken. Mit 32 KB sind es rund 1,5 ms.
#:
#: Fuer eine Verteilung reicht der Anfang: Entropie und Zeichenanteile
#: stehen nach wenigen Kilobyte fest, und eine verschleierte Nutzlast
#: steht am Anfang der Datei, nicht hinter 200 KB Fuellmaterial. Was
#: weiter hinten steckt, faellt trotzdem auf - der Fingerabdruck geht
#: ueber die ganze Datei, die Musterpruefung ueber das erste Megabyte.
MAX_PROBE = 32_768

#: Ab dieser Entropie ist der Inhalt praktisch Zufall: verschluesselt,
#: gepackt oder verschleiert. Fuer Programmtext ist das ein Widerspruch
#: in sich, deshalb gilt es dort auch ohne jede Grundlinie.
ENTROPIE_GEPACKT = 7.2

#: Formate, die von Natur aus wie Zufall aussehen, weil sie komprimiert
#: sind. Bei ihnen sagt hohe Entropie nichts aus.
GEPACKTE_ENDUNGEN = {
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".apk", ".war",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".avi",
    ".mkv", ".ogg", ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".epub",
    ".woff", ".woff2", ".ttf", ".so", ".dll", ".pyc", ".whl", ".dmg",
}

#: Obergrenze fuer die Punktzahl aus reiner Statistik. Die Schwelle, ab
#: der eine Datei als schadhaft gilt, liegt bei 8 (``malware.block_score``)
#: - dieser Deckel liegt bewusst darunter. Eine Abweichung allein soll
#: nichts beiseitelegen; sie soll den Ausschlag geben, wenn ausserdem ein
#: echtes Merkmal gefunden wurde.
MAX_PUNKTE = 7

#: Ab diesem Betrag gilt eine Abweichung als deutlich. 3,5 ist der
#: uebliche Grenzwert fuer den robusten z-Wert.
Z_AUFFAELLIG = 3.5
Z_STARK = 7.0

#: So viele Dateien braucht eine Klasse, bevor ueber sie geurteilt wird.
MIN_DATEIEN = 20

#: So lange gilt eine einmal geladene Grundlinie, bevor in der Ablage
#: nachgesehen wird, ob inzwischen etwas Neues gelernt wurde.
NACHLADEN_NACH = 60.0

#: Nur base64, nicht zusaetzlich Hex: Der Hex-Ausdruck kostete allein
#: 9 der 20 ms je Datei und fand nichts, was nicht ohnehin auffiel - die
#: Musterpruefung hat fuer lange ``\xNN``-Folgen eine eigene Regel.
_BASE64_LAUF = re.compile(rb"[A-Za-z0-9+/=]{16,}")

#: Die Merkmale und die Richtung, in der eine Abweichung verdaechtig ist.
#: Nur eine Richtung zaehlt: Eine Datei mit *weniger* Unordnung als ueblich
#: ist kein Schaedling, sondern meistens eine Textdatei.
MERKMALE: Tuple[Tuple[str, str, str], ...] = (
    ("entropie", "hoch", "Unordnung im Inhalt (0-8)"),
    ("zeile_max", "hoch", "laengste Zeile in Zeichen"),
    ("block_max", "hoch", "laengster base64- oder Hex-Block"),
    ("druckbar", "niedrig", "Anteil lesbarer Zeichen"),
)

#: Der kleinste Spielraum, der einem Merkmal zugestanden wird - als
#: absoluter Wert und als Anteil des Medians; es gilt der groessere.
#:
#: Das ist die Lehre aus dem ersten Versuch. Gelernt wurde an diesem
#: Projekt, dessen Quelltext sehr einheitlich formatiert ist: Die laengste
#: Zeile lag fast ueberall bei 87 Zeichen, die gemessene Streuung bei 3,5.
#: Rechnerisch war damit jede Datei mit 118 Zeichen "zehnfach abweichend" -
#: und die README, die Konfigurationsdatei und das Dashboard wurden als
#: verdaechtig gemeldet. Elf Fehlalarme bei 59 eigenen Dateien.
#:
#: Der Fehler steckt nicht in der Rechnung, sondern in der Annahme: Ein
#: Bestand, in dem ein Merkmal kaum streut, sagt nichts darueber aus, wie
#: viel Streuung *normal* ist - er taeuscht Genauigkeit vor. Deshalb wird
#: jedem Merkmal ein Mindestspielraum zugestanden, unter den die gemessene
#: Streuung nicht fallen darf.
MINDEST_STREUUNG: Dict[str, Tuple[float, float]] = {
    # Merkmal:      (absolut, Anteil des Medians)
    "entropie":     (0.5,   0.0),
    "druckbar":     (0.05,  0.0),
    # 600 statt 200: Fliesstext ohne harte Umbrueche - eine Markdown-Datei,
    # ein Absatz in einer HTML-Seite - kommt leicht auf ueber 1000 Zeichen
    # in einer Zeile. Das ist voellig gewoehnlich. Aussagekraeftig wird das
    # Merkmal erst bei einigen tausend, und dort schlaegt es weiter an.
    "zeile_max":    (600.0, 1.0),
    "block_max":    (120.0, 2.0),
}

#: Endungen, deren Inhalt lesbarer Text sein sollte. Ist er es nicht,
#: sondern reiner Zufall, stimmt etwas nicht - und zwar unabhaengig davon,
#: was sonst auf diesem Rechner liegt.
LESBARE_ENDUNGEN = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".js", ".mjs", ".py",
    ".sh", ".bash", ".pl", ".cgi", ".rb", ".lua", ".asp", ".aspx", ".jsp",
    ".html", ".htm", ".css", ".txt", ".md", ".json", ".xml", ".yaml",
    ".yml", ".ini", ".conf", ".cfg", ".csv", ".sql", ".htaccess",
}


# ----------------------------------------------------------------------
# Messen
# ----------------------------------------------------------------------
def merkmale(data: bytes) -> Dict[str, float]:
    """Misst eine Datei. Immer dieselben Zahlen, immer in derselben Ordnung."""
    probe = data[:MAX_PROBE]
    laenge = len(probe)
    if laenge == 0:
        return {name: 0.0 for name, _, _ in MERKMALE}

    haeufigkeit = Counter(probe)
    entropie = 0.0
    for anzahl in haeufigkeit.values():
        anteil = anzahl / laenge
        entropie -= anteil * math.log2(anteil)

    druckbar = sum(
        anzahl for byte, anzahl in haeufigkeit.items()
        if 32 <= byte < 127 or byte in (9, 10, 13)
    ) / laenge

    zeilen = probe.split(b"\n")
    zeile_max = float(max(len(zeile) for zeile in zeilen))

    block_max = 0
    for treffer in _BASE64_LAUF.finditer(probe):
        # Ein eingebettetes Bild (``data:image/png;base64,...``) ist ein
        # langer base64-Block mit einem voellig harmlosen Grund. Dieselbe
        # Ausnahme kennt auch die Musterpruefung; ohne sie meldet jede
        # Webseite mit eingebettetem Symbol.
        vorher = probe[max(0, treffer.start() - 24):treffer.start()]
        if b"base64," in vorher:
            continue
        block_max = max(block_max, treffer.end() - treffer.start())

    return {
        "entropie": round(entropie, 4),
        "druckbar": round(druckbar, 4),
        "zeile_max": zeile_max,
        "block_max": float(block_max),
    }


def _spielraum(name: str, median: float, mad: float) -> float:
    """Der Spielraum, mit dem gerechnet wird - nie enger als erlaubt."""
    absolut, anteil = MINDEST_STREUUNG.get(name, (0.0, 0.0))
    return max(mad, absolut, median * anteil)


def dateiklasse(filename: str, data: bytes) -> str:
    """Womit wird diese Datei verglichen?

    Ein Bild mit einer Entropie von 7,9 ist voellig normal, eine
    ``.php``-Datei mit 7,9 ist es nicht. Beide in einen Topf zu werfen,
    hiesse entweder das Bild staendig zu melden oder die Webshell nie.
    """
    endung = os.path.splitext(os.path.basename(filename).lower())[1]
    if endung in GEPACKTE_ENDUNGEN:
        return "gepackt"
    kopf = data[:512]
    if kopf.startswith(b"\x7fELF") or kopf.startswith(b"MZ"):
        return "programm"
    # Ueberwiegend lesbar? Dann Text - unabhaengig davon, wie die Datei
    # heisst. Die Endung ist das Erste, was ein Angreifer aendert.
    if kopf:
        lesbar = sum(1 for byte in kopf
                     if 32 <= byte < 127 or byte in (9, 10, 13)) / len(kopf)
        if lesbar >= 0.85:
            return "text"
    return "binaer"


# ----------------------------------------------------------------------
# Grundlinie
# ----------------------------------------------------------------------
def _median(werte: Sequence[float]) -> float:
    if not werte:
        return 0.0
    sortiert = sorted(werte)
    mitte = len(sortiert) // 2
    if len(sortiert) % 2:
        return float(sortiert[mitte])
    return (sortiert[mitte - 1] + sortiert[mitte]) / 2.0


def _mad(werte: Sequence[float], median: float) -> float:
    """Mittlere absolute Abweichung vom Median.

    Robust: Ein einzelner Ausreisser - etwa eine schon vorhandene Webshell
    im gelernten Bestand - verschiebt sie kaum. Bei der
    Standardabweichung wuerde er die Erwartung so weit aufblaehen, dass
    hinterher gar nichts mehr auffaellt.
    """
    if not werte:
        return 0.0
    return _median([abs(wert - median) for wert in werte])


@dataclass
class Klassenwerte:
    """Was auf diesem Rechner fuer eine Dateiart normal ist."""

    dateien: int = 0
    werte: Dict[str, Dict[str, float]] = field(default_factory=dict)

    @property
    def belastbar(self) -> bool:
        return self.dateien >= MIN_DATEIEN

    def as_dict(self) -> dict:
        return {"dateien": self.dateien, "werte": self.werte}

    @classmethod
    def from_dict(cls, daten: dict) -> "Klassenwerte":
        return cls(dateien=int(daten.get("dateien", 0)),
                   werte=dict(daten.get("werte") or {}))


@dataclass
class Grundlinie:
    """Der gelernte Normalzustand, nach Dateiart getrennt."""

    created_ts: float = 0.0
    dateien: int = 0
    klassen: Dict[str, Klassenwerte] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "version": 1,
            "created_ts": self.created_ts,
            "dateien": self.dateien,
            "klassen": {name: k.as_dict() for name, k in self.klassen.items()},
        }

    @classmethod
    def from_dict(cls, daten: dict) -> "Grundlinie":
        return cls(
            created_ts=float(daten.get("created_ts", 0.0)),
            dateien=int(daten.get("dateien", 0)),
            klassen={
                name: Klassenwerte.from_dict(werte)
                for name, werte in (daten.get("klassen") or {}).items()
            },
        )


@dataclass
class Signal:
    """Ein einzelnes Merkmal, das aus der Reihe faellt."""

    name: str
    beobachtet: float
    erwartet: float
    z: float
    beschreibung: str

    def as_dict(self) -> dict:
        return {"name": self.name, "beobachtet": self.beobachtet,
                "erwartet": self.erwartet, "z": round(self.z, 2),
                "beschreibung": self.beschreibung}


@dataclass
class Befund:
    """Das Urteil - immer mit den Signalen, aus denen es entstand."""

    punkte: int = 0
    klasse: str = ""
    signale: List[Signal] = field(default_factory=list)
    grund: str = ""

    @property
    def auffaellig(self) -> bool:
        return self.punkte > 0

    @property
    def zusammenfassung(self) -> str:
        if not self.signale:
            return self.grund or "unauffaellig"
        return "; ".join(signal.beschreibung for signal in self.signale[:3])

    def as_dict(self) -> dict:
        return {"punkte": self.punkte, "klasse": self.klasse,
                "grund": self.grund,
                "signale": [signal.as_dict() for signal in self.signale]}


class Klassifikator:
    """Lernt, wie die Dateien hier aussehen - und meldet, was fremd ist."""

    def __init__(self, guard=None, store=None,
                 grundlinie: Optional[Grundlinie] = None,
                 max_punkte: Optional[int] = None) -> None:
        self.guard = guard
        self._store = store
        self._grundlinie = grundlinie
        #: Fest vorgegeben heisst: nicht aus der Ablage nachladen.
        self._fest = grundlinie is not None
        self._geladen_ts = 0.0
        self.max_punkte = MAX_PUNKTE if max_punkte is None else max(1, max_punkte)

    @property
    def store(self):
        return self._store or (self.guard.store if self.guard else None)

    # ------------------------------------------------------------------
    def grundlinie(self, jetzt: Optional[float] = None) -> Optional[Grundlinie]:
        """Die gelernte Grundlinie - gemerkt, aber nicht fuer immer.

        Nachgeladen wird hoechstens alle :data:`NACHLADEN_NACH` Sekunden.
        Beides waere falsch: Bei jedem Aufruf nachzusehen hiesse eine
        Datenbankabfrage je gepruefter Datei. Nie nachzusehen hiesse, dass
        ein laufender Waechter nichts davon mitbekommt, wenn nebenan
        ``erkennung --learn`` gerade etwas gelernt hat - er wuerde bis zum
        Neustart weiter ohne Grundlinie arbeiten.
        """
        if self._fest:
            return self._grundlinie
        jetzt = time.time() if jetzt is None else jetzt
        if self._geladen_ts and jetzt - self._geladen_ts < NACHLADEN_NACH:
            return self._grundlinie
        self._geladen_ts = jetzt
        store = self.store
        if store is None:
            return None
        roh = store.get_meta(GRUNDLINIE_KEY)
        if not roh:
            return None
        try:
            self._grundlinie = Grundlinie.from_dict(json.loads(roh))
        except (ValueError, TypeError) as exc:
            log.warning("Gelernte Grundlinie unlesbar, wird uebergangen: %s", exc)
            self._grundlinie = None
        return self._grundlinie

    @property
    def bereit(self) -> bool:
        grundlinie = self.grundlinie()
        return grundlinie is not None and any(
            klasse.belastbar for klasse in grundlinie.klassen.values()
        )

    # ------------------------------------------------------------------
    def lernen(self, pfade: Sequence[str], *, max_dateien: int = 20_000,
               skip_dirs: Sequence[str] = (), now: Optional[float] = None,
               speichern: bool = True) -> Grundlinie:
        """Sieht sich an, was hier liegt, und haelt das Uebliche fest.

        Wie bei der Integritaetspruefung gilt: **nur auf einem System
        lernen, das sauber ist.** Wird nach einem Einbruch gelernt, gilt
        die Webshell anschliessend als das Uebliche.
        """
        gesammelt: Dict[str, Dict[str, List[float]]] = {}
        anzahl = 0
        uebersprungen = set(skip_dirs)

        for pfad in _dateien(pfade, uebersprungen, max_dateien):
            try:
                with open(pfad, "rb") as handle:
                    daten = handle.read(MAX_PROBE)
            except OSError:
                continue
            if not daten:
                continue
            klasse = dateiklasse(pfad, daten)
            gemessen = merkmale(daten)
            eimer = gesammelt.setdefault(klasse, {})
            for name, wert in gemessen.items():
                eimer.setdefault(name, []).append(wert)
            anzahl += 1

        grundlinie = Grundlinie(
            created_ts=time.time() if now is None else now, dateien=anzahl,
        )
        for klasse, merkmalswerte in gesammelt.items():
            werte: Dict[str, Dict[str, float]] = {}
            for name, liste in merkmalswerte.items():
                median = _median(liste)
                werte[name] = {"median": round(median, 4),
                               "mad": round(_mad(liste, median), 4)}
            grundlinie.klassen[klasse] = Klassenwerte(
                dateien=len(next(iter(merkmalswerte.values()), [])), werte=werte,
            )

        self._grundlinie = grundlinie
        self._geladen_ts = time.time() if now is None else now
        if speichern:
            store = self.store
            if store is not None:
                store.set_meta(GRUNDLINIE_KEY,
                               json.dumps(grundlinie.as_dict()))
            else:
                log.warning("Gelernt, aber keine Ablage vorhanden - die "
                            "Grundlinie gilt nur fuer diesen Lauf")
        log.info("Dateierkennung gelernt: %s Dateien, %s Klassen",
                 anzahl, len(grundlinie.klassen))
        return grundlinie

    # ------------------------------------------------------------------
    def bewerten(self, daten: bytes, filename: str = "") -> Befund:
        """Faellt diese Datei aus der Reihe?"""
        if not daten:
            return Befund(grund="leere Datei")

        klasse = dateiklasse(filename, daten)
        gemessen = merkmale(daten)
        befund = Befund(klasse=klasse)

        # 1. Was ohne jede Grundlinie gilt: Was lesbarer Text sein
        #    sollte, aber wie Zufall aussieht, ist kein Text mehr.
        #    Gemeint sind zwei Faelle - eine Textdatei, deren Inhalt
        #    verschleiert wurde, und eine ``update.php``, in der in
        #    Wahrheit eine gepackte Nutzlast steckt.
        endung = os.path.splitext(os.path.basename(filename).lower())[1]
        sollte_lesbar = klasse == "text" or endung in LESBARE_ENDUNGEN
        if (sollte_lesbar and endung not in GEPACKTE_ENDUNGEN
                and gemessen["entropie"] >= ENTROPIE_GEPACKT):
            befund.signale.append(Signal(
                "entropie_gepackt", gemessen["entropie"], ENTROPIE_GEPACKT, 0.0,
                f"sollte lesbarer Text sein, hat aber Entropie "
                f"{gemessen['entropie']:.1f} - der Inhalt ist verschluesselt, "
                f"gepackt oder verschleiert",
            ))
            befund.punkte += 5

        # 2. Was nur mit Grundlinie geht: der Vergleich mit dem Ueblichen.
        grundlinie = self.grundlinie()
        if grundlinie is None:
            befund.grund = "noch nichts gelernt"
            return _deckeln(befund, self.max_punkte)

        werte = grundlinie.klassen.get(klasse)
        if werte is None or not werte.belastbar:
            befund.grund = (
                f"zu wenig gelernt fuer die Art '{klasse}' "
                f"({werte.dateien if werte else 0} von {MIN_DATEIEN} Dateien)"
            )
            return _deckeln(befund, self.max_punkte)

        for name, richtung, beschreibung in MERKMALE:
            grenzen = werte.werte.get(name)
            if not grenzen:
                continue
            median = float(grenzen.get("median", 0.0))
            # Der zugestandene Mindestspielraum wird erst hier angewandt,
            # nicht schon beim Lernen: In der Grundlinie steht die wirklich
            # gemessene Streuung, damit sie sich nachtraeglich anders
            # gewichten laesst, ohne alles neu zu lernen.
            spielraum = _spielraum(name, median,
                                   float(grenzen.get("mad", 0.0)))
            if spielraum <= 0:
                # Kein Spielraum - dann laesst sich auch keine Abweichung
                # messen. Lieber nichts sagen als raten.
                continue
            beobachtet = gemessen.get(name, 0.0)
            # Robuster z-Wert. 0,6745 rechnet die MAD auf das Mass um, das
            # eine Standardabweichung haette - damit bedeutet 3,5 hier
            # dasselbe wie sonst auch.
            z = 0.6745 * (beobachtet - median) / spielraum
            if richtung == "niedrig":
                z = -z
            if z < Z_AUFFAELLIG:
                continue
            befund.signale.append(Signal(
                name, beobachtet, median, z,
                f"{beschreibung}: {beobachtet:.2f} statt sonst "
                f"{median:.2f} bei Dateien dieser Art",
            ))
            befund.punkte += 3 if z < Z_STARK else 5

        if befund.signale and not befund.grund:
            befund.grund = (
                f"weicht von {werte.dateien} gelernten Dateien der Art "
                f"'{klasse}' ab"
            )
        return _deckeln(befund, self.max_punkte)

    # ------------------------------------------------------------------
    def status(self) -> dict:
        grundlinie = self.grundlinie()
        if grundlinie is None:
            return {"bereit": False, "grund": "Es wurde noch nichts gelernt.",
                    "dateien": 0, "klassen": {}}
        klassen = {
            name: {"dateien": klasse.dateien, "belastbar": klasse.belastbar}
            for name, klasse in grundlinie.klassen.items()
        }
        return {
            "bereit": self.bereit,
            "grund": "" if self.bereit else
                     f"Zu wenig gelernt - je Dateiart braucht es "
                     f"{MIN_DATEIEN} Dateien.",
            "dateien": grundlinie.dateien,
            "created_ts": grundlinie.created_ts,
            "klassen": klassen,
        }


def _deckeln(befund: Befund, grenze: int = MAX_PUNKTE) -> Befund:
    """Haelt die Punktzahl unter der Schwelle zum Beiseitelegen.

    Der wichtigste Satz dieses Moduls steht in dieser Funktion: Eine
    statistische Abweichung allein reicht nie, um eine Datei anzufassen.

    Die Grenze stand hier einmal fest auf 7 - passend zur Voreinstellung
    ``block_score: 8``. Wer die Schwelle in der Konfiguration niedriger
    setzt, haette den Grundsatz damit still ausgehebelt. Deshalb richtet
    sie sich jetzt nach der tatsaechlich eingestellten Schwelle.
    """
    if befund.punkte > grenze:
        befund.punkte = grenze
    return befund


def _dateien(pfade: Sequence[str], skip_dirs, grenze: int):
    """Laeuft ueber die angegebenen Pfade - mit Obergrenze."""
    anzahl = 0
    for wurzel in pfade:
        if os.path.isfile(wurzel):
            yield wurzel
            anzahl += 1
            continue
        for ordner, unterordner, dateien in os.walk(wurzel):
            unterordner[:] = [
                d for d in unterordner
                if d not in skip_dirs and not d.startswith(".")
            ]
            for name in dateien:
                if anzahl >= grenze:
                    log.warning("Lernen nach %s Dateien abgebrochen", grenze)
                    return
                anzahl += 1
                yield os.path.join(ordner, name)
