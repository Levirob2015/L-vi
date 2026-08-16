"""Anomalie-Erkennung: lernt den Normalzustand und meldet Abweichungen.

Feste Regeln erkennen, was jemand vorher als Angriff beschrieben hat. Sie
sehen nicht, wenn etwas einfach **unueblich** ist: eine Adresse, die 200
verschiedene Pfade abklappert, obwohl Besucher sonst drei aufrufen. Ein
Ansturm um vier Uhr morgens auf einem Server, der nachts still ist. Ein
Programm, das sich als Browser ausgibt, aber schneller klickt als ein Mensch.

Dieses Modul lernt aus den eigenen Aufzeichnungen des Servers, wie normaler
Verkehr dort aussieht, und bewertet Abweichungen davon.

Was es **nicht** ist
--------------------
Kein neuronales Netz und kein Sprachmodell. Beides waere hier die falsche
Wahl: Verzoegerung bei jeder Anfrage, keine Trainingsdaten, schwere
Abhaengigkeiten - und vor allem Sperren, die niemand erklaeren kann.

Stattdessen lernt es unbeaufsichtigt aus den vorhandenen Daten (robuste
Statistik: Median und mittlere absolute Abweichung, dazu Entropie und
Neuheitsmasse). Jede Bewertung zerfaellt in **benannte Einzelsignale** mit
Beobachtung und Erwartung - man kann also immer nachlesen, warum eine
Adresse auffaellt.

Drei Grundsaetze
----------------
1. **Ohne genug Daten wird nicht geurteilt.** Solange die Grundlinie zu duenn
   ist, meldet das Modul das offen, statt zu raten.
2. **Standardmaessig wird nur gemeldet, nicht gesperrt.** Eine statistische
   Abweichung ist ein Verdacht, kein Beweis - ein Werbeschub sieht einem
   Angriff zunaechst aehnlich.
3. **Jedes Urteil ist begruendet.** Kein Punktwert ohne die Signale, aus
   denen er entstand.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence

from .config import AnomalyConfig
from .models import Event, Reason

log = logging.getLogger("loginshield.anomaly")

BASELINE_KEY = "anomaly_baseline"
LAST_LEARN_KEY = "anomaly_last_learn"


# ----------------------------------------------------------------------
# Robuste Statistik
# ----------------------------------------------------------------------
def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mitte = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mitte])
    return (ordered[mitte - 1] + ordered[mitte]) / 2.0


def mad(values: Sequence[float], center: Optional[float] = None) -> float:
    """Mittlere absolute Abweichung vom Median.

    Robuster als die Standardabweichung: einzelne Ausreisser - also genau
    die Angriffe, die man sucht - verzerren die Grundlinie nicht.
    """
    if not values:
        return 0.0
    mitte = median(values) if center is None else center
    return median([abs(value - mitte) for value in values])


def robust_z(value: float, center: float, streuung: float) -> float:
    """Wie viele typische Abweichungen liegt der Wert vom Normalen entfernt?"""
    if streuung <= 0:
        # Ohne Streuung ist jede Abweichung nach oben bemerkenswert, aber
        # nicht unendlich - sonst kippt ein einziger Wert die Bewertung.
        if center <= 0:
            # Wo vorher nichts war, ist jede Aktivitaet bemerkenswert. Der
            # feste Wert liegt genau auf der ueblichen Schwelle - Aufrufer
            # muessen ihn deshalb mit >= pruefen, nicht mit >.
            return 3.0 if value > 0 else 0.0
        return min(10.0, max(0.0, (value - center) / max(center, 1.0)) * 3.0)
    return 0.6745 * (value - center) / streuung


def regelmaessigkeit(zeitstempel: Sequence[float]) -> Optional[float]:
    """Wie gleichmaessig ist der Rhythmus? 0 = maschinell exakt, 1 = wie ein Mensch.

    Gemessen als Variationskoeffizient der Abstaende. Das ist deutlich
    schaerfer als die Durchschnittsgeschwindigkeit: Ein Programm, das alle
    30 Sekunden anfragt, ist langsam - aber unmenschlich regelmaessig. Ein
    Mensch macht Pausen, liest, klickt schnell hintereinander.
    """
    if len(zeitstempel) < 6:
        return None
    geordnet = sorted(zeitstempel)
    abstaende = [b - a for a, b in zip(geordnet, geordnet[1:]) if b > a]
    if len(abstaende) < 5:
        return None
    mittel = sum(abstaende) / len(abstaende)
    if mittel <= 0:
        return 0.0
    varianz = sum((wert - mittel) ** 2 for wert in abstaende) / len(abstaende)
    return math.sqrt(varianz) / mittel


def entropy(counts: Sequence[float]) -> float:
    """Shannon-Entropie - wie breit streut das Verhalten?"""
    gesamt = float(sum(counts))
    if gesamt <= 0:
        return 0.0
    wert = 0.0
    for count in counts:
        if count > 0:
            anteil = count / gesamt
            wert -= anteil * math.log2(anteil)
    return wert


# ----------------------------------------------------------------------
# Grundlinie
# ----------------------------------------------------------------------
@dataclass
class Baseline:
    """Der gelernte Normalzustand dieses Servers."""

    created_ts: float = 0.0
    von_ts: float = 0.0
    bis_ts: float = 0.0
    ereignisse: int = 0
    adressen: int = 0

    ereignisse_je_ip_median: float = 0.0
    ereignisse_je_ip_streuung: float = 0.0
    pfade_je_ip_median: float = 0.0
    pfade_je_ip_streuung: float = 0.0
    konten_je_ip_median: float = 0.0
    konten_je_ip_streuung: float = 0.0

    fehlerquote: float = 0.0
    fehler_je_stunde_median: float = 0.0
    fehler_je_stunde_streuung: float = 0.0
    #: Wie breit streuen normale Besucher ihre Zugriffe ueber die Seiten?
    pfad_entropie_median: float = 0.0
    pfad_entropie_streuung: float = 0.0
    #: Wie regelmaessig sind normale Besucher (Variationskoeffizient)?
    regelmaessigkeit_median: float = 0.0
    #: Wie viele Adressen waren im Lernzeitraum wegen eines Angriffs
    #: ausgeschlossen? Nur zur Nachvollziehbarkeit.
    ausgeschlossen: int = 0

    #: Pfade und Programmkennungen, die im Lernzeitraum vorkamen.
    bekannte_pfade: Dict[str, int] = field(default_factory=dict)
    bekannte_kennungen: Dict[str, int] = field(default_factory=dict)
    #: Stunden (UTC), in denen nennenswert Verkehr herrscht.
    aktive_stunden: List[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        bekannt = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (data or {}).items() if k in bekannt})

    def usable(self, min_events: int, min_ips: int) -> bool:
        return self.ereignisse >= min_events and self.adressen >= min_ips

    @property
    def alter_stunden(self) -> float:
        return max(0.0, (time.time() - self.created_ts) / 3600.0)


def learn(store, *, days: float = 7.0, now: Optional[float] = None) -> Baseline:
    """Lernt den Normalzustand aus den vorhandenen Aufzeichnungen.

    Bewusst aus den eigenen Daten des Servers: was auf einem Firmenportal
    normal ist, waere auf einem Blog voellig unueblich.

    Adressen, die im Lernzeitraum gesperrt wurden, bleiben aussen vor.
    Sonst lernt die Grundlinie den Angriff als normal - und erkennt ihn
    beim naechsten Mal nicht mehr.
    """
    now = time.time() if now is None else now
    since = now - days * 86400.0

    gesperrt = set(store.blocked_ips_since(since, include_networks=False))
    profile = store.profile_by_ip(since, exclude=gesperrt)
    ereignisse_je_ip = [entry["events"] for entry in profile.values()]
    pfade_je_ip = [len(entry["routes"]) for entry in profile.values()]
    konten_je_ip = [len(entry["identities"]) for entry in profile.values()]

    gesamt = sum(ereignisse_je_ip)
    fehler = sum(entry["failures"] for entry in profile.values())

    # Nur Stunden mit Betrieb zaehlen. Sonst zieht jede stille Nacht den
    # Median auf 0 - und gegen 0 ist jeder Vergleich wertlos.
    alle_stunden = store.hourly_counts(since, now=now)
    fehler_stunden = store.hourly_counts(since, Event.LOGIN_FAILURE, now=now)
    stundenwerte = [
        wert for wert, gesamt_stunde in zip(fehler_stunden, alle_stunden)
        if gesamt_stunde > 0
    ] or fehler_stunden

    stunden_last: Dict[int, int] = {}
    for entry in profile.values():
        for stunde in entry["hours"]:
            stunden_last[stunde] = stunden_last.get(stunde, 0) + entry["events"]
    schwelle = (max(stunden_last.values()) * 0.1) if stunden_last else 0
    aktive = sorted(s for s, last in stunden_last.items() if last >= schwelle)

    entropien = [
        entropy(list(entry["route_counts"].values()))
        for entry in profile.values() if entry["route_counts"]
    ]
    takte = [
        wert for wert in (
            regelmaessigkeit(entry["timestamps"]) for entry in profile.values()
        ) if wert is not None
    ]

    baseline = Baseline(
        created_ts=now,
        ausgeschlossen=len(gesperrt),
        pfad_entropie_median=median(entropien),
        pfad_entropie_streuung=mad(entropien),
        regelmaessigkeit_median=median(takte),
        von_ts=since,
        bis_ts=now,
        ereignisse=gesamt,
        adressen=len(profile),
        ereignisse_je_ip_median=median(ereignisse_je_ip),
        ereignisse_je_ip_streuung=mad(ereignisse_je_ip),
        pfade_je_ip_median=median(pfade_je_ip),
        pfade_je_ip_streuung=mad(pfade_je_ip),
        konten_je_ip_median=median(konten_je_ip),
        konten_je_ip_streuung=mad(konten_je_ip),
        fehlerquote=(fehler / gesamt) if gesamt else 0.0,
        fehler_je_stunde_median=median(stundenwerte),
        fehler_je_stunde_streuung=mad(stundenwerte),
        bekannte_pfade=store.route_counts(since),
        bekannte_kennungen=store.agent_counts(since),
        aktive_stunden=aktive,
    )
    log.info(
        "Grundlinie gelernt: %s Ereignisse von %s Adressen ueber %.1f Tage "
        "(%s gesperrte Adressen ausgeschlossen)",
        baseline.ereignisse, baseline.adressen, days, len(gesperrt),
    )
    return baseline


# ----------------------------------------------------------------------
# Bewertung
# ----------------------------------------------------------------------
@dataclass
class Signal:
    """Ein einzelner Hinweis mit Beobachtung und Erwartung."""

    name: str
    beobachtet: float
    erwartet: float
    punkte: float
    erklaerung: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnomalyReport:
    ip: str
    score: float = 0.0
    signals: List[Signal] = field(default_factory=list)
    #: Wie viele Ereignisse liegen dem Urteil zugrunde ...
    evidence: int = 0
    #: ... und wie stark wurde der Rohwert deshalb gedaempft (0..1).
    confidence: float = 1.0

    @property
    def verdict(self) -> str:
        if self.score >= 70:
            return "kritisch"
        if self.score >= 40:
            return "auffaellig"
        return "normal"

    @property
    def summary(self) -> str:
        return "; ".join(signal.erklaerung for signal in self.signals[:3]) or "unauffaellig"

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "score": round(self.score, 1),
            "verdict": self.verdict,
            "summary": self.summary,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "signals": [signal.as_dict() for signal in self.signals],
        }


class AnomalyDetector:
    """Bewertet Adressen gegen die gelernte Grundlinie."""

    def __init__(self, config: Optional[AnomalyConfig] = None, guard=None) -> None:
        self.config = config or AnomalyConfig()
        self.guard = guard
        self._baseline: Optional[Baseline] = None
        self._cache: Optional[List[AnomalyReport]] = None
        self._cache_at = 0.0
        self._cache_window = 0.0
        self._last_evaluate = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    # -- Grundlinie ----------------------------------------------------
    def baseline(self, store=None) -> Optional[Baseline]:
        if self._baseline is not None:
            return self._baseline
        store = store or (self.guard.store if self.guard else None)
        if store is None:
            return None
        raw = store.get_meta(BASELINE_KEY)
        if not raw:
            return None
        try:
            self._baseline = Baseline.from_dict(json.loads(raw))
        except (ValueError, TypeError):
            log.warning("Gespeicherte Grundlinie ist unlesbar - bitte neu lernen")
            return None
        return self._baseline

    def learn_and_store(self, store=None, *, days: Optional[float] = None,
                        now: Optional[float] = None) -> Baseline:
        store = store or (self.guard.store if self.guard else None)
        if store is None:
            raise ValueError("Kein Speicher verfuegbar")
        if now is None and self.guard is not None:
            now = self.guard.clock()
        baseline = learn(store, days=days or self.config.learn_days, now=now)
        store.set_meta(BASELINE_KEY, json.dumps(baseline.as_dict()))
        store.set_meta(LAST_LEARN_KEY, str(baseline.created_ts))
        self._baseline = baseline
        self._cache = None
        return baseline

    def ready(self, store=None) -> bool:
        """Reicht die Datengrundlage fuer ein Urteil?"""
        baseline = self.baseline(store)
        return bool(baseline and baseline.usable(
            self.config.min_events, self.config.min_addresses
        ))

    def status(self, store=None) -> dict:
        baseline = self.baseline(store)
        if baseline is None:
            return {"ready": False, "reason": "Noch keine Grundlinie gelernt "
                                              "('loginshield learn')"}
        if not baseline.usable(self.config.min_events, self.config.min_addresses):
            return {
                "ready": False,
                "reason": (
                    f"Datengrundlage zu duenn: {baseline.ereignisse} Ereignisse von "
                    f"{baseline.adressen} Adressen (noetig: {self.config.min_events} "
                    f"von {self.config.min_addresses}). Es wird noch nicht geurteilt."
                ),
                "events": baseline.ereignisse,
                "addresses": baseline.adressen,
            }
        return {
            "ready": True,
            "events": baseline.ereignisse,
            "addresses": baseline.adressen,
            "age_hours": round(baseline.alter_stunden, 1),
            "failure_ratio": round(baseline.fehlerquote, 3),
            "known_routes": len(baseline.bekannte_pfade),
        }

    # -- Einzelne Adresse ----------------------------------------------
    def score_profile(self, ip: str, entry: dict,
                      baseline: Baseline) -> AnomalyReport:
        """Bewertet ein fertiges Verhaltensprofil gegen die Grundlinie."""
        report = AnomalyReport(ip=ip)
        gewichte = self.config.weights

        # 1. Ungewoehnlich viele Ereignisse
        z = robust_z(entry["events"], baseline.ereignisse_je_ip_median,
                     baseline.ereignisse_je_ip_streuung)
        if z > 2:
            punkte = min(gewichte.get("volumen", 25), z * 4)
            report.signals.append(Signal(
                "volumen", entry["events"], baseline.ereignisse_je_ip_median, punkte,
                f"{entry['events']} Ereignisse - ueblich sind "
                f"{baseline.ereignisse_je_ip_median:.0f}",
            ))

        # 2. Ungewoehnlich viele verschiedene Pfade (Abklappern)
        pfade = len(entry["routes"])
        z = robust_z(pfade, baseline.pfade_je_ip_median, baseline.pfade_je_ip_streuung)
        if z > 2:
            punkte = min(gewichte.get("pfadvielfalt", 25), z * 5)
            report.signals.append(Signal(
                "pfadvielfalt", pfade, baseline.pfade_je_ip_median, punkte,
                f"{pfade} verschiedene Pfade - ueblich sind "
                f"{baseline.pfade_je_ip_median:.0f}",
            ))

        # 3. Pfade, die es hier noch nie gab
        if entry["routes"] and baseline.bekannte_pfade:
            unbekannt = [r for r in entry["routes"] if r not in baseline.bekannte_pfade]
            anteil = len(unbekannt) / len(entry["routes"])
            if anteil > 0.5 and len(unbekannt) >= 3:
                punkte = min(gewichte.get("neue_pfade", 20), anteil * 20)
                report.signals.append(Signal(
                    "neue_pfade", len(unbekannt), 0, punkte,
                    f"{len(unbekannt)} nie zuvor angefragte Pfade "
                    f"({anteil * 100:.0f}% der Zugriffe)",
                ))

        # 4. Fehlerquote weit ueber dem Normalen
        if entry["events"] >= 5:
            quote = entry["failures"] / entry["events"]
            if quote > max(0.5, baseline.fehlerquote * 3):
                punkte = min(gewichte.get("fehlerquote", 20), quote * 20)
                report.signals.append(Signal(
                    "fehlerquote", round(quote, 2), round(baseline.fehlerquote, 2),
                    punkte,
                    f"{quote * 100:.0f}% Fehlversuche - ueblich sind "
                    f"{baseline.fehlerquote * 100:.0f}%",
                ))

        # 5. Viele verschiedene Konten
        konten = len(entry["identities"])
        z = robust_z(konten, baseline.konten_je_ip_median, baseline.konten_je_ip_streuung)
        if konten >= 3 and z > 2:
            punkte = min(gewichte.get("kontenvielfalt", 20), z * 5)
            report.signals.append(Signal(
                "kontenvielfalt", konten, baseline.konten_je_ip_median, punkte,
                f"{konten} verschiedene Konten - ueblich sind "
                f"{baseline.konten_je_ip_median:.0f}",
            ))

        # 6. Unbekannte Programmkennung
        if entry["agents"] and baseline.bekannte_kennungen:
            neu = [a for a in entry["agents"] if a not in baseline.bekannte_kennungen]
            if neu and len(neu) == len(entry["agents"]):
                punkte = gewichte.get("kennung", 10)
                report.signals.append(Signal(
                    "kennung", len(neu), 0, punkte,
                    f"unbekannte Programmkennung ({neu[0][:40]})",
                ))

        # 7. Aktivitaet zu sonst stillen Zeiten
        if baseline.aktive_stunden and entry["hours"]:
            still = [h for h in entry["hours"] if h not in baseline.aktive_stunden]
            if still and len(still) == len(entry["hours"]):
                punkte = gewichte.get("uhrzeit", 10)
                report.signals.append(Signal(
                    "uhrzeit", still[0], 0, punkte,
                    f"aktiv zu einer Zeit, zu der hier sonst nichts passiert "
                    f"({still[0]:02d} Uhr UTC)",
                ))

        # 8. Takt: erst die schiere Geschwindigkeit ...
        dauer = entry["last_ts"] - entry["first_ts"]
        if entry["events"] >= 10 and dauer > 0:
            takt = dauer / entry["events"]
            if takt < 2.0:
                punkte = gewichte.get("takt", 15)
                report.signals.append(Signal(
                    "takt", round(takt, 2), 0, punkte,
                    f"ein Zugriff alle {takt:.1f}s ueber {dauer:.0f}s - "
                    f"maschinell schnell",
                ))

        # 9. ... dann der Rhythmus. Das ist die schaerfere Frage: ein
        # Programm, das alle 30 Sekunden anfragt, ist langsam - aber
        # unmenschlich gleichmaessig. Nur ueber die Geschwindigkeit waere
        # es nicht aufgefallen.
        gleichmass = regelmaessigkeit(entry.get("timestamps") or [])
        if gleichmass is not None and gleichmass < 0.35:
            erwartet = baseline.regelmaessigkeit_median
            if erwartet <= 0 or gleichmass < erwartet * 0.5:
                punkte = gewichte.get("regelmaessigkeit", 20)
                report.signals.append(Signal(
                    "regelmaessigkeit", round(gleichmass, 3), round(erwartet, 2),
                    punkte,
                    f"unmenschlich gleichmaessiger Rhythmus "
                    f"(Schwankung {gleichmass * 100:.0f}%, ueblich "
                    f"{erwartet * 100:.0f}%)",
                ))

        # 10. Streuung ueber die Pfade: ein Scanner ruft jede Seite genau
        # einmal auf, ein Besucher kehrt zurueck. Bei gleicher Anzahl
        # unterscheidet erst die Verteilung die beiden.
        zaehler = list((entry.get("route_counts") or {}).values())
        if len(zaehler) >= 5 and baseline.pfad_entropie_median > 0:
            streuung = entropy(zaehler)
            z = robust_z(streuung, baseline.pfad_entropie_median,
                         baseline.pfad_entropie_streuung)
            if z > 2:
                punkte = min(gewichte.get("pfadstreuung", 15), z * 4)
                report.signals.append(Signal(
                    "pfadstreuung", round(streuung, 2),
                    round(baseline.pfad_entropie_median, 2), punkte,
                    f"Zugriffe gleichmaessig ueber {len(zaehler)} Pfade verteilt "
                    f"statt auf wenige konzentriert",
                ))

        roh = sum(signal.punkte for signal in report.signals)

        # Beweislast: Wer nur wenige Ereignisse erzeugt hat, kann nicht
        # "kritisch" sein - dafuer ist die Datenbasis zu duenn. Der Wert
        # waechst mit der Zahl der Belege.
        mindest = max(1, self.config.min_evidence)
        vertrauen = min(1.0, entry["events"] / mindest)
        report.evidence = entry["events"]
        report.confidence = vertrauen
        report.score = min(100.0, roh * vertrauen)
        return report

    def global_report(self, *, window: Optional[float] = None,
                      now: Optional[float] = None, store=None) -> AnomalyReport:
        """Die Lage im Ganzen statt Adresse fuer Adresse.

        Der blinde Fleck jeder Einzelbewertung: Verteilen 200 Adressen je
        fuenf Fehlversuche unter sich auf, ist keine davon auffaellig - in
        der Summe ist es trotzdem ein Angriff. Diese Sicht misst deshalb den
        Server als Ganzes gegen die Grundlinie.
        """
        report = AnomalyReport(ip="(gesamt)")
        store = store or (self.guard.store if self.guard else None)
        baseline = self.baseline(store)
        if store is None or baseline is None or not self.enabled:
            return report
        if not baseline.usable(self.config.min_events, self.config.min_addresses):
            return report

        if now is None:
            now = self.guard.clock() if self.guard else time.time()
        window = window or self.config.window
        seit = now - window
        stunden = max(window / 3600.0, 0.01)

        profile = store.profile_by_ip(seit)
        fehler = sum(entry["failures"] for entry in profile.values())
        fehler_je_stunde = fehler / stunden

        # 1. Fehlversuche insgesamt weit ueber dem Ueblichen
        z = robust_z(fehler_je_stunde, baseline.fehler_je_stunde_median,
                     baseline.fehler_je_stunde_streuung)
        if z >= 3 and fehler >= 20:
            punkte = min(40, z * 5)
            report.signals.append(Signal(
                "gesamtlast", round(fehler_je_stunde, 1),
                round(baseline.fehler_je_stunde_median, 1), punkte,
                f"{fehler} Fehlversuche in {stunden:.1f}h - ueblich sind "
                f"{baseline.fehler_je_stunde_median:.0f} pro Stunde",
            ))

        # 2. Ungewoehnlich viele Adressen beteiligt: das Kennzeichen eines
        #    verteilten Angriffs, bei dem einzeln niemand auffaellt.
        beteiligt = sum(1 for entry in profile.values() if entry["failures"] > 0)
        ueblich_beteiligt = max(1.0, baseline.adressen * (window / max(
            baseline.bis_ts - baseline.von_ts, 1.0)))
        if beteiligt >= 20 and beteiligt > ueblich_beteiligt * 3:
            punkte = min(35, (beteiligt / ueblich_beteiligt) * 5)
            report.signals.append(Signal(
                "verteilte_last", beteiligt, round(ueblich_beteiligt, 1), punkte,
                f"{beteiligt} verschiedene Adressen mit Fehlversuchen - "
                f"ueblich sind etwa {ueblich_beteiligt:.0f}",
            ))

        # 3. Die Fehlerquote des ganzen Servers kippt
        gesamt = sum(entry["events"] for entry in profile.values())
        if gesamt >= 50:
            quote = fehler / gesamt
            if quote > max(0.4, baseline.fehlerquote * 3):
                punkte = min(25, quote * 25)
                report.signals.append(Signal(
                    "gesamtfehlerquote", round(quote, 2),
                    round(baseline.fehlerquote, 2), punkte,
                    f"{quote * 100:.0f}% aller Anfragen sind Fehlversuche - "
                    f"ueblich sind {baseline.fehlerquote * 100:.0f}%",
                ))

        report.evidence = gesamt
        report.score = min(100.0, sum(signal.punkte for signal in report.signals))
        return report

    def scan(self, *, window: Optional[float] = None,
             now: Optional[float] = None, store=None) -> List[AnomalyReport]:
        """Bewertet alle Adressen des letzten Zeitfensters."""
        store = store or (self.guard.store if self.guard else None)
        if store is None or not self.enabled:
            return []
        baseline = self.baseline(store)
        if baseline is None or not baseline.usable(
            self.config.min_events, self.config.min_addresses
        ):
            return []

        if now is None:
            now = self.guard.clock() if self.guard else time.time()
        window = window or self.config.window
        profile = store.profile_by_ip(now - window)

        berichte = []
        for ip, entry in profile.items():
            if self.guard is not None and self.guard.is_allowlisted(ip):
                continue
            report = self.score_profile(ip, entry, baseline)
            if report.score >= self.config.report_score:
                berichte.append(report)
        berichte.sort(key=lambda r: r.score, reverse=True)
        return berichte

    def cached_scan(self, *, window: Optional[float] = None,
                    now: Optional[float] = None) -> List[AnomalyReport]:
        """Wie :meth:`scan`, aber mit kurzem Zwischenspeicher.

        Das Dashboard aktualisiert alle zehn Sekunden. Ohne Zwischenspeicher
        waere das auf einem belebten Server dauerhafte Rechenlast, weil jede
        Auswertung eine Stunde Ereignisse durchgeht.
        """
        if now is None:
            now = self.guard.clock() if self.guard else time.time()
        window = window or self.config.window
        ttl = self.config.cache_seconds

        if (self._cache is not None and self._cache_window == window
                and now - self._cache_at < ttl):
            return self._cache

        berichte = self.scan(window=window, now=now)
        self._cache = berichte
        self._cache_at = now
        self._cache_window = window
        return berichte

    def maintain(self, *, now: Optional[float] = None, store=None) -> dict:
        """Im laufenden Betrieb: bei Bedarf neu lernen und pruefen.

        Wird aus :meth:`Guard.maintenance` aufgerufen. Ohne diesen Weg liefe
        die Erkennung nur, wenn jemand von Hand nachsieht - eine Sperre bei
        ``action: block`` kaeme dann nie zustande.
        """
        if not self.enabled:
            return {"gelernt": False, "geprueft": 0}
        store = store or (self.guard.store if self.guard else None)
        if store is None:
            return {"gelernt": False, "geprueft": 0}
        if now is None:
            now = self.guard.clock() if self.guard else time.time()

        gelernt = False
        if self.config.relearn_hours > 0:
            try:
                zuletzt = float(store.get_meta(LAST_LEARN_KEY) or 0.0)
            except (TypeError, ValueError):
                zuletzt = 0.0
            # Auch der allererste Lauf lernt - dann steht die Grundlinie,
            # sobald genug Daten da sind, ohne dass jemand 'learn' tippt.
            if now - zuletzt >= self.config.relearn_hours * 3600:
                self.learn_and_store(store, now=now)
                gelernt = True

        geprueft: List[AnomalyReport] = []
        if self.config.evaluate_interval > 0:
            if now - self._last_evaluate >= self.config.evaluate_interval:
                self._last_evaluate = now
                geprueft = self.evaluate(now=now)

        return {"gelernt": gelernt, "geprueft": len(geprueft)}

    def evaluate(self, *, now: Optional[float] = None) -> List[AnomalyReport]:
        """Bewertet und handelt - je nach ``action``.

        Standard ist ``report``: nur vermerken. Eine statistische Abweichung
        ist ein Verdacht, kein Beweis - ein Werbeschub sieht einem Angriff
        zunaechst aehnlich.
        """
        berichte = self.scan(now=now)
        if self.guard is None:
            return berichte

        for report in berichte:
            detail = f"Anomalie {report.score:.0f}/100: {report.summary}"
            if self.config.action == "block" and report.score >= self.config.block_score:
                self.guard.record_honeypot(
                    report.ip, route="", reason=Reason.ANOMALY,
                    source="anomaly", detail=detail,
                    seconds=self.config.block_seconds,
                )
            else:
                self.guard.record_suspicious(
                    report.ip, source="anomaly", detail=detail
                )
        return berichte
