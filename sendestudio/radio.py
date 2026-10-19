"""Radio nach der Uhr.

Eine Radio-Sendung spielt ihre veroeffentlichten Folgen als Endlosschleife.
Wo die Schleife gerade steht, folgt allein aus der Uhrzeit - jeder, der
einschaltet, hoert dieselbe Stelle, wie bei einem echten Sender. Dafuer
braucht es keinen Streaming-Server: Jeder Hoerer rechnet die Position
selbst aus (siehe ``RADIO_JS`` in :mod:`sendestudio.site`, dieselbe
Rechnung wie hier) und springt in der Datei an die richtige Stelle. Das
funktioniert deshalb auch auf einer rein statischen Seite.

Die Reihenfolge ist die der Veroeffentlichung, aelteste zuerst. Kommt eine
Folge hinzu, aendert sich die Schleifenlaenge und das Programm springt -
wie bei einem Sender, der sein Programm umstellt.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Bezugspunkt der Uhr: 1. Januar 2024, 00:00 UTC.
ANKER = 1_704_067_200


def programm(folgen: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Die Folgen in Sendereihenfolge - nur solche mit bekannter Dauer."""
    spielbar = [f for f in folgen if f.get("online") and f.get("datei") and f.get("dauer", 0) > 0]
    return sorted(spielbar, key=lambda f: (f["veroeffentlicht"], f["id"]))


def jetzt(folgen: List[Dict[str, Any]], zeit: float) -> Optional[Dict[str, Any]]:
    """Was laeuft zur Zeit ``zeit``? ``None``, wenn das Programm leer ist."""
    liste = programm(folgen)
    gesamt = sum(f["dauer"] for f in liste)
    if gesamt <= 0:
        return None
    pos = (zeit - ANKER) % gesamt
    for i, f in enumerate(liste):
        if pos < f["dauer"]:
            return {"index": i, "folge": f, "offset": pos, "rest": f["dauer"] - pos}
        pos -= f["dauer"]
    # Nur durch Rundung erreichbar: dann beginnt gerade die erste Folge.
    f = liste[0]
    return {"index": 0, "folge": f, "offset": 0.0, "rest": f["dauer"]}
