"""Benachrichtigungen: Bescheid sagen, statt gefunden zu werden.

Bisher erfuhr man nur etwas, wenn man nachsah. Das Dashboard liegt jetzt
auf dem Startbildschirm - aber es meldet sich nie von selbst. Wer nachts
um drei angegriffen wird, sieht es am naechsten Morgen.

Drei Wege, alle mit der Standardbibliothek:

* **webhook** - eine Adresse, an die eine kurze Meldung geschickt wird.
  Das ist auch der Weg aufs iPhone: Dienste wie ntfy.sh nehmen einen
  einfachen POST entgegen und schicken eine Mitteilung aufs Telefon.
* **email** - ueber einen SMTP-Server.
* **command** - ein eigenes Programm mit der Meldung als Argument.

Zwei Dinge sind dabei wichtiger als die Zustellung selbst:

**Nichts darf die Anfrage aufhalten.** Ein SMTP-Server, der nicht
antwortet, wuerde sonst jeden Login blockieren, der eine Sperre ausloest.
Deshalb wird ausschliesslich in einem eigenen Faden zugestellt, mit
Zeitgrenze, und Fehler werden protokolliert statt weitergereicht.

**Niemand liest 400 Meldungen.** Ein Angriff erzeugt viele Ereignisse in
kurzer Zeit. Gleichartige Meldungen werden deshalb zusammengefasst: die
erste geht sofort raus, weitere derselben Art erst nach einer Sperrfrist -
und dann mit der Anzahl der uebersprungenen im Text.
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Dict, List, Optional

from .config import NotifyConfig

log = logging.getLogger("loginshield.notify")

#: Mehr als so viele unzugestellte Meldungen werden verworfen. Lieber ein
#: paar Meldungen verlieren als Speicher volllaufen lassen, waehrend ein
#: Angriff laeuft.
MAX_WARTESCHLANGE = 200


@dataclass
class Meldung:
    """Eine Nachricht, die hinausgehen soll."""

    titel: str
    text: str
    schwere: int = 5
    #: Gleiche Kennung = gleichartige Meldung (fuer die Sperrfrist).
    kennung: str = ""
    ts: float = 0.0
    #: Wie viele gleichartige seit der letzten Zustellung unterdrueckt wurden.
    unterdrueckt: int = 0

    def betreff(self) -> str:
        text = f"[LoginShield] {self.titel}"
        if self.unterdrueckt:
            text += f" (+{self.unterdrueckt} weitere)"
        return text

    def als_text(self) -> str:
        zeilen = [self.text]
        if self.unterdrueckt:
            zeilen.append(f"\n{self.unterdrueckt} weitere gleichartige Meldung(en) "
                          f"in der Zwischenzeit.")
        zeilen.append(f"\nZeit: {time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(self.ts))}")
        return "\n".join(zeilen)

    def as_dict(self) -> dict:
        return {"titel": self.titel, "text": self.text, "schwere": self.schwere,
                "kennung": self.kennung, "ts": self.ts,
                "unterdrueckt": self.unterdrueckt}


class Notifier:
    """Nimmt Meldungen entgegen und stellt sie im Hintergrund zu."""

    def __init__(self, config: Optional[NotifyConfig] = None,
                 clock=time.time, sender=None) -> None:
        self.config = config or NotifyConfig()
        self.clock = clock
        #: Zum Testen austauschbar; sonst der echte Versand.
        self._sender = sender or self._zustellen
        self._queue: "queue.Queue[Optional[Meldung]]" = queue.Queue(MAX_WARTESCHLANGE)
        self._faden: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        #: Kennung -> (letzte Zustellung, seither unterdrueckte)
        self._letzte: Dict[str, List[float]] = {}
        self.zugestellt = 0
        self.fehler = 0
        self.verworfen = 0

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled) and self.config.method != "none"

    # ------------------------------------------------------------------
    def notify(self, titel: str, text: str, *, schwere: int = 5,
               kennung: str = "") -> bool:
        """Meldet ein Ereignis. Kehrt sofort zurueck.

        Rueckgabe sagt nur, ob die Meldung angenommen wurde - nicht, ob
        sie angekommen ist. Das kann sie auch nicht: Zugestellt wird
        spaeter und woanders.
        """
        if not self.enabled or schwere < self.config.min_severity:
            return False

        jetzt = self.clock()
        kennung = kennung or titel
        with self._lock:
            eintrag = self._letzte.get(kennung)
            if eintrag is not None:
                letzte, unterdrueckt = eintrag
                if jetzt - letzte < self.config.min_interval:
                    # Zu frueh: nur mitzaehlen, nicht zustellen.
                    eintrag[1] = unterdrueckt + 1
                    return False
                self._letzte[kennung] = [jetzt, 0.0]
                nachzutragen = int(unterdrueckt)
            else:
                self._letzte[kennung] = [jetzt, 0.0]
                nachzutragen = 0
            # Der Speicher darf nicht unbegrenzt wachsen.
            if len(self._letzte) > 512:
                alt = sorted(self._letzte.items(), key=lambda p: p[1][0])[:256]
                for schluessel, _ in alt:
                    self._letzte.pop(schluessel, None)

        meldung = Meldung(titel=titel, text=text, schwere=schwere,
                          kennung=kennung, ts=jetzt, unterdrueckt=nachzutragen)
        return self._einreihen(meldung)

    def _einreihen(self, meldung: Meldung) -> bool:
        self.start()
        try:
            self._queue.put_nowait(meldung)
        except queue.Full:
            self.verworfen += 1
            log.warning("Benachrichtigung verworfen, Warteschlange voll (%s)",
                        meldung.titel)
            return False
        return True

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._faden is not None and self._faden.is_alive():
            return
        with self._lock:
            if self._faden is not None and self._faden.is_alive():
                return
            self._faden = threading.Thread(
                target=self._schleife, name="loginshield-benachrichtigung",
                daemon=True,
            )
            self._faden.start()

    def _schleife(self) -> None:
        while True:
            meldung = self._queue.get()
            if meldung is None:
                return
            try:
                self._sender(meldung)
                self.zugestellt += 1
            except Exception as exc:      # pragma: no cover - netzabhaengig
                self.fehler += 1
                log.warning("Benachrichtigung nicht zugestellt (%s): %s",
                            self.config.method, exc)

    def close(self, timeout: float = 3.0) -> None:
        if self._faden is None:
            return
        try:
            self._queue.put_nowait(None)
        except queue.Full:      # pragma: no cover
            pass
        self._faden.join(timeout=timeout)
        self._faden = None

    def flush(self, timeout: float = 5.0) -> bool:
        """Wartet, bis die Warteschlange leer ist (fuer Tests und den CLI-Test)."""
        ende = time.time() + timeout
        while time.time() < ende:
            if self._queue.empty():
                time.sleep(0.02)        # dem Faden Zeit zum Abschluss geben
                return True
            time.sleep(0.02)
        return False

    # ------------------------------------------------------------------
    # Die eigentlichen Wege
    # ------------------------------------------------------------------
    def _zustellen(self, meldung: Meldung) -> None:
        art = self.config.method
        if art == "webhook":
            self._webhook(meldung)
        elif art == "email":
            self._email(meldung)
        elif art == "command":
            self._command(meldung)

    def _webhook(self, meldung: Meldung) -> None:
        ziel = self.config.url
        if not ziel:
            raise ValueError("notify.url fehlt")

        if self.config.format == "text":
            # ntfy.sh und aehnliche Dienste nehmen den Text direkt entgegen
            # und machen daraus eine Mitteilung auf dem Telefon.
            daten = meldung.als_text().encode("utf-8")
            kopf = {"Content-Type": "text/plain; charset=utf-8",
                    "Title": meldung.betreff(),
                    "Priority": "high" if meldung.schwere >= 8 else "default"}
        else:
            daten = json.dumps(meldung.as_dict(), ensure_ascii=False).encode("utf-8")
            kopf = {"Content-Type": "application/json; charset=utf-8"}

        for name, wert in (self.config.headers or {}).items():
            kopf[str(name)] = str(wert)

        anfrage = urllib.request.Request(ziel, data=daten, headers=kopf,
                                         method="POST")
        with urllib.request.urlopen(anfrage, timeout=self.config.timeout) as antwort:
            antwort.read(1024)

    def _email(self, meldung: Meldung) -> None:
        if not (self.config.smtp_host and self.config.mail_to):
            raise ValueError("notify.smtp_host oder notify.mail_to fehlt")

        nachricht = EmailMessage()
        nachricht["Subject"] = meldung.betreff()
        nachricht["From"] = self.config.mail_from or self.config.mail_to[0]
        nachricht["To"] = ", ".join(self.config.mail_to)
        nachricht.set_content(meldung.als_text())

        if self.config.smtp_ssl:
            verbindung = smtplib.SMTP_SSL(self.config.smtp_host,
                                          self.config.smtp_port,
                                          timeout=self.config.timeout)
        else:
            verbindung = smtplib.SMTP(self.config.smtp_host,
                                      self.config.smtp_port,
                                      timeout=self.config.timeout)
        try:
            if self.config.smtp_starttls and not self.config.smtp_ssl:
                verbindung.starttls()
            if self.config.smtp_user:
                verbindung.login(self.config.smtp_user, self.config.smtp_password)
            verbindung.send_message(nachricht)
        finally:
            try:
                verbindung.quit()
            except Exception:   # pragma: no cover - Verbindung schon zu
                pass

    def _command(self, meldung: Meldung) -> None:
        if not self.config.command:
            raise ValueError("notify.command fehlt")
        argumente = [
            teil.replace("{titel}", meldung.titel)
                .replace("{text}", meldung.text)
                .replace("{schwere}", str(meldung.schwere))
            for teil in self.config.command
        ]
        # Feste Argumentliste, keine Shell - nichts wird interpretiert.
        subprocess.run(argumente, timeout=self.config.timeout,  # noqa: S603
                       capture_output=True, check=False)
