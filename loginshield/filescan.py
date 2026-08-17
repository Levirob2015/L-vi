"""Dateipruefung: Schadcode auf dem Server finden, statt ihn zu behaupten.

Was hier **nicht** passiert
---------------------------
Es wird kein eigener Virenscanner geschrieben. Eine Erkennungsmaschine mit
eigenen Signaturen zu bauen, waere unehrlich: Sie haette keine gepflegte
Signaturdatenbank, keine Aktualisierung, keine Heuristik - und wuerde
trotzdem "Virenschutz" behaupten. Software, die Schutz vortaeuscht, ist
schlechter als gar keine, weil man sich auf sie verlaesst.

Was hier passiert
-----------------
Drei Dinge, die auf einem Webserver wirklich zaehlen und die ein
allgemeiner Virenscanner gerade **nicht** gut abdeckt:

1. **Webshells.** Der klassische Fall nach einem erfolgreichen Angriff:
   Es wird eine kleine Skriptdatei abgelegt, ueber die sich der Server
   fernsteuern laesst. Solche Dateien haben wiederkehrende Merkmale.
2. **Getarnte Dateien.** Eine ``rechnung.pdf.php``, oder eine ``.jpg``, die
   in Wahrheit mit ``<?php`` beginnt - der Standardweg, um an einer
   Upload-Pruefung vorbeizukommen.
3. **Anbindung an einen echten Scanner.** Ist ClamAV installiert, wird es
   benutzt. Damit kommen echte, gepflegte Signaturen ins Spiel - ohne dass
   dieses Projekt so tut, als haette es eigene.

Gefundene Dateien werden **nie geloescht**, sondern in Quarantaene
verschoben: Nach einem Einbruch sind sie Beweismittel, und ein Fehlalarm
soll keine Daten vernichten.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .config import MalwareConfig
from .models import sauber

log = logging.getLogger("loginshield.filescan")

#: Standard-Testdatei der Virenschutzbranche (EICAR). Voellig harmlos, aber
#: jeder Scanner muss sie erkennen - damit laesst sich pruefen, ob die
#: Pruefkette ueberhaupt funktioniert.
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
    b"ANTIVIRUS-TEST-FILE!$H+H*"
)


@dataclass(frozen=True)
class FileRule:
    """Ein Erkennungsmerkmal fuer Dateiinhalte."""

    name: str
    pattern: bytes
    severity: int
    description: str
    regex: bool = False
    #: Nur in Skriptdateien pruefen. Manche Merkmale (etwa aneinander-
    #: gehaengte Zeichenketten) kommen in gewoehnlichem Text oder in
    #: minimiertem JavaScript vor und waeren dort ein Fehlalarm.
    only_scripts: bool = False


#: Merkmale, die in Webshells wiederkehren. Bewusst auf die Kombination
#: "Ausfuehrung + Eingabe von aussen" gezielt - einzelne dieser Funktionen
#: kommen auch in harmlosem Code vor.
WEBSHELL_RULES: Sequence[FileRule] = (
    FileRule("eval_eingabe", rb"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", 10,
             "Code aus einer Anfrage wird direkt ausgefuehrt", regex=True),
    FileRule("system_eingabe",
             rb"(system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_"
             rb"(GET|POST|REQUEST|COOKIE)", 10,
             "Systembefehl aus einer Anfrage", regex=True),
    FileRule("eval_base64", rb"eval\s*\(\s*(base64_decode|gzinflate|str_rot13)", 9,
             "Verschleierter, ausgefuehrter Code", regex=True),
    FileRule("assert_eingabe", rb"assert\s*\(\s*\$_", 9,
             "assert() mit Fremdeingabe", regex=True),
    FileRule("preg_e_modifikator", rb"preg_replace\s*\(\s*['\"].*/e['\"]", 9,
             "preg_replace mit /e - fuehrt Code aus", regex=True),
    # Die Kennungen brauchen Wortgrenzen, und "WSO" zusaetzlich eine
    # Versionsnummer mit Punkt. Ohne das passt "WSO" auf jede zufaellige
    # Zeichenfolge in einem base64-Block - und ein TLS-Zertifikat unter
    # /etc/ssl/certs galt als Webshell. Ein Fehlalarm mit Schwere 10 legt
    # im Quarantaene-Betrieb echte Dateien beiseite.
    FileRule("bekannte_shell",
             rb"\b(c99shell|r57shell|FilesMan|b374k|IndoXploit)\b"
             rb"|\bWSO\s*[0-9]+\.[0-9]+", 10,
             "Kennung einer bekannten Webshell", regex=True),
    FileRule("python_exec_eingabe",
             rb"(os\.system|subprocess\.(call|run|Popen))\s*\(\s*request\.", 9,
             "Systembefehl aus einer Web-Anfrage (Python)", regex=True),
    FileRule("jsp_runtime", rb"Runtime\.getRuntime\(\)\.exec\s*\(\s*request", 10,
             "Systembefehl aus einer Web-Anfrage (JSP)", regex=True),
    FileRule("versteckter_upload", rb"move_uploaded_file\s*\(.{0,80}\$_", 5,
             "Datei-Upload aus einer Anfrage", regex=True),

    # -- Verschleierung ------------------------------------------------
    # Die Regeln oben treffen den offenen Fall: eval($_POST[...]). Wer eine
    # Webshell ablegt, schreibt sie heute selten so hin. Er zerlegt den
    # Funktionsnamen, ruft ihn ueber eine Variable auf oder setzt den
    # Namen der Superglobalen aus Bruchstuecken zusammen. Das Ergebnis ist
    # dasselbe - deshalb wird auch der Umweg erkannt.
    FileRule("dynamische_funktion_eingabe",
             rb"\$\{?\w+\}?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[", 9,
             "Funktionsname steht in einer Variablen und wird mit "
             "Fremdeingabe aufgerufen", regex=True),
    FileRule("call_user_func_eingabe",
             rb"call_user_func(_array)?\s*\(.{0,60}\$_(GET|POST|REQUEST|COOKIE)",
             9, "call_user_func mit Fremdeingabe", regex=True),
    FileRule("zerlegte_superglobale",
             rb"\$\{\s*['\"](_(GET|POST|REQUEST|COOKIE)|[A-Za-z_]{0,6}['\"]\s*\.)",
             8, "Name einer Superglobalen aus Bruchstuecken zusammengesetzt",
             regex=True),
    FileRule("include_eingabe",
             rb"(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)",
             9, "Datei aus einer Anfrage wird eingebunden (LFI/RFI)",
             regex=True),
    FileRule("remote_ausfuehrung",
             rb"(file_get_contents|curl_exec|fsockopen|fopen)\s*\(\s*\$_"
             rb"(GET|POST|REQUEST|COOKIE)", 8,
             "Abruf einer Adresse aus einer Anfrage", regex=True),
    FileRule("chr_kette", rb"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(", 6,
             "Zeichenkette aus chr() zusammengesetzt - Verschleierung",
             regex=True, only_scripts=True),
    # 24 statt 10: Bei 10 meldete die Regel Zeichensatz-Tabellen in der
    # Python-Standardbibliothek. Gemessen an rund 4000 gewoehnlichen
    # Dateien meldet sie ab 24 nichts mehr - eine verschleierte Nutzlast
    # ist um ein Vielfaches laenger.
    FileRule("hex_verschleierung", rb"(\\x[0-9A-Fa-f]{2}){24,}", 5,
             "lange Folge hexadezimal geschriebener Zeichen",
             regex=True, only_scripts=True),
    FileRule("shell_passwortabfrage",
             rb"(md5|sha1|crc32)\s*\(\s*\$_(POST|GET|COOKIE)\s*\[[^\]]{0,30}\]"
             rb"\s*\)\s*(===?|!=)", 7,
             "Passwortabfrage auf Fremdeingabe - typische Shell-Anmeldung",
             regex=True),
    FileRule("dateirechte_geaendert",
             rb"chmod\s*\(\s*.{0,40},\s*0?7[0-7][0-7]\s*\)", 4,
             "setzt weitreichende Dateirechte", regex=True, only_scripts=True),
)

#: Merkmale in Dateien mit einem bestimmten Namen. ``AddType ... php`` ist
#: in einer .htaccess der uebliche Weg, hochgeladene Bilder doch noch als
#: Programm ausfuehren zu lassen - in einer beliebigen Textdatei waere
#: dieselbe Zeile dagegen voellig harmlos.
NAME_RULES: Sequence[Tuple[str, FileRule]] = (
    (".htaccess", FileRule(
        "htaccess_php_freigabe",
        rb"(AddType|AddHandler|SetHandler)[^\n]{0,80}php|php_flag\s+engine\s+on",
        8, "erlaubt die Ausfuehrung von PHP in diesem Verzeichnis",
        regex=True)),
    (".htaccess", FileRule(
        "htaccess_schutz_entfernt", rb"(Satisfy\s+any|Allow\s+from\s+all)", 4,
        "hebt eine Zugriffsbeschraenkung auf", regex=True)),
)

#: Anfangsbytes und was sie bedeuten.
MAGIC = (
    (b"\x7fELF", "ausfuehrbare Linux-Datei"),
    (b"MZ", "ausfuehrbare Windows-Datei"),
    (b"#!", "Skript mit Interpreterzeile"),
    (b"<?php", "PHP-Quelltext"),
    (b"<?=", "PHP-Kurzform"),
    (b"PK\x03\x04", "ZIP-Archiv"),
)

#: Dateiformate, die in Wahrheit ZIP-Archive sind. Ein ``PK``-Anfang ist
#: bei ihnen kein Widerspruch zur Endung, sondern voellig richtig - sonst
#: waere jedes hochgeladene Word-Dokument ein Fund.
ZIP_FORMATE = {
    ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".jar", ".apk", ".epub",
}

#: Endungen, hinter denen ein anderer Inhalt stecken kann.
HARMLOSE_ENDUNGEN = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg",
    ".pdf", ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".zip", ".ico",
}


@dataclass
class FileFinding:
    name: str
    severity: int
    description: str

    def as_dict(self) -> dict:
        return {"name": self.name, "severity": self.severity,
                "description": self.description}


@dataclass
class ScanResult:
    """Ergebnis einer Dateipruefung - immer mit Begruendung."""

    path: str = ""
    size: int = 0
    sha256: str = ""
    findings: List[FileFinding] = field(default_factory=list)
    score: int = 0
    error: str = ""

    @property
    def clean(self) -> bool:
        return not self.findings and not self.error

    @property
    def verdict(self) -> str:
        if self.error:
            return "ungeprueft"
        if not self.findings:
            return "sauber"
        if self.score >= 10:
            return "schadhaft"
        if self.score >= 5:
            return "verdaechtig"
        return "auffaellig"

    @property
    def summary(self) -> str:
        if self.error:
            return self.error
        if not self.findings:
            return "unauffaellig"
        return "; ".join(f.description for f in self.findings[:3])

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "score": self.score,
            "verdict": self.verdict,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
            "error": self.error,
        }


class FileScanner:
    """Prueft Dateien und Dateiinhalte auf Merkmale von Schadcode."""

    def __init__(self, config: Optional[MalwareConfig] = None, guard=None,
                 run=None) -> None:
        self.config = config or MalwareConfig()
        self.guard = guard
        self._run = run or _run_command
        aus = set(self.config.disabled_rules)
        self._rules = [
            (rule, re.compile(rule.pattern, re.IGNORECASE) if rule.regex else None)
            for rule in WEBSHELL_RULES
            if rule.name not in aus
        ]
        self._name_rules = [
            (name, rule, re.compile(rule.pattern, re.IGNORECASE))
            for name, rule in NAME_RULES
            if rule.name not in aus
        ]
        self._heuristiken = [
            h for h in (_heuristik_zerlegte_texte, _heuristik_base64_block)
            if h.__name__.replace("_heuristik_", "") not in aus
        ]
        self._clamav: Optional[str] = None
        self._clamav_geprueft = False

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    # ------------------------------------------------------------------
    # ClamAV - ein echter Scanner, wenn vorhanden
    # ------------------------------------------------------------------
    def clamav_binary(self) -> Optional[str]:
        """Findet clamdscan/clamscan, falls die Anbindung erlaubt ist."""
        if self.config.clamav == "off":
            return None
        if self._clamav_geprueft:
            return self._clamav
        self._clamav_geprueft = True
        for name in ("clamdscan", "clamscan"):
            if shutil.which(name):
                self._clamav = name
                log.info("ClamAV gefunden: %s", name)
                break
        else:
            if self.config.clamav == "on":
                log.warning(
                    "clamav: on gesetzt, aber weder clamdscan noch clamscan "
                    "gefunden - es wird nur mit eigenen Merkmalen geprueft"
                )
        return self._clamav

    def _clamav_scan(self, path: str) -> Optional[FileFinding]:
        binary = self.clamav_binary()
        if binary is None:
            return None
        result = self._run([binary, "--no-summary", path], self.config.timeout)
        # 0 = sauber, 1 = Fund, 2 = Fehler
        if result[0] == 1:
            name = ""
            for zeile in result[1].splitlines():
                if ":" in zeile and "FOUND" in zeile:
                    name = zeile.split(":", 1)[1].replace("FOUND", "").strip()
                    break
            return FileFinding("clamav", 10,
                               f"ClamAV: {name or 'Fund'}")
        if result[0] not in (0, 1):
            log.debug("ClamAV meldete Fehler: %s", result[2][:200])
        return None

    # ------------------------------------------------------------------
    # Pruefung
    # ------------------------------------------------------------------
    def scan_bytes(self, data: bytes, filename: str = "") -> ScanResult:
        """Prueft einen Inhalt, ohne ihn auf die Platte zu schreiben.

        Fuer Uploads gedacht: erst pruefen, dann speichern.
        """
        result = ScanResult(path=filename, size=len(data))
        if not self.enabled:
            return result

        result.sha256 = hashlib.sha256(data).hexdigest()
        probe = data[: self.config.max_scan_bytes]
        ist_skript = self._ist_skript(filename, probe)

        if EICAR in probe:
            result.findings.append(FileFinding(
                "eicar", 10, "EICAR-Testdatei (harmlos, prueft die Pruefkette)"
            ))

        for rule, muster in self._rules:
            if rule.only_scripts and not ist_skript:
                continue
            treffer = muster.search(probe) if muster else (rule.pattern in probe)
            if treffer:
                result.findings.append(
                    FileFinding(rule.name, rule.severity, rule.description)
                )

        basisname = os.path.basename(filename).lower()
        for name, rule, muster in self._name_rules:
            if basisname == name and muster.search(probe):
                result.findings.append(
                    FileFinding(rule.name, rule.severity, rule.description)
                )

        if ist_skript:
            for heuristik in self._heuristiken:
                fund = heuristik(probe)
                if fund is not None:
                    result.findings.append(fund)

        result.findings.extend(self._check_tarnung(probe, filename))
        result.score = sum(f.severity for f in result.findings)
        return result

    def _ist_skript(self, filename: str, probe: bytes) -> bool:
        """Ist das eine Programmdatei - unabhaengig davon, wie sie heisst?

        Die Endung allein reicht nicht: Genau das Umbenennen ist ja der
        Trick. Deshalb zaehlt auch ein PHP-Anfang im Inhalt.
        """
        endung = os.path.splitext(os.path.basename(filename).lower())[1]
        if endung in self.config.script_extensions:
            return True
        kopf = probe[:512]
        return kopf.startswith(b"#!") or b"<?php" in kopf or b"<?=" in kopf

    def _check_tarnung(self, probe: bytes, filename: str) -> List[FileFinding]:
        """Passt der Inhalt zur Endung, und ist die Endung selbst harmlos?"""
        funde: List[FileFinding] = []
        if not filename:
            return funde

        name = os.path.basename(filename).lower()
        endung = os.path.splitext(name)[1]

        # Doppelte Endung: rechnung.pdf.php
        teile = name.split(".")
        if len(teile) >= 3:
            vorletzte = "." + teile[-2]
            if vorletzte in HARMLOSE_ENDUNGEN and endung in self.config.script_extensions:
                funde.append(FileFinding(
                    "doppelte_endung", 8,
                    f"getarnte Endung: {name} sieht aus wie {vorletzte}, "
                    f"ist aber {endung}",
                ))

        # Inhalt passt nicht zur Endung
        if endung in HARMLOSE_ENDUNGEN:
            for magic, bedeutung in MAGIC:
                if not probe.startswith(magic):
                    continue
                if magic == b"PK\x03\x04" and endung in ZIP_FORMATE:
                    break       # ein .docx *ist* ein ZIP-Archiv
                funde.append(FileFinding(
                    "inhalt_passt_nicht", 9,
                    f"{endung}-Datei enthaelt {bedeutung}",
                ))
                break
            # PHP irgendwo in einem vermeintlichen Bild
            if endung in {".jpg", ".jpeg", ".png", ".gif", ".webp"} and (
                b"<?php" in probe or b"<?=" in probe
            ):
                funde.append(FileFinding(
                    "php_im_bild", 9, "PHP-Code in einer Bilddatei",
                ))
        return funde

    def scan_file(self, path: str) -> ScanResult:
        """Prueft eine Datei auf der Platte."""
        result = ScanResult(path=path)
        if not self.enabled:
            return result
        try:
            groesse = os.path.getsize(path)
        except OSError as exc:
            result.error = f"nicht lesbar: {exc}"
            return result

        if groesse > self.config.max_file_bytes:
            result.size = groesse
            result.error = (
                f"uebersprungen: {groesse / 1e6:.1f} MB groesser als das Limit"
            )
            return result

        try:
            with open(path, "rb") as handle:
                data = handle.read(self.config.max_scan_bytes)
        except OSError as exc:
            result.error = f"nicht lesbar: {exc}"
            return result

        result = self.scan_bytes(data, filename=path)
        result.size = groesse

        if self.config.inspect_archives and data.startswith(b"PK\x03\x04"):
            for fund in self.scan_archive(path):
                result.findings.append(fund)
                result.score += fund.severity

        fund = self._clamav_scan(path)
        if fund is not None:
            result.findings.append(fund)
            result.score += fund.severity
        return result

    # ------------------------------------------------------------------
    # Archive
    # ------------------------------------------------------------------
    def scan_archive(self, path: str) -> List[FileFinding]:
        """Sieht in ein ZIP-Archiv hinein, ohne es auszupacken.

        Ein Archiv ist sonst ein blinder Fleck: Die Webshell darin faellt
        erst auf, wenn sie schon entpackt ist. Zwei Dinge werden geprueft:

        * **Der Inhalt der einzelnen Dateien** - mit denselben Merkmalen
          wie sonst auch.
        * **Die Namen der Eintraege.** Ein Eintrag wie ``../../config.php``
          schreibt beim Auspacken ausserhalb des Zielverzeichnisses. Das
          ist keine Schlamperei, sondern der Angriff selbst ("Zip-Slip").

        Gegen "Zip-Bomben" - kleine Archive, die sich zu Gigabytes
        entpacken - gelten harte Obergrenzen fuer Anzahl und Groesse. Es
        wird nie mehr gelesen, als dort steht.
        """
        import zipfile

        funde: List[FileFinding] = []
        try:
            with zipfile.ZipFile(path) as archiv:
                eintraege = archiv.infolist()[: self.config.max_archive_entries]
                gelesen = 0
                for eintrag in eintraege:
                    if _ist_ausbruch(eintrag.filename):
                        funde.append(FileFinding(
                            "archiv_ausbruch", 9,
                            f"Archiv-Eintrag schreibt ausserhalb des Ziels: "
                            f"{eintrag.filename[:80]}",
                        ))
                        continue
                    if eintrag.is_dir():
                        continue
                    uebrig = self.config.max_archive_bytes - gelesen
                    if uebrig <= 0:
                        log.info("Archiv %s nur teilweise geprueft (Obergrenze)",
                                 path)
                        break
                    menge = min(self.config.max_scan_bytes, uebrig)
                    try:
                        with archiv.open(eintrag) as handle:
                            daten = handle.read(menge)
                    except (OSError, ValueError, zipfile.BadZipFile,
                            RuntimeError) as exc:
                        log.debug("Archiv-Eintrag nicht lesbar: %s", exc)
                        continue
                    gelesen += len(daten)
                    innen = self.scan_bytes(daten, filename=eintrag.filename)
                    for fund in innen.findings:
                        funde.append(FileFinding(
                            fund.name, fund.severity,
                            f"im Archiv ({eintrag.filename[:60]}): "
                            f"{fund.description}",
                        ))
        except (zipfile.BadZipFile, OSError) as exc:
            log.debug("Archiv %s nicht lesbar: %s", path, exc)
        return funde

    def scan_dir(self, path: str, *, recursive: bool = True,
                 limit: int = 20000) -> List[ScanResult]:
        """Prueft ein Verzeichnis und liefert nur die Auffaelligkeiten."""
        treffer: List[ScanResult] = []
        gezaehlt = 0
        for wurzel, verzeichnisse, dateien in os.walk(path):
            verzeichnisse[:] = [
                d for d in verzeichnisse
                if d not in self.config.skip_dirs and not d.startswith(".")
            ]
            for datei in dateien:
                gezaehlt += 1
                if gezaehlt > limit:
                    log.warning("Pruefung nach %s Dateien abgebrochen", limit)
                    return treffer
                ergebnis = self.scan_file(os.path.join(wurzel, datei))
                if not ergebnis.clean:
                    treffer.append(ergebnis)
            if not recursive:
                break
        return treffer

    def is_malicious(self, result: ScanResult) -> bool:
        return result.score >= self.config.block_score


# ----------------------------------------------------------------------
# Quarantaene
# ----------------------------------------------------------------------
#: Eine Quarantaene-Kennung ist immer der Anfang eines SHA-256-Wertes.
_GUELTIGE_KENNUNG = re.compile(r"^[0-9a-f]{8,64}$")


class Quarantine:
    """Verschiebt verdaechtige Dateien beiseite - und loescht sie nie.

    Nach einem Einbruch sind solche Dateien Beweismittel. Und ein Fehlalarm
    darf keine Daten vernichten: alles laesst sich zurueckholen.
    """

    def __init__(self, directory: str = "quarantine") -> None:
        self.directory = directory

    def _ensure(self) -> None:
        os.makedirs(self.directory, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:  # pragma: no cover - plattformabhaengig
            pass

    def store(self, path: str, result: Optional[ScanResult] = None,
              now: Optional[float] = None) -> Optional[str]:
        """Verschiebt eine Datei in die Quarantaene. Gibt das Ziel zurueck."""
        if not os.path.isfile(path):
            return None
        self._ensure()
        now = time.time() if now is None else now

        kennung = hashlib.sha256(
            f"{path}{now}".encode("utf-8")
        ).hexdigest()[:16]
        ziel = os.path.join(self.directory, kennung)

        try:
            shutil.move(path, ziel)
            os.chmod(ziel, 0o600)   # nicht mehr ausfuehrbar, nicht lesbar
        except OSError as exc:
            log.error("Quarantaene fehlgeschlagen fuer %s: %s",
                      sauber(path, 200), exc)
            return None

        beleg = {
            "original": os.path.abspath(path),
            "quarantined_ts": now,
            "result": result.as_dict() if result else {},
        }
        with open(ziel + ".json", "w", encoding="utf-8") as handle:
            json.dump(beleg, handle, indent=2, ensure_ascii=False)
        try:
            os.chmod(ziel + ".json", 0o600)
        except OSError:  # pragma: no cover - plattformabhaengig
            pass
        log.warning("In Quarantaene verschoben: %s -> %s",
                    sauber(path, 200), ziel)
        return ziel

    def list(self) -> List[dict]:
        if not os.path.isdir(self.directory):
            return []
        eintraege = []
        for name in sorted(os.listdir(self.directory)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.directory, name),
                          encoding="utf-8") as handle:
                    daten = json.load(handle)
            except (OSError, ValueError):
                continue
            daten["id"] = name[:-5]
            eintraege.append(daten)
        return eintraege

    def restore(self, kennung: str, ziel: Optional[str] = None) -> Optional[str]:
        """Holt eine Datei zurueck - fuer den Fall eines Fehlalarms.

        Die Kennung kommt von der Kommandozeile, also von aussen. Sie wird
        deshalb geprueft, bevor sie an einen Pfad angehaengt wird: eine
        Kennung wie ``../../etc/shadow`` wuerde sonst eine beliebige Datei
        des Servers verschieben.
        """
        if not _GUELTIGE_KENNUNG.match(kennung or ""):
            log.warning("Ungueltige Quarantaene-Kennung abgewiesen: %r",
                        (kennung or "")[:40])
            return None
        quelle = os.path.join(self.directory, kennung)
        beleg_pfad = quelle + ".json"
        if not os.path.isfile(quelle) or not os.path.isfile(beleg_pfad):
            return None
        with open(beleg_pfad, encoding="utf-8") as handle:
            beleg = json.load(handle)
        zielpfad = ziel or beleg.get("original")
        if not zielpfad:
            return None
        os.makedirs(os.path.dirname(zielpfad) or ".", exist_ok=True)
        shutil.move(quelle, zielpfad)
        os.remove(beleg_pfad)
        log.info("Aus der Quarantaene zurueckgeholt: %s", zielpfad)
        return zielpfad


# ----------------------------------------------------------------------
# Heuristiken
#
# Sie treffen keine Aussage fuer sich allein - deshalb sind die Gewichte
# niedrig gehalten. Verschleierung ist kein Beweis: auch ordentlicher Code
# enthaelt manchmal eine lange Zeichenkette. Erst zusammen mit einem der
# Merkmale oben ergibt sich ein Urteil, das eine Datei beiseitelegt.
# ----------------------------------------------------------------------
#: Grenze fuer die Zahl der Teile einer Formularsendung, die angesehen
#: werden. Mehr als das ist kein Formular mehr, sondern ein Versuch, die
#: Pruefung mit Arbeit zuzuschuetten.
MAX_TEILE = 32

_DATEINAME = re.compile(rb'filename\*?=\s*"?([^"\r\n;]{1,255})', re.IGNORECASE)


def multipart_teile(body: bytes, content_type: str,
                    max_teile: int = MAX_TEILE) -> Tuple[bytes, List[Tuple[str, bytes]]]:
    """Zerlegt eine Formularsendung in Textfelder und hochgeladene Dateien.

    Die Trennung ist wichtig, weil beide unterschiedlich geprueft werden:

    * **Textfelder** gehen an die Anfrage-Firewall - dort steckt eine
      SQL-Injection drin, wenn eine drinsteckt.
    * **Dateien** gehen an die Dateipruefung.

    Wuerde man den ganzen Koerper an die Anfrage-Firewall geben, waere jedes
    hochgeladene Bild ein Treffer: Ein JPEG enthaelt Nullbytes und zufaellig
    auch Zeichenfolgen wie ``--``, und genau darauf achten diese Regeln.
    Ein Kunde, der sein Profilbild hochlaedt, waere gesperrt.

    Bewusst klein gehalten: Es wird nichts dekodiert und nichts gespeichert,
    der Koerper wird unveraendert weitergereicht. Ein unvollstaendiger
    Koerper (die Middleware liest nur den Anfang) ist kein Fehlerfall -
    was da ist, wird geprueft, der Rest fehlt eben.
    """
    if "multipart/form-data" not in (content_type or "").lower():
        return body, []
    treffer = re.search(r'boundary=\s*"?([^";,\s]+)', content_type or "",
                        re.IGNORECASE)
    if not treffer:
        return body, []

    grenze = b"--" + treffer.group(1).encode("latin-1", "replace")
    felder: List[bytes] = []
    dateien: List[Tuple[str, bytes]] = []
    for abschnitt in body.split(grenze)[1:]:
        if len(dateien) + len(felder) >= max_teile:
            break
        trenner = abschnitt.find(b"\r\n\r\n")
        if trenner == -1:
            continue
        kopf, inhalt = abschnitt[:trenner], abschnitt[trenner + 4:]
        inhalt = inhalt.rstrip(b"\r\n-")
        name = _DATEINAME.search(kopf)
        if name:
            dateien.append((name.group(1).decode("utf-8", "replace"), inhalt))
        else:
            felder.append(inhalt)
    return b"\n".join(felder), dateien


def upload_teile(body: bytes, content_type: str,
                 max_teile: int = MAX_TEILE) -> List[Tuple[str, bytes]]:
    """Nur die hochgeladenen Dateien einer Formularsendung."""
    return multipart_teile(body, content_type, max_teile)[1]


def _ist_ausbruch(name: str) -> bool:
    """Schreibt dieser Archiv-Eintrag beim Auspacken woandershin?

    Absolute Pfade und ".." fuehren aus dem Zielverzeichnis heraus - damit
    laesst sich beim Entpacken jede Datei auf dem Server ueberschreiben.
    """
    if not name:
        return False
    geglaettet = name.replace("\\", "/")
    if geglaettet.startswith("/") or re.match(r"^[A-Za-z]:", geglaettet):
        return True
    return any(teil == ".." for teil in geglaettet.split("/"))


#: Eine *Kette* aus mindestens vier kurzen Bruchstuecken:
#: ``'e'.'v'.'a'.'l'``. Nicht einzelne Verbindungen zaehlen, sondern die
#: Kette - das ist der Unterschied zwischen Verschleierung und normalem
#: Code.
#:
#: Zwei Fehlversuche stecken in diesem Muster. Erst passte ``'.'`` selbst
#: darauf, also ein Punkt *innerhalb* einer Zeichenkette - der kommt in
#: gewoehnlichem Code staendig vor (``pfad.split('.')``). Dann zaehlte es
#: einzelne Verbindungen, und Perl-Programme wie gitweb.cgi kamen auf 135,
#: weil ``.`` dort wie in PHP der Verkettungsoperator ist. Gegen echte
#: Dateien gemessen meldet die Kettenform davon nichts mehr.
_ZERLEGT = re.compile(
    rb"['\"][^'\"\n]{0,6}['\"](\s*\.\s*['\"][^'\"\n]{0,6}['\"]){3,}"
)
_BASE64_BLOCK = re.compile(rb"[A-Za-z0-9+/]{256,}={0,2}")


def _heuristik_zerlegte_texte(probe: bytes) -> Optional[FileFinding]:
    """Ein Wort, aus einzelnen Zeichen zusammengesetzt: 'e'.'v'.'a'.'l'."""
    treffer = len(_ZERLEGT.findall(probe))
    if treffer:
        return FileFinding(
            "zerlegte_texte", 5,
            f"{treffer} aus Einzelteilen zusammengesetzte Zeichenkette(n) - "
            f"typische Verschleierung",
        )
    return None


def _heuristik_base64_block(probe: bytes) -> Optional[FileFinding]:
    """Ein langer base64-Block in einer Programmdatei."""
    for treffer in _BASE64_BLOCK.finditer(probe):
        vorher = probe[max(0, treffer.start() - 24):treffer.start()]
        if b"base64," in vorher:      # eingebettetes Bild (data:-Adresse)
            continue
        return FileFinding(
            "base64_block", 4,
            f"{treffer.end() - treffer.start()} Zeichen langer base64-Block "
            f"in einer Programmdatei",
        )
    return None


def _run_command(argv: Sequence[str], timeout: float = 30.0) -> Tuple[int, str, str]:
    try:
        fertig = subprocess.run(  # noqa: S603 - feste Argumentliste, keine Shell
            list(argv), capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 2, "", str(exc)
    return (
        fertig.returncode,
        fertig.stdout.decode("utf-8", "replace"),
        fertig.stderr.decode("utf-8", "replace"),
    )
