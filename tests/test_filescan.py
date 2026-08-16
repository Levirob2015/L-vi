"""Dateipruefung und Quarantaene.

Die Merkmale in den Testdaten sind bewusst Fragmente - sie loesen die
Erkennung aus, ergeben aber kein lauffaehiges Schadprogramm.

Genauso wichtig wie die Erkennung: gewoehnliche Dateien einer Website
duerfen nicht gemeldet werden. Ein Fehlalarm, der eine echte Datei in
Quarantaene schiebt, legt die Seite lahm.
"""

import os

import pytest

from loginshield import Guard
from loginshield.config import Config, ConfigError, MalwareConfig
from loginshield.filescan import EICAR, FileScanner, Quarantine

#: Merkmale, die erkannt werden muessen (Fragmente, nicht lauffaehig).
VERDAECHTIG = [
    ("eval_eingabe", b"<?php eval($_POST['x']); ?>"),
    ("system_eingabe", b"<?php system($_GET['cmd']); ?>"),
    ("eval_base64", b"<?php eval(base64_decode($data)); ?>"),
    ("assert_eingabe", b"<?php assert($_REQUEST['a']); ?>"),
    ("preg_e_modifikator", b"<?php preg_replace('/x/e', $c, $s); ?>"),
    ("bekannte_shell", b"<?php # c99shell v1 ?>"),
    ("python_exec_eingabe", b"os.system(request.args['c'])"),
    ("jsp_runtime", b'Runtime.getRuntime().exec(request.getParameter("c"))'),
]

#: Gewoehnliche Dateien einer Website - hier darf nichts anschlagen.
HARMLOS = [
    ("index.php", b"<?php\n$titel = 'Willkommen';\necho htmlspecialchars($titel);\n"),
    ("funktionen.php", b"<?php\nfunction summe($a, $b) { return $a + $b; }\n"),
    ("stil.css", b"body { font-family: sans-serif; color: #333; }"),
    ("app.js", b"document.addEventListener('click', function () { console.log(1); });"),
    ("logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 300),
    ("daten.json", b'{"name": "Anna", "rolle": "admin"}'),
    ("liste.csv", b"name;menge\nRegal;2\nStuhl;4\n"),
    ("hinweis.txt", "Bitte nicht loeschen - System-Datei.".encode("utf-8")),
    ("upload.php", b"<?php\nmove_uploaded_file($tmp, $ziel);\n"),
]


@pytest.fixture
def scanner():
    return FileScanner(MalwareConfig())


# -- Erkennung -----------------------------------------------------------
@pytest.mark.parametrize("name,inhalt", VERDAECHTIG)
def test_webshell_merkmale_werden_erkannt(scanner, name, inhalt):
    result = scanner.scan_bytes(inhalt, filename="datei.php")
    assert result.findings, f"{name} nicht erkannt"
    assert name in {f.name for f in result.findings}


def test_eicar_testdatei(scanner):
    """Die Standard-Testdatei der Branche - prueft, ob die Kette laeuft."""
    result = scanner.scan_bytes(EICAR, filename="test.txt")
    assert result.verdict == "schadhaft"
    assert "eicar" in {f.name for f in result.findings}


@pytest.mark.parametrize("name,inhalt", HARMLOS)
def test_gewoehnliche_dateien_bleiben_unbehelligt(scanner, name, inhalt):
    result = scanner.scan_bytes(inhalt, filename=name)
    assert not scanner.is_malicious(result), (
        f"Fehlalarm bei {name}: {result.summary}"
    )


def test_getarnte_bilddatei(scanner):
    result = scanner.scan_bytes(b"<?php system($_GET['c']); ?>", filename="foto.jpg")
    assert result.verdict == "schadhaft"
    namen = {f.name for f in result.findings}
    assert "inhalt_passt_nicht" in namen or "php_im_bild" in namen


def test_echtes_bild_bleibt_sauber(scanner):
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 500
    assert scanner.scan_bytes(jpeg, filename="foto.jpg").clean


def test_doppelte_endung(scanner):
    result = scanner.scan_bytes(b"<?php echo 1; ?>", filename="rechnung.pdf.php")
    assert "doppelte_endung" in {f.name for f in result.findings}


def test_ausfuehrbare_datei_als_pdf(scanner):
    result = scanner.scan_bytes(b"MZ\x90\x00" + b"\x00" * 100, filename="handbuch.pdf")
    assert "inhalt_passt_nicht" in {f.name for f in result.findings}


# -- Verschleierung: derselbe Angriff, nur umgeschrieben ----------------
#: Alle drei Zeilen tun dasselbe wie ``eval($_POST['x'])`` - nur nicht
#: woertlich. Genau so werden Webshells heute geschrieben.
VERSCHLEIERT = [
    ("dynamische_funktion_eingabe", b"<?php $f = 'ev'.'al'; $f($_POST['x']); ?>"),
    ("call_user_func_eingabe", b"<?php call_user_func('system', $_GET['c']); ?>"),
    ("zerlegte_superglobale", b"<?php $a = ${'_PO'.'ST'}; ?>"),
    ("include_eingabe", b"<?php include($_GET['datei']); ?>"),
    ("remote_ausfuehrung", b"<?php $d = file_get_contents($_GET['url']); ?>"),
    ("chr_kette", b"<?php $s = chr(101).chr(118).chr(97); ?>"),
    ("shell_passwortabfrage",
     b"<?php if (md5($_POST['pw']) === $hash) { } ?>"),
]


@pytest.mark.parametrize("name,inhalt", VERSCHLEIERT)
def test_verschleierte_webshells(scanner, name, inhalt):
    result = scanner.scan_bytes(inhalt, filename="x.php")
    assert name in {f.name for f in result.findings}, result.summary


def test_zerlegte_texte_sind_nur_ein_hinweis(scanner):
    """Verschleierung allein ist kein Beweis - sie darf nichts wegsperren."""
    bruchstuecke = b"<?php $s = 'e'.'v'.'a'.'l'; ?>"
    result = scanner.scan_bytes(bruchstuecke, filename="x.php")
    assert "zerlegte_texte" in {f.name for f in result.findings}
    assert not scanner.is_malicious(result)


def test_zerlegte_texte_nur_in_programmdateien(scanner):
    text = b"Der Code lautet 'e'.'v'.'a'.'l' - siehe Anhang."
    assert "zerlegte_texte" not in {
        f.name for f in scanner.scan_bytes(text, filename="notiz.txt").findings
    }


def test_base64_block_in_programmdatei(scanner):
    result = scanner.scan_bytes(b"<?php $x = '" + b"QUJD" * 80 + b"'; ?>",
                                filename="x.php")
    assert "base64_block" in {f.name for f in result.findings}


def test_eingebettetes_bild_ist_kein_fund(scanner):
    """data:-Adressen enthalten voellig regulaer lange base64-Bloecke."""
    css = b"body { background: url(data:image/png;base64," + b"QUJD" * 90 + b"); }"
    assert scanner.scan_bytes(css, filename="stil.css").clean


def test_umbenannte_programmdatei_wird_trotzdem_streng_geprueft(scanner):
    """Die Endung sagt .txt, der Inhalt ist PHP - dann zaehlt der Inhalt."""
    inhalt = b"<?php $s = chr(101).chr(118); ?>"
    assert "chr_kette" in {
        f.name for f in scanner.scan_bytes(inhalt, filename="notiz.txt").findings
    }


# -- .htaccess -----------------------------------------------------------
def test_htaccess_macht_uploads_ausfuehrbar(scanner):
    """Der Standardtrick: Bilder im Upload-Ordner als PHP ausfuehren lassen."""
    result = scanner.scan_bytes(b"AddType application/x-httpd-php .jpg\n",
                                filename="/var/www/uploads/.htaccess")
    assert "htaccess_php_freigabe" in {f.name for f in result.findings}


def test_dieselbe_zeile_in_einer_textdatei_ist_harmlos(scanner):
    """In einer Anleitung ist genau diese Zeile nur Text."""
    result = scanner.scan_bytes(b"AddType application/x-httpd-php .jpg\n",
                                filename="anleitung.txt")
    assert "htaccess_php_freigabe" not in {f.name for f in result.findings}


# -- Archive -------------------------------------------------------------
def _zip(tmp_path, eintraege, name="paket.zip"):
    """Baut ein Archiv - komprimiert, damit der Inhalt wirklich verpackt ist.

    Unkomprimiert stuende der Schadcode woertlich in der Archivdatei und
    wuerde schon beim gewoehnlichen Durchsehen auffallen. Die Pruefung des
    Archivinhalts waere dann gar nicht getestet.
    """
    import zipfile

    pfad = tmp_path / name
    with zipfile.ZipFile(pfad, "w", zipfile.ZIP_DEFLATED) as archiv:
        for eintrag, inhalt in eintraege:
            archiv.writestr(eintrag, inhalt)
    return str(pfad)


def test_webshell_im_archiv(scanner, tmp_path):
    """Ohne Blick ins Archiv faellt sie erst nach dem Auspacken auf."""
    pfad = _zip(tmp_path, [("bilder/logo.png", b"\x89PNG\r\n\x1a\n"),
                           ("shell.php", b"<?php eval($_POST['x']); ?>")])
    result = scanner.scan_file(pfad)
    assert result.verdict == "schadhaft"
    assert "shell.php" in result.summary


def test_archiv_ausbruch(scanner, tmp_path):
    """Ein Eintrag mit '..' ueberschreibt beim Auspacken fremde Dateien."""
    pfad = _zip(tmp_path, [("../../../etc/cron.d/x", b"* * * * * root sh\n")])
    assert "archiv_ausbruch" in {f.name for f in scanner.scan_file(pfad).findings}


def test_gewoehnliches_archiv_bleibt_sauber(scanner, tmp_path):
    pfad = _zip(tmp_path, [("lesen.txt", b"Hallo"),
                           ("bild.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)])
    assert scanner.scan_file(pfad).clean


def test_word_dokument_ist_kein_fund(scanner, tmp_path):
    """Ein .docx *ist* ein ZIP-Archiv - das ist kein Widerspruch."""
    pfad = _zip(tmp_path, [("word/document.xml", b"<w:document/>"),
                           ("[Content_Types].xml", b"<Types/>")],
                name="brief.docx")
    result = scanner.scan_file(pfad)
    assert "inhalt_passt_nicht" not in {f.name for f in result.findings}
    assert result.clean


def test_archiv_obergrenze(tmp_path):
    """Gegen Zip-Bomben: es wird nie mehr gelesen als erlaubt."""
    scanner = FileScanner(MalwareConfig(max_archive_bytes=2048))
    pfad = _zip(tmp_path, [(f"datei{i}.txt", b"x" * 4096) for i in range(20)])
    assert scanner.scan_file(pfad).clean          # bricht ab, statt zu lesen


def test_archivpruefung_abschaltbar(tmp_path):
    scanner = FileScanner(MalwareConfig(inspect_archives=False))
    pfad = _zip(tmp_path, [("shell.php", b"<?php eval($_POST['x']); ?>")])
    assert scanner.scan_file(pfad).clean


def test_kaputtes_archiv_stuerzt_nicht_ab(scanner, tmp_path):
    pfad = tmp_path / "kaputt.zip"
    pfad.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    assert scanner.scan_file(str(pfad)).verdict in ("sauber", "ungeprueft")


def test_regeln_abschaltbar():
    scanner = FileScanner(MalwareConfig(disabled_rules=["system_eingabe"]))
    result = scanner.scan_bytes(b"<?php system($_GET['c']); ?>", filename="x.php")
    assert "system_eingabe" not in {f.name for f in result.findings}


def test_abschaltbar():
    scanner = FileScanner(MalwareConfig(enabled=False))
    assert scanner.scan_bytes(EICAR, filename="x.txt").clean


# -- Dateien auf der Platte ---------------------------------------------
def test_datei_pruefen(scanner, tmp_path):
    pfad = tmp_path / "shell.php"
    pfad.write_bytes(b"<?php eval($_POST['x']); ?>")
    result = scanner.scan_file(str(pfad))
    assert result.verdict == "schadhaft"
    assert result.sha256
    assert result.size > 0


def test_zu_grosse_datei_wird_uebersprungen(tmp_path):
    scanner = FileScanner(MalwareConfig(max_file_bytes=100))
    pfad = tmp_path / "gross.bin"
    pfad.write_bytes(b"x" * 5000)
    result = scanner.scan_file(str(pfad))
    assert "uebersprungen" in result.error
    assert result.verdict == "ungeprueft"


def test_nicht_lesbare_datei(scanner, tmp_path):
    result = scanner.scan_file(str(tmp_path / "gibtsnicht.php"))
    assert result.error
    assert result.verdict == "ungeprueft"


def test_verzeichnis_pruefen(scanner, tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "index.php").write_bytes(b"<?php echo 'hallo'; ?>")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    (tmp_path / "uploads" / "shell.php").write_bytes(b"<?php system($_GET['c']); ?>")

    treffer = scanner.scan_dir(str(tmp_path))
    assert len(treffer) == 1
    assert treffer[0].path.endswith("shell.php")


def test_uebersprungene_verzeichnisse(scanner, tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.php").write_bytes(b"<?php eval($_GET['c']); ?>")
    assert scanner.scan_dir(str(tmp_path)) == []


# -- ClamAV --------------------------------------------------------------
def test_clamav_wird_benutzt_wenn_vorhanden(monkeypatch, tmp_path):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which",
                        lambda name: "/usr/bin/clamdscan" if name == "clamdscan" else None)

    def fake_run(argv, timeout=30):
        return 1, f"{argv[-1]}: Win.Trojan.Beispiel FOUND\n", ""

    scanner = FileScanner(MalwareConfig(), run=fake_run)
    pfad = tmp_path / "harmlos.txt"
    pfad.write_bytes(b"nichts besonderes")

    result = scanner.scan_file(str(pfad))
    assert "clamav" in {f.name for f in result.findings}
    assert "Win.Trojan.Beispiel" in result.summary


def test_ohne_clamav_wird_trotzdem_geprueft(monkeypatch, scanner, tmp_path):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which", lambda name: None)
    pfad = tmp_path / "shell.php"
    pfad.write_bytes(b"<?php eval($_POST['x']); ?>")
    assert scanner.scan_file(str(pfad)).verdict == "schadhaft"


def test_clamav_abschaltbar(monkeypatch):
    import shutil as shutil_module

    monkeypatch.setattr(shutil_module, "which", lambda name: "/usr/bin/clamdscan")
    scanner = FileScanner(MalwareConfig(clamav="off"))
    assert scanner.clamav_binary() is None


# -- Quarantaene ---------------------------------------------------------
def test_quarantaene_verschiebt_statt_zu_loeschen(tmp_path):
    quelle = tmp_path / "shell.php"
    quelle.write_bytes(b"<?php eval($_POST['x']); ?>")
    quarantine = Quarantine(str(tmp_path / "q"))

    ziel = quarantine.store(str(quelle))
    assert ziel and os.path.isfile(ziel)
    assert not quelle.exists()
    # Nicht mehr ausfuehrbar und nur fuer den Eigentuemer lesbar.
    assert oct(os.stat(ziel).st_mode)[-3:] == "600"


def test_quarantaene_haelt_den_ursprung_fest(tmp_path, scanner):
    quelle = tmp_path / "shell.php"
    quelle.write_bytes(b"<?php system($_GET['c']); ?>")
    quarantine = Quarantine(str(tmp_path / "q"))
    quarantine.store(str(quelle), scanner.scan_file(str(quelle)))

    eintraege = quarantine.list()
    assert len(eintraege) == 1
    assert eintraege[0]["original"].endswith("shell.php")
    assert eintraege[0]["result"]["verdict"] == "schadhaft"


def test_zurueckholen_nach_fehlalarm(tmp_path):
    quelle = tmp_path / "wichtig.php"
    quelle.write_bytes(b"<?php # eigentlich harmlos ?>")
    quarantine = Quarantine(str(tmp_path / "q"))
    quarantine.store(str(quelle))
    assert not quelle.exists()

    kennung = quarantine.list()[0]["id"]
    zurueck = quarantine.restore(kennung)
    assert zurueck and os.path.isfile(zurueck)
    assert quelle.read_bytes() == b"<?php # eigentlich harmlos ?>"
    assert quarantine.list() == []


def test_zurueckholen_an_anderen_ort(tmp_path):
    quelle = tmp_path / "datei.php"
    quelle.write_bytes(b"inhalt")
    quarantine = Quarantine(str(tmp_path / "q"))
    quarantine.store(str(quelle))

    ziel = str(tmp_path / "woanders" / "datei.php")
    assert quarantine.restore(quarantine.list()[0]["id"], ziel) == ziel
    assert os.path.isfile(ziel)


def test_unbekannte_kennung(tmp_path):
    assert Quarantine(str(tmp_path / "q")).restore("gibtsnicht") is None


@pytest.mark.parametrize("kennung", [
    "../../etc/shadow", "/etc/shadow", "..", "", "a" * 200, "ab",
])
def test_kennung_darf_nicht_aus_dem_verzeichnis_fuehren(tmp_path, kennung):
    """Die Kennung kommt von der Kommandozeile, also von aussen.

    Ohne Pruefung wuerde 'restore ../../etc/shadow' eine beliebige Datei
    des Servers verschieben.
    """
    opfer = tmp_path / "wichtig"
    opfer.write_text("nicht anfassen")
    assert Quarantine(str(tmp_path / "q")).restore(kennung) is None
    assert opfer.read_text() == "nicht anfassen"


def test_beleg_ist_nur_fuer_den_eigentuemer_lesbar(tmp_path):
    """Im Beleg steht, wo die Datei herkam - das geht sonst niemanden an."""
    quelle = tmp_path / "shell.php"
    quelle.write_bytes(b"<?php eval($_POST['x']); ?>")
    quarantine = Quarantine(str(tmp_path / "q"))
    ziel = quarantine.store(str(quelle))
    assert oct(os.stat(ziel + ".json").st_mode)[-3:] == "600"


# -- Zusammenspiel mit der Sperre ---------------------------------------
def test_schadhafter_upload_sperrt_den_absender(config, store, clock):
    """Erkennen allein reicht nicht - wer eine Webshell ablegt, fliegt raus."""
    guard = Guard(config, store, clock=clock)
    result = guard.scan_upload(b"<?php eval($_POST['x']); ?>",
                               filename="foto.php", ip="192.0.2.55")

    assert result.verdict == "schadhaft"
    assert not guard.check(ip="192.0.2.55").allowed


def test_harmloser_upload_bleibt_folgenlos(config, store, clock):
    guard = Guard(config, store, clock=clock)
    result = guard.scan_upload(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200,
                               filename="logo.png", ip="192.0.2.56")
    assert result.clean
    assert guard.check(ip="192.0.2.56").allowed


def test_leichter_fund_sperrt_nicht_sofort(config, store, clock):
    """Unterhalb der Schwelle wird nur vermerkt - Fehlalarme sperren nicht."""
    guard = Guard(config, store, clock=clock)
    guard.scan_upload(b"<?php $s = 'e'.'v'.'a'.'l'; ?>",
                      filename="x.php", ip="192.0.2.57")
    assert guard.check(ip="192.0.2.57").allowed
    assert store.recent_attempts(limit=10)


def test_eigene_adresse_wird_nie_gesperrt(config, store, clock):
    config.allowlist = ["192.0.2.58"]
    guard = Guard(config, store, clock=clock)
    guard.scan_upload(EICAR, filename="test.txt", ip="192.0.2.58")
    assert guard.check(ip="192.0.2.58").allowed


def test_pruefen_und_beiseitelegen(config, store, clock, tmp_path):
    config.malware.action = "quarantine"
    config.malware.quarantine_dir = str(tmp_path / "q")
    guard = Guard(config, store, clock=clock)

    datei = tmp_path / "webroot" / "shell.php"
    datei.parent.mkdir()
    datei.write_bytes(b"<?php eval($_POST['x']); ?>")

    ergebnis = guard.scan_and_quarantine(str(datei))
    assert ergebnis["quarantined"]
    assert not datei.exists()
    assert guard.quarantine.list()[0]["original"] == str(datei)


def test_ohne_quarantaene_wird_nur_gemeldet(config, store, clock, tmp_path):
    """Voreinstellung: melden. Nichts wird ohne Ansage verschoben."""
    config.malware.quarantine_dir = str(tmp_path / "q")
    guard = Guard(config, store, clock=clock)
    datei = tmp_path / "shell.php"
    datei.write_bytes(b"<?php eval($_POST['x']); ?>")

    ergebnis = guard.scan_and_quarantine(str(datei))
    assert ergebnis["quarantined"] is None
    assert datei.exists()
    assert ergebnis["result"].verdict == "schadhaft"


def test_leere_quarantaene(tmp_path):
    assert Quarantine(str(tmp_path / "leer")).list() == []


# -- Konfiguration -------------------------------------------------------
def test_ungueltige_konfiguration():
    with pytest.raises(ConfigError):
        Config.from_dict({"malware": {"action": "quatsch"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"malware": {"clamav": "vielleicht"}})
    with pytest.raises(ConfigError):
        Config.from_dict({"malware": {"block_score": 0}})


def test_guard_stellt_die_pruefung_bereit(config, store, clock):
    guard = Guard(config, store, clock=clock)
    assert guard.filescan.enabled
    assert guard.quarantine is not None


# -- Uploads in der Middleware ------------------------------------------
# Die Pruefung greift, ohne dass die Anwendung etwas dafuer tun muss: Die
# Datei erreicht sie gar nicht erst.
GRENZE = "----------------formular42"


def _multipart(dateiname, inhalt, feldname="datei"):
    teile = [
        f"--{GRENZE}\r\n".encode(),
        f'Content-Disposition: form-data; name="titel"\r\n\r\n'.encode(),
        b"Mein Urlaubsbild\r\n",
        f"--{GRENZE}\r\n".encode(),
        (f'Content-Disposition: form-data; name="{feldname}"; '
         f'filename="{dateiname}"\r\n').encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        inhalt, b"\r\n",
        f"--{GRENZE}--\r\n".encode(),
    ]
    return b"".join(teile)


def _asgi_upload(guard, koerper, ip="198.51.100.5"):
    import asyncio

    from loginshield.middleware import ShieldMiddleware
    from tests.test_middleware import make_app

    app = ShieldMiddleware(make_app(200), guard)
    scope = {
        "type": "http", "path": "/upload", "method": "POST",
        "client": (ip, 5000), "query_string": b"",
        "headers": [
            (b"user-agent", b"Mozilla/5.0"),
            (b"content-type",
             f"multipart/form-data; boundary={GRENZE}".encode()),
        ],
    }
    nachrichten = []

    async def receive():
        return {"type": "http.request", "body": koerper, "more_body": False}

    async def send(nachricht):
        nachrichten.append(nachricht)

    asyncio.run(app(scope, receive, send))
    return next(n["status"] for n in nachrichten
                if n["type"] == "http.response.start")


def test_webshell_erreicht_die_anwendung_nicht(config, store, clock):
    guard = Guard(config, store, clock=clock)
    koerper = _multipart("foto.php", b"<?php eval($_POST['x']); ?>")
    assert _asgi_upload(guard, koerper) == 403
    assert not guard.check("198.51.100.5").allowed


def test_echtes_bild_geht_durch(config, store, clock):
    guard = Guard(config, store, clock=clock)
    koerper = _multipart("foto.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 400)
    assert _asgi_upload(guard, koerper) == 200
    assert guard.check("198.51.100.5").allowed


def test_getarntes_bild_wird_gestoppt(config, store, clock):
    """.jpg im Namen, PHP im Inhalt - der Standardweg an Uploads vorbei."""
    guard = Guard(config, store, clock=clock)
    koerper = _multipart("urlaub.jpg", b"<?php system($_GET['c']); ?>")
    assert _asgi_upload(guard, koerper) == 403


def test_gewoehnliches_formular_bleibt_unberuehrt(config, store, clock):
    """Ohne Datei gibt es nichts zu pruefen."""
    guard = Guard(config, store, clock=clock)
    koerper = (f"--{GRENZE}\r\n".encode()
               + b'Content-Disposition: form-data; name="text"\r\n\r\n'
               + b"Bitte um Rueckruf\r\n"
               + f"--{GRENZE}--\r\n".encode())
    assert _asgi_upload(guard, koerper) == 200


def test_uploadpruefung_abschaltbar(config, store, clock):
    config.malware.scan_uploads = False
    guard = Guard(config, store, clock=clock)
    koerper = _multipart("foto.php", b"<?php eval($_POST['x']); ?>")
    assert _asgi_upload(guard, koerper) == 200


def test_wsgi_stoppt_den_upload(config, store, clock):
    import io
    import json as json_modul

    from loginshield.middleware import WSGIShield

    guard = Guard(config, store, clock=clock)
    koerper = _multipart("shell.php", b"<?php eval($_POST['x']); ?>")

    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"gespeichert"]

    gesehen = []
    antwort = WSGIShield(app, guard)({
        "PATH_INFO": "/upload", "REQUEST_METHOD": "POST",
        "REMOTE_ADDR": "198.51.100.6", "HTTP_USER_AGENT": "Mozilla/5.0",
        "CONTENT_TYPE": f"multipart/form-data; boundary={GRENZE}",
        "CONTENT_LENGTH": str(len(koerper)),
        "wsgi.input": io.BytesIO(koerper),
    }, lambda status, headers, exc_info=None: gesehen.append(status))

    assert gesehen[-1].startswith("403")
    assert json_modul.loads(b"".join(antwort))["reason"] == "malicious_upload"


def test_die_anwendung_bekommt_den_koerper_unveraendert(config, store, clock):
    """Gepuffert wird nur zum Pruefen - weitergereicht wird das Original."""
    import asyncio

    from loginshield.middleware import ShieldMiddleware

    guard = Guard(config, store, clock=clock)
    koerper = _multipart("logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    empfangen = {}

    async def app(scope, receive, send):
        nachricht = await receive()
        empfangen["body"] = nachricht["body"]
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})

    scope = {
        "type": "http", "path": "/upload", "method": "POST",
        "client": ("198.51.100.8", 5000), "query_string": b"",
        "headers": [(b"content-type",
                     f"multipart/form-data; boundary={GRENZE}".encode())],
    }

    async def receive():
        return {"type": "http.request", "body": koerper, "more_body": False}

    asyncio.run(ShieldMiddleware(app, guard)(scope, receive,
                                             lambda nachricht: _nichts()))
    assert empfangen["body"] == koerper


async def _nichts():
    return None


# -- Formularsendungen zerlegen -----------------------------------------
def test_teile_werden_erkannt():
    from loginshield.filescan import upload_teile

    koerper = _multipart("bild.png", b"INHALT")
    teile = upload_teile(koerper, f"multipart/form-data; boundary={GRENZE}")
    assert teile == [("bild.png", b"INHALT")]


def test_ohne_multipart_nichts_zu_holen():
    from loginshield.filescan import upload_teile

    assert upload_teile(b"a=1&b=2", "application/x-www-form-urlencoded") == []
    assert upload_teile(b"...", "multipart/form-data") == []      # ohne boundary


def test_abgeschnittener_koerper_ist_kein_fehler():
    """Die Middleware liest nur den Anfang - das darf nichts umwerfen."""
    from loginshield.filescan import upload_teile

    koerper = _multipart("gross.php", b"<?php eval($_POST['x']); ?>")[:120]
    upload_teile(koerper, f"multipart/form-data; boundary={GRENZE}")


def test_zu_viele_teile_werden_gedeckelt():
    from loginshield.filescan import upload_teile

    koerper = b"".join(
        _multipart(f"d{i}.txt", b"x") for i in range(60)
    )
    teile = upload_teile(koerper, f"multipart/form-data; boundary={GRENZE}")
    assert len(teile) <= 32


# -- Fehlalarme, die es wirklich gab ------------------------------------
# Diese drei Faelle stammen aus einem Durchlauf ueber echte Verzeichnisse
# dieses Rechners (/etc, /usr/lib/python3.11). Jeder war ein Fehlalarm,
# jeder ist hier festgehalten.
def test_tls_zertifikat_ist_keine_webshell(scanner):
    """base64 enthaelt zufaellig "WSO" - ein Zertifikat galt als Webshell.

    Mit Schwere 10 haette der Quarantaene-Betrieb die Zertifikatsablage
    des Servers beiseitegeraeumt.
    """
    zertifikat = (b"-----BEGIN CERTIFICATE-----\n"
                  b"MIIFaTCCA1GgAwIBAgIJAJK4iNuwisFjMA0GCSqGSIb3DQEBCwUAMEc\n"
                  b"01utI3\ngzhTODY7z2zp+WsO0PsE6E9312UBeIYMej4hYyz1sBiE\n"
                  b"-----END CERTIFICATE-----\n")
    assert scanner.scan_bytes(zertifikat, filename="ca-root.pem").clean


def test_echte_shell_kennung_wird_weiter_erkannt(scanner):
    for kennung in (b"<?php # WSO 2.5 ?>", b"<?php # c99shell ?>",
                    b"<?php # b374k ?>"):
        result = scanner.scan_bytes(kennung, filename="x.php")
        assert "bekannte_shell" in {f.name for f in result.findings}, kennung


def test_punkt_in_einer_zeichenkette_ist_keine_verschleierung(scanner):
    """pfad.split('.') - das Muster '.' kommt in normalem Code staendig vor."""
    code = b"<?php\n" + b"$teile = explode('.', $host);\n" * 30
    assert scanner.scan_bytes(code, filename="hilfe.php").clean


def test_verkettung_in_gewoehnlichem_code_zaehlt_nicht(scanner):
    """In Perl und PHP ist '.' der Verkettungsoperator - das ist Alltag.

    Gemessen an /usr/share/gitweb/gitweb.cgi (135 einzelne Verkettungen,
    aber keine einzige Kette aus Einzelzeichen).
    """
    code = b"<?php\n" + (b"$zeile = 'Name: ' . $name . ' (' . $rolle . ')';\n"
                         b"$pfad = $wurzel . '/' . $datei . '.html';\n") * 40
    assert scanner.scan_bytes(code, filename="vorlage.php").clean


def test_zeichensatztabelle_ist_keine_verschleierung(scanner):
    """Kurze \\x-Folgen stehen in ganz gewoehnlichen Bibliotheken."""
    code = b"<?php $tabelle = \"\\x00\\x01\\x02\\x03\\x04\\x05\"; ?>"
    assert "hex_verschleierung" not in {
        f.name for f in scanner.scan_bytes(code, filename="tab.php").findings
    }
