# Sendestudio

Podcasts, Radio und Dokumentationen im Browser aufnehmen und direkt ins Netz
stellen. Ein Programm, ein Befehl, keine fremden Pakete – nur Python 3.9+.
ffmpeg ist optional und macht die Aufnahmen podcast-tauglich.

![Studio bei der Aufnahme](docs/sendestudio.png)

## Was es kann

**Aufnehmen**
- Mikrofon, Kamera + Mikrofon oder Bildschirm + Mikrofon – direkt im Browser
- Pegelanzeige, Lautstärkeregler, Pause, Uhr
- **Jingle-Pads**: sechs Tasten für Jingles, Intros und Einspieler, die live in die Aufnahme gemischt werden
- **Kapitelmarken** per Knopfdruck während der Aufnahme
- Oder eine fertige Datei hochladen (MP3, M4A, MP4, WebM, Ogg, WAV)

**Verwalten**
- Sendungen in drei Arten: **Podcast**, **Radio**, **Dokumentation**
- Cover, Beschreibung, Shownotes, Kapitel bearbeiten
- Entwürfe, die niemand sieht, bis du sie veröffentlichst – auch die Datei nicht

**Ins Netz stellen**
- Öffentliche Seite mit Player, Kapiteln und Download – auch auf dem Handy
- **Podcast-Feed** (RSS mit iTunes- und Kapitel-Angaben) für Apple Podcasts, Spotify, AntennaPod & Co.
- **Radio rund um die Uhr**: Die Folgen einer Radio-Sendung laufen als Endlosprogramm nach der Uhrzeit. Wer einschaltet, hört dieselbe Stelle wie alle anderen – ohne Streaming-Server.
- Auf drei Wegen online: der Studio-Server selbst, als **statische Seite** für jeden Webspace (GitHub Pages, Netlify …) oder per **FTP/FTPS** direkt auf deinen Webspace

Mit ffmpeg werden Aufnahmen automatisch in MP3 (Ton) bzw. MP4 (Video)
umgewandelt, auf Wunsch auf Podcast-Lautstärke (−16 LUFS) angeglichen und
exakt vermessen. Ohne ffmpeg bleibt die Datei, wie sie ist.

## Schnellstart

```bash
git clone https://github.com/Levirob2015/L-vi.git
cd L-vi
pip install -e .                    # oder: export PYTHONPATH=$PWD

sendestudio init --titel "Mein Sender"
# -> zeigt das Studio-Passwort an, gut aufheben

sendestudio serve
# Studio:            http://127.0.0.1:8790/studio
# Öffentliche Seite: http://127.0.0.1:8790/
```

Im Studio:

1. **+ Neue Sendung** – Titel, Art (Podcast / Radio / Dokumentation), Beschreibung, danach ein Cover.
2. **● Neue Folge aufnehmen** – Quelle wählen, *Studio einschalten*, *Aufnahme*. Jingles laden und antippen, mit *⚑ Kapitelmarke* Abschnitte markieren, *■ Stopp*.
3. Anhören, Titel und Shownotes eintragen, **Speichern & veröffentlichen**.

Die Folge ist sofort auf der öffentlichen Seite und im Feed.

## Wirklich ins Netz

### Weg 1: Das Studio läuft auf einem Server

Dann ist alles, was du veröffentlichst, sofort online. Auf einem Server
(z.B. ein kleiner VPS) mit eigener Domain:

```bash
sudo python3 -m venv /opt/sendestudio
sudo /opt/sendestudio/bin/pip install "git+https://github.com/Levirob2015/L-vi"
sudo apt install ffmpeg                       # empfohlen
sudo mkdir -p /var/lib/sendestudio && cd /var/lib/sendestudio
sudo /opt/sendestudio/bin/sendestudio init --titel "Mein Sender" \
     --basis-url https://radio.example.de
sudo cp deploy/sendestudio.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sendestudio
```

Davor gehört ein Webserver mit HTTPS. **Ohne HTTPS erlaubt kein Browser
den Zugriff auf Mikrofon und Kamera** (Ausnahme: `localhost`). Am
einfachsten mit [Caddy](https://caddyserver.com), das sich das Zertifikat
selbst holt – `/etc/caddy/Caddyfile`:

```
radio.example.de {
    request_body {
        max_size 4GB
    }
    reverse_proxy 127.0.0.1:8790
}
```

Danach in `sendestudio.json` setzen und den Dienst neu starten:

```json
"sicheres_cookie": true,
"vertraute_proxys": ["127.0.0.1"]
```

`vertraute_proxys` sorgt dafür, dass der Login-Schutz die echte Adresse
des Besuchers sieht und nicht die von Caddy.

### Weg 2: Statische Seite auf beliebigen Webspace

Das Studio läuft bei dir zu Hause, veröffentlicht wird eine fertige
Webseite:

```bash
sendestudio export               # schreibt nach ./oeffentlich
```

oder im Studio *Ins Netz stellen → Statische Seite erzeugen*. Den Ordner
lädst du auf deinen Webspace, zu GitHub Pages oder Netlify. Wichtig:
`basis_url` in `sendestudio.json` auf die spätere Adresse setzen, sonst gibt
es keinen Podcast-Feed – Podcast-Apps brauchen vollständige Adressen.

Der Export räumt hinter sich auf: Ziehst du eine Folge zurück,
verschwindet sie beim nächsten Export auch aus dem Ordner. Dateien, die
nicht vom Export stammen, bleiben unangetastet.

### Weg 3: Per FTP direkt auf den Webspace

In `sendestudio.json`:

```json
"basis_url": "https://www.mein-webspace.de/podcast",
"ftp": {
  "host": "ftp.mein-webspace.de",
  "benutzer": "web123",
  "passwort": "…",
  "pfad": "/podcast",
  "port": 21,
  "tls": true
}
```

Dann `sendestudio ftp` oder im Studio *Ins Netz stellen → Per FTP
hochladen*. Verschlüsselt (FTPS) ist Standard. Audio-Dateien, die schon
oben liegen, werden übersprungen.

## Den Podcast bei Apple, Spotify & Co. anmelden

Die Feed-Adresse steht auf der Seite deiner Sendung und im Studio unter
*Ins Netz stellen*, z.B. `https://radio.example.de/s/mein-podcast/feed.xml`.
Diese Adresse reichst du einmal ein:

- Apple Podcasts: [podcastsconnect.apple.com](https://podcastsconnect.apple.com)
- Spotify: [podcasters.spotify.com](https://podcasters.spotify.com)
- Alle anderen Apps: *Podcast per URL hinzufügen*

Neue Folgen erscheinen danach automatisch. Apple verlangt ein Cover von
mindestens 1400 × 1400 Pixeln.

## Einstellungen (`sendestudio.json`)

| Schlüssel | Bedeutung |
|---|---|
| `seitentitel` | Name der öffentlichen Seite |
| `basis_url` | Öffentliche Adresse – nötig für den Feed |
| `host`, `port` | Wo der Server lauscht (Standard `127.0.0.1:8790`) |
| `daten` | Ordner für Datenbank und Aufnahmen |
| `export_ziel` | Ordner für den statischen Export |
| `max_upload_mb` | Größte erlaubte Datei (Standard 4096) |
| `sicheres_cookie` | Anmeldung nur über HTTPS – einschalten, sobald HTTPS läuft |
| `vertraute_proxys` | Proxys, deren `X-Forwarded-For` geglaubt wird |
| `ftp` | Zugang für Weg 3 |
| `passwort_hash` | Nicht von Hand ändern – `sendestudio passwort` benutzen |

Die Datei wird nur für ihren Besitzer lesbar angelegt (sie enthält ggf. das
FTP-Passwort).

## Sicherheit

- **Login-Schutz durch LoginShield** aus diesem Repository: Nach mehreren
  falschen Passwörtern wird die Adresse mit ansteigender Dauer gesperrt.
- Passwort nur als PBKDF2-Hash gespeichert, Sitzung als `HttpOnly`-,
  `SameSite=Strict`-Cookie, zusätzlich eine Pflicht-Kennung an jeder
  ändernden Anfrage gegen CSRF.
- Hochgeladene Dateien werden **am Inhalt** erkannt, nicht am Namen – eine
  HTML-Datei, die sich `folge.mp3` nennt, wird abgewiesen.
- Entwürfe und ihre Dateien sind öffentlich nicht erreichbar.
- Strenge Content-Security-Policy auf allen Seiten, keine Inline-Skripte.

## Befehle

```
sendestudio init [--titel T] [--basis-url URL]   Konfiguration + Passwort anlegen
sendestudio passwort [--zufall]                 Neues Passwort setzen
sendestudio serve [--host H] [--port P]         Studio + öffentliche Seite starten
sendestudio export [ZIEL]                       Statische Seite schreiben
sendestudio ftp                                 Exportieren und per FTP hochladen
```

## Tests

```bash
python -m pytest tests/test_sendestudio.py -q
```

Die Tests laufen mit und ohne ffmpeg.
