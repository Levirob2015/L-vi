# Die Website ins Internet stellen

Eine Adresse, alles drin:

| Adresse | Was | Für wen |
|---|---|---|
| `https://deine-domain.de/` | Startseite mit allen Bereichen und den neuesten Folgen | alle |
| `/sendungen/` | Podcasts, Radio (live nach der Uhr) und Dokumentationen, mit Feeds und gesprochenem Text zum Mitlesen | alle |
| `/zeitung/` | **Die Zeitung** – alle Ausgaben, gesetzt wie gedruckt, mit Knopf zum Drucken | alle |
| `/roboter/` | **ProBot Roboter-Designer** – Roboter beschreiben, Zeichnung, Teileliste, Code, 3D-Druckteile | alle |
| `/studio` | **Sendestudio** – aufnehmen (mit Teleprompter), Zeitung schreiben, Musik, KI, veröffentlichen | nur du (Anmeldung) |
| `/leitstand/` | **Hack-Schutz-Leitstand** (LoginShield) – wer versucht einzubrechen, wer ist gesperrt | nur du (Anmeldung) |

Eine Anmeldung (Passwort, auf Wunsch mit Zwei-Faktor-Code) gilt für Studio
und Leitstand. Alles läuft auf **deinem eigenen Server**, mit HTTPS.

## Was du brauchst

1. **Einen Server (VPS)** mit **Debian 12** oder **Ubuntu 24.04**, mindestens
   2 GB Arbeitsspeicher und 40 GB Speicher. Solche Server gibt es bei vielen
   Anbietern für etwa 4–6 € im Monat. Für Videos und viele Aufnahmen lieber
   mehr Speicher wählen.
2. **Eine Domain** (z. B. `mein-sender.de`, meist ca. 1 € im Monat) – beim
   Server-Anbieter oder einem Domain-Anbieter.
3. Ein **Terminal** auf deinem Computer (Mac: „Terminal“, Windows:
   „PowerShell“) für die Verbindung per SSH.

## Schritt für Schritt

### 1. Domain auf den Server zeigen lassen

In der Verwaltung deiner Domain einen **A-Eintrag** anlegen: Name `@` (oder
eine Unteradresse wie `radio`), Ziel = die **IPv4-Adresse deines Servers**.
Hat der Server auch eine IPv6-Adresse, zusätzlich einen **AAAA-Eintrag**.
Das kann bis zu einer Stunde dauern. Prüfen:

```bash
ping mein-sender.de        # muss die Adresse deines Servers zeigen
```

### 2. Auf dem Server anmelden

```bash
ssh root@DIE-IP-DEINES-SERVERS
```

### 3. Installieren – ein Befehl

```bash
apt-get update && apt-get install -y git
git clone https://github.com/Levirob2015/L-vi.git
bash L-vi/deploy/install.sh --domain mein-sender.de --titel "Mein Sender" --email du@example.de
```

Das Skript erledigt alles: Pakete (Python, ffmpeg, Caddy), das Programm, einen
eigenen Systembenutzer, die Einstellungen, den Dienst (startet nach einem
Neustart von selbst), HTTPS mit automatischem Zertifikat, die Firewall-Regeln
und automatische Sicherheitsupdates für das System.

Am Ende zeigt es **dein Passwort** und deinen **Wiederherstellungsschlüssel**.
Beides aufschreiben (am besten auf Papier). Ohne beides sind unveröffentlichte
Aufnahmen verloren – sie liegen verschlüsselt.

### 4. Ausprobieren

`https://mein-sender.de` öffnen. Über **Studio → Anmelden** mit dem Passwort
hinein. Oben in der Studio-Leiste geht es zum **Leitstand** und zum
**Roboter-Designer**.

### 5. Zwei-Faktor-Anmeldung einschalten (sehr empfohlen)

```bash
sudo -u sendestudio /opt/sendestudio/bin/sendestudio -c /var/lib/sendestudio/sendestudio.json zweifaktor
systemctl restart sendestudio
```

Den angezeigten Schlüssel in eine Authenticator-App eintragen und mit einem
Code bestätigen. Ab dann braucht die Anmeldung zusätzlich den Code vom Handy.

### 6. KI-Werkzeuge (freiwillig)

```bash
nano /etc/sendestudio/umgebung     # Schlüssel eintragen, # am Zeilenanfang entfernen
systemctl restart sendestudio
```

Welche Schlüssel wofür, steht in [SENDESTUDIO.md](SENDESTUDIO.md#ki-werkzeuge).

## Aktualisieren

```bash
cd L-vi && git pull
bash deploy/install.sh --domain mein-sender.de
```

Daten, Passwort und Einstellungen bleiben, nur das Programm wird erneuert.

## Sichern

Alles Wichtige liegt in `/var/lib/sendestudio`:

```bash
systemctl stop sendestudio
tar czf /root/sendestudio-sicherung-$(date +%F).tar.gz -C /var/lib sendestudio
systemctl start sendestudio
```

Die Sicherung auf einen anderen Rechner kopieren (z. B. mit `scp`).
Unveröffentlichtes bleibt darin verschlüsselt – zum Wiederherstellen brauchst
du Passwort oder Wiederherstellungsschlüssel.

## Wenn etwas nicht geht

| Problem | Lösung |
|---|---|
| Browser meldet „unsicher“ / kein Zertifikat | Zeigt die Domain schon auf den Server (`ping`)? Sind Port 80 und 443 beim Anbieter offen? `journalctl -u caddy -n 50` |
| Seite lädt nicht | `systemctl status sendestudio` und `journalctl -u sendestudio -n 50` |
| Passwort vergessen | `sudo -u sendestudio /opt/sendestudio/bin/sendestudio -c /var/lib/sendestudio/sendestudio.json passwort` – fragt nach dem Wiederherstellungsschlüssel |
| Gesperrt nach Fehlversuchen | einige Minuten warten – oder auf dem Server `systemctl restart sendestudio` und erneut versuchen |
| Upload bricht ab | Dateien bis 4 GB gehen; größer in `/etc/caddy/Caddyfile` (`max_size`) und `max_upload_mb` in der Konfiguration |

## Gut zu wissen

- **Sicherheit:** Der Dienst lauscht nur auf dem Server selbst; von außen
  erreichbar ist nur Caddy (HTTPS). Der Leitstand läuft nur intern und ist
  nur nach Anmeldung erreichbar. Der Roboter-Designer läuft **abgeschottet**:
  Er kann weder auf die Anmeldung noch auf das Studio zugreifen.
- **Roboter-Designer:** Weil er abgeschottet ist, merkt er sich deinen
  KI-Schlüssel und das letzte Projekt nicht über einen Neustart des Browsers
  hinweg. Wer das möchte, gibt ihm eine eigene Unteradresse – Anleitung in
  `deploy/Caddyfile`. Die optionale Sprach-KI zum Herunterladen läuft
  abgeschottet ebenfalls nicht; die eingebaute ProBot-KI und Claude schon.
- **Nur Sendungen, ohne Roboter und Leitstand:** In
  `/var/lib/sendestudio/sendestudio.json` `"website": false` setzen und neu
  starten.
- **SSH absichern:** Statt Passwort einen SSH-Schlüssel benutzen – die
  Anleitung dafür gibt es bei jedem Server-Anbieter.
