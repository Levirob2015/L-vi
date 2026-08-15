# LoginShield

Schutz gegen Brute-Force- und automatisierte Angriffe auf Logins und Server.
Erkennt Angriffsmuster, sperrt die IP automatisch mit ansteigender Dauer und
zeigt die Lage in einem Web-Dashboard.

**Ohne externe Abhängigkeiten** – nur Python 3.9+ und die Standardbibliothek.
Nutzbar als Bibliothek, als Middleware, als Log-Wächter und über die
Kommandozeile.

![Dashboard](docs/dashboard.png)

---

## Schnellstart

```bash
git clone https://github.com/Levirob2015/L-vi.git
cd L-vi
pip install -e .          # oder einfach: export PYTHONPATH=$PWD

loginshield init          # Konfiguration + Dashboard-Token anlegen
loginshield demo          # Beispieldaten, damit man etwas sieht
loginshield serve         # Dashboard auf http://127.0.0.1:8787
```

Oder direkt die lauffähige Beispielanwendung mit echtem Login ausprobieren:

```bash
python examples/demo_login_app.py
# Login:     http://127.0.0.1:8080   (anna / geheim123)
# Dashboard: http://127.0.0.1:8787
```

Fünfmal ein falsches Passwort eingeben – danach ist die IP gesperrt, auch mit
dem richtigen Passwort.

---

## Was erkannt wird

| Muster | Beschreibung | Standard-Schwelle |
|---|---|---|
| **Brute Force** | Viele Fehlversuche von einer IP | 5 Versuche / 5 Min |
| **Password Spraying** | Eine IP probiert viele verschiedene Konten | 5 Konten / 10 Min |
| **Gezielter Kontoangriff** | Viele Fehlversuche gegen *ein* Konto, verteilt über viele IPs | 10 Versuche / 15 Min |
| **Request-Flut** | Zu viele Anfragen pro IP (unabhängig vom Login) | 60 / Min |

Spraying braucht eine eigene Regel: Wer pro Konto nur zwei Passwörter probiert,
löst die klassische Fehlversuchs-Schwelle nie aus – über zwanzig Konten hinweg
ist es trotzdem ein Angriff.

**Sperrdauer steigt an:** erste Sperre 15 Minuten, dann 30, 60, 120 … bis
maximal 24 Stunden. Frühere Sperren zählen 7 Tage lang mit. Ein hartnäckiger
Angreifer sperrt sich damit selbst immer länger aus, ein Nutzer mit
Zahlendreher wartet nur kurz.

---

## Einbinden in eine eigene Anwendung

### Direkt (funktioniert mit jedem Framework)

Drei Aufrufe, mehr braucht es nicht:

```python
from loginshield import Guard, load_config

guard = Guard(load_config())

def login(request):
    ip = guard.resolve_ip(request.remote_addr, request.headers.get("X-Forwarded-For"))

    # 1. Vor der Passwortprüfung: darf diese IP überhaupt?
    decision = guard.check(ip, identity=request.form["username"], route="/login")
    if not decision.allowed:
        return response(decision.status_code, "Zu viele Versuche.",
                        headers={"Retry-After": str(decision.retry_after)})

    if passwort_stimmt:
        guard.record_success(ip, identity=username)   # setzt die Zähler zurück
        return redirect("/")

    # 2. Fehlschlag melden – die Antwort sagt, ob jetzt gesperrt wurde
    result = guard.record_failure(ip, identity=username, route="/login")
    return response(401, "Benutzername oder Passwort falsch.")
```

### FastAPI / Starlette / jedes ASGI-Framework

```python
from loginshield import Guard, load_config
from loginshield.middleware import ShieldMiddleware

guard = Guard(load_config())
app.add_middleware(ShieldMiddleware, guard=guard,
                   login_paths=["/login", "/api/auth/*"],
                   exempt_paths=["/health", "/static/*"])
```

Die Middleware erkennt Fehlschläge am HTTP-Status (401/403/422). Für die
Spraying-Erkennung braucht sie zusätzlich den Benutzernamen:

```python
def identity_from_scope(scope):
    return dict(scope["headers"]).get(b"x-username", b"").decode() or None
```

### Flask / Django / WSGI

```python
from loginshield.middleware import WSGIShield

app.wsgi_app = WSGIShield(app.wsgi_app, guard, login_paths=["/login"])
```

---

## SSH und Webserver schützen (ohne Codeänderung)

`loginshield watch` liest Logdateien mit und meldet Fehlversuche an dieselbe
Engine – wie fail2ban, nur mit Dashboard:

```bash
loginshield watch --path /var/log/auth.log --format sshd
```

Dauerhaft über die Konfiguration:

```yaml
logwatch:
  - path: /var/log/auth.log
    format: sshd
  - path: /var/log/nginx/access.log
    format: nginx
    path_filter: /login
    failure_statuses: [401, 403]
```

Eigene Anwendungslogs mit `format: custom` und einem Regex, der die Gruppen
`(?P<ip>...)` und optional `(?P<identity>...)` enthält.
Logrotation wird automatisch erkannt.

Damit die IP auch auf Netzwerkebene blockiert wird, optional die Firewall
anbinden (aus Sicherheitsgründen standardmäßig aus, läuft ohne Shell):

```yaml
firewall:
  enabled: true
  block_command:   ["nft", "add", "element", "inet", "filter", "banned", "{ {ip} }"]
  unblock_command: ["nft", "delete", "element", "inet", "filter", "banned", "{ {ip} }"]
```

---

## Kommandozeile

```
loginshield init                       Konfiguration + Token anlegen
loginshield serve [--watch]            Dashboard starten
loginshield watch --path DATEI         Logdateien mitlesen
loginshield status [--hours 24]        Lage-Überblick im Terminal
loginshield check IP                   Status einer IP abfragen
loginshield block IP [--minutes 60]    IP manuell sperren
loginshield unblock IP                 Sperre aufheben
loginshield allow add|remove|list      Allowlist verwalten
loginshield export --format csv        Ereignisse exportieren
loginshield prune                      Alte Daten löschen
loginshield demo                       Beispieldaten erzeugen
```

`loginshield status` im Terminal:

```
Lage der letzten 24 Stunden
==============================================
  Fehlversuche       97
  Angreifende IPs    6
  Aktive Sperren     3
```

---

## Konfiguration

`loginshield init` legt eine kommentierte `loginshield.yaml` an (bzw. `.json`,
wenn PyYAML fehlt). Die wichtigsten Punkte:

```yaml
allowlist:              # wird NIE gesperrt – hier dein Büro/VPN eintragen
  - 127.0.0.1
trusted_proxies: []     # nur diesen IPs wird X-Forwarded-For geglaubt
identity_mode: hashed   # Benutzernamen nur als HMAC speichern
retention_days: 30

rules:
  ip_failure_threshold: 5
  ip_failure_window: 300
  block_base_seconds: 900
  block_escalation_factor: 2.0
  identity_action: throttle   # throttle | lock | off
```

Geheimnisse lassen sich per Umgebungsvariable aus der Datei heraushalten:
`LOGINSHIELD_DB`, `LOGINSHIELD_TOKEN`, `LOGINSHIELD_HMAC_KEY`.

### Zwei Einstellungen, die wirklich zählen

**`trusted_proxies`** – Läuft die App hinter nginx/Cloudflare, kommt jede
Anfrage von der Proxy-IP; ohne diese Einstellung sperrt LoginShield im
Ernstfall den Proxy und damit alle Nutzer. Trage hier die Proxy-Adressen ein,
dann wird `X-Forwarded-For` ausgewertet – aber **nur** dann. Diesen Header
ungeprüft zu glauben wäre die größere Lücke: Er ist frei erfindbar, und
jeder Angreifer könnte damit die Sperre umgehen oder fremde IPs sperren lassen.

**`identity_action`** – Ein Konto nach zu vielen Fehlversuchen komplett zu
sperren (`lock`) klingt sicher, ist aber ein Denial-of-Service-Vektor: Wer
deinen Benutzernamen kennt, sperrt dich damit absichtlich aus. Standard ist
deshalb `throttle` – der Angriff wird ausgebremst, der echte Nutzer kommt
weiterhin rein.

---

## Dashboard

`loginshield serve` startet es auf `127.0.0.1:8787`. Es zeigt Kennzahlen,
den Zeitverlauf, aktive Sperren (mit Entsperren-Knopf), auffälligste IPs und
die letzten Ereignisse; Allowlist und manuelle Sperren lassen sich dort pflegen.

Zum Sicherheitsmodell:

* Standardmäßig lauscht es **nur lokal**. Für den Zugriff von außen ist ein
  Token Pflicht – die Konfiguration verweigert sonst den Start.
* Ändernde Aufrufe verlangen den Token im Header `X-Auth-Token`, nicht in der
  URL. Damit ist CSRF ausgeschlossen, und der Token landet nicht in
  Server-Logs oder im Browserverlauf.
* Token-Vergleich in konstanter Zeit, strikte CSP, keine externen Ressourcen.

Für den Zugriff von unterwegs besser einen SSH-Tunnel nehmen, als den Port
zu öffnen:

```bash
ssh -L 8787:127.0.0.1:8787 user@server
```

---

## Datenschutz

Benutzernamen werden standardmäßig **nicht im Klartext** gespeichert, sondern
als HMAC (`identity_mode: hashed`) – im Dashboard erscheint `user:a2935c74…`.
Korrelation über Angriffe hinweg bleibt möglich, aber die Angriffsdatenbank
enthält keine Kontonamen. Passwörter werden **nie** protokolliert, auch nicht
gehasht. Die Datenbankdatei wird mit Rechten `600` angelegt, Ereignisse nach
`retention_days` gelöscht (`loginshield prune`, z. B. per Cron).

---

## Was das schützt – und was nicht

LoginShield deckt eine bestimmte Angriffsklasse ab: **automatisiertes
Durchprobieren von Zugangsdaten und Anfrageschwemmen.** Das ist der mit
Abstand häufigste Angriff auf einen Server, der im Internet steht.

Es ersetzt nicht:

* **starke Passwörter und 2FA** – der wirksamste Login-Schutz überhaupt.
  LoginShield verschafft Zeit, es rettet kein Passwort „123456“.
* **Passwort-Hashing** mit argon2/bcrypt/scrypt in deiner Anwendung.
* **Schutz vor SQL-Injection, XSS, CSRF** – das gehört in den Anwendungscode.
* **Updates** von Betriebssystem und Abhängigkeiten.
* **Backups** – gegen Ransomware hilft nur eine Kopie, die offline liegt.
* **DDoS-Abwehr** auf Netzwerkebene; ein verteilter Angriff aus zehntausenden
  IPs braucht Schutz beim Provider.

Zwei praktische Hinweise: Trage deine eigene IP in die `allowlist` ein, bevor
du scharf schaltest – sonst sperrst du dich im Zweifel selbst aus (`loginshield
unblock DEINE-IP` hilft dann von der Konsole). Und teste die Schwellwerte
zuerst mit `loginshield demo` oder der Beispiel-App.

---

## Tests

```bash
pip install pytest
python -m pytest -q      # 120 Tests
```

Abgedeckt sind unter anderem: Erkennungsregeln und Eskalation, Allowlist,
Rate-Limiting, IP-Auflösung hinter Proxys inklusive gefälschter Header,
Log-Parsing (sshd/nginx/custom) samt Logrotation, ASGI- und WSGI-Middleware,
Dashboard-API mit Authentifizierung und die Kommandozeile. Zeitabhängige
Tests laufen über eine steuerbare Uhr – keine echten Wartezeiten.

---

## Aufbau

```
loginshield/
  engine.py      Guard – Erkennung und Entscheidungen (Herzstück)
  store.py       SQLite-Persistenz
  ratelimit.py   Gleitendes Zeitfenster
  netutils.py    IP-/CIDR-Logik, Proxy-Auflösung
  middleware.py  ASGI- und WSGI-Einbindung
  logwatch.py    Logdateien mitlesen
  dashboard.py   Web-Oberfläche
  firewall.py    optionale nft/iptables-Anbindung
  cli.py         Kommandozeile
examples/        lauffähige Beispielanwendung
tests/           Testsuite
```

## Lizenz

MIT
