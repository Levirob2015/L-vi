#!/usr/bin/env bash
# Richtet die ganze Website (Sendestudio, Roboter-Designer, Hack-Schutz-
# Leitstand) auf einem frischen Server ein - mit HTTPS, als Dienst, der nach
# einem Neustart von selbst wieder laeuft.
#
# Voraussetzungen: Debian 12/13 oder Ubuntu 24.04, Zugang als root, und eine
# Domain, deren A-Eintrag (ggf. auch AAAA) auf diesen Server zeigt.
#
#   git clone https://github.com/Levirob2015/L-vi.git
#   sudo bash L-vi/deploy/install.sh --domain radio.example.de --titel "Mein Sender"
#
# Noch einmal ausgefuehrt, aktualisiert das Skript nur das Programm und
# startet neu - Daten, Passwort und Einstellungen bleiben.
#
# Optionen:
#   --domain NAME      Adresse der Website (Pflicht, ausser mit --ohne-dienste)
#   --titel TEXT       Name der Website (nur bei der ersten Einrichtung)
#   --email ADRESSE    fuer Hinweise von Let's Encrypt zum Zertifikat (empfohlen)
#   --quelle PFAD|URL  Programm von hier statt aus dem Ordner dieses Skripts
#   --ohne-dienste     nur Programm und Einstellungen - kein apt, systemd,
#                      Caddy und keine Firewall (zum Ausprobieren und Testen)
#   --praefix ORDNER   alles unterhalb dieses Ordners anlegen (zum Testen)
set -euo pipefail

DOMAIN=""
TITEL="Mein Sender"
EMAIL=""
QUELLE=""
OHNE_DIENSTE=0
PRAEFIX=""
PORT=8790

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --titel) TITEL="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --quelle) QUELLE="${2:-}"; shift 2 ;;
    --ohne-dienste) OHNE_DIENSTE=1; shift ;;
    --praefix) PRAEFIX="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1 (Hilfe: --help)" >&2; exit 2 ;;
  esac
done

meldung() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
abbruch() { printf '\n\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$OHNE_DIENSTE" -eq 0 ]; then
  [ "$(id -u)" -eq 0 ] || abbruch "Bitte als root ausführen (sudo bash $0 ...)."
  [ -n "$DOMAIN" ] || abbruch "Bitte --domain angeben, z.B. --domain radio.example.de"
  command -v apt-get >/dev/null || abbruch "Dieses Skript ist für Debian/Ubuntu (apt-get fehlt)."
fi
if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'; then
  abbruch "Ungültige Domain: $DOMAIN"
fi

PROGRAMM="$PRAEFIX/opt/sendestudio"          # Python-Umgebung mit dem Programm
DATEN="$PRAEFIX/var/lib/sendestudio"         # Daten, Aufnahmen, Konfiguration
UMGEBUNG="$PRAEFIX/etc/sendestudio/umgebung" # API-Schluessel fuer die KI
KONFIG="$DATEN/sendestudio.json"
SKRIPTORDNER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -n "$QUELLE" ] || QUELLE="$(dirname "$SKRIPTORDNER")"

# ----------------------------------------------------------------------
meldung "1/6 Pakete"
if [ "$OHNE_DIENSTE" -eq 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  # ffmpeg: Umwandeln, Lautheit, Musik unterlegen, Videos. Caddy: HTTPS.
  apt-get install -y -q python3 python3-venv ffmpeg caddy git ca-certificates unattended-upgrades
  # Sicherheitsupdates fuer das System spielt der Server ab jetzt selbst ein.
  if [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
      > /etc/apt/apt.conf.d/20auto-upgrades
  fi
  if ! id sendestudio >/dev/null 2>&1; then
    useradd --system --home-dir "$DATEN" --shell /usr/sbin/nologin sendestudio
  fi
else
  echo "übersprungen (--ohne-dienste)"
fi
command -v python3 >/dev/null || abbruch "python3 fehlt"

# ----------------------------------------------------------------------
meldung "2/6 Programm installieren"
mkdir -p "$PROGRAMM"
[ -x "$PROGRAMM/bin/python" ] || python3 -m venv "$PROGRAMM"
"$PROGRAMM/bin/pip" install -q --upgrade pip
# Mit KI-Extra (Anthropic-SDK, braucht Python 3.10+); sonst ohne.
if "$PROGRAMM/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  "$PROGRAMM/bin/pip" install -q --upgrade "${QUELLE}[ki]"
else
  "$PROGRAMM/bin/pip" install -q --upgrade "$QUELLE"
fi
"$PROGRAMM/bin/sendestudio" --version

# ----------------------------------------------------------------------
meldung "3/6 Einstellungen"
mkdir -p "$DATEN"
ZUGANG=""
if [ -f "$KONFIG" ]; then
  echo "Vorhandene Einrichtung gefunden - Daten und Passwort bleiben unverändert."
else
  ZUGANG="$("$PROGRAMM/bin/sendestudio" -c "$KONFIG" init --titel "$TITEL" \
            ${DOMAIN:+--basis-url "https://$DOMAIN"})"
fi
# Hinter Caddy mit HTTPS: Cookie nur ueber HTTPS, Caddy als vertrauter Proxy,
# und der Dienst selbst nur von diesem Rechner aus erreichbar.
"$PROGRAMM/bin/python" - "$KONFIG" "$DOMAIN" "$PORT" <<'PY'
import json, os, sys
pfad, domain, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(pfad, encoding="utf-8") as f:
    cfg = json.load(f)
cfg.update(host="127.0.0.1", port=port, vertraute_proxys=["127.0.0.1", "::1"])
if domain:
    cfg.update(basis_url=f"https://{domain}", sicheres_cookie=True)
tmp = pfad + ".neu"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
os.replace(tmp, pfad)
PY
mkdir -p "$(dirname "$UMGEBUNG")"
if [ ! -f "$UMGEBUNG" ]; then
  ( umask 077; cat > "$UMGEBUNG" <<'ENV'
# Schluessel fuer die KI-Werkzeuge - alle freiwillig. Eintragen, dann:
#   sudo systemctl restart sendestudio
# Diese Datei ist nur fuer root lesbar.
#ANTHROPIC_API_KEY=sk-ant-...
#OPENAI_API_KEY=sk-...
#ELEVENLABS_API_KEY=...
ENV
  )
fi

# ----------------------------------------------------------------------
meldung "4/6 Dienst"
if [ "$OHNE_DIENSTE" -eq 0 ]; then
  chown -R sendestudio:sendestudio "$DATEN"
  chmod 700 "$DATEN"
  install -m 644 "$SKRIPTORDNER/sendestudio.service" /etc/systemd/system/sendestudio.service
  systemctl daemon-reload
  systemctl enable sendestudio >/dev/null
  systemctl restart sendestudio
  sleep 2
  systemctl is-active --quiet sendestudio || { journalctl -u sendestudio -n 30 --no-pager; abbruch "Der Dienst startet nicht (Protokoll oben)."; }
  echo "läuft"
else
  echo "übersprungen (--ohne-dienste)"
fi

# ----------------------------------------------------------------------
meldung "5/6 HTTPS mit Caddy"
if [ "$OHNE_DIENSTE" -eq 0 ]; then
  CADDYFILE=/etc/caddy/Caddyfile
  if [ -f "$CADDYFILE" ] && ! grep -q "Sendestudio" "$CADDYFILE"; then
    cp "$CADDYFILE" "$CADDYFILE.vor-sendestudio"
    echo "Bisherige Caddy-Einstellungen gesichert: $CADDYFILE.vor-sendestudio"
  fi
  sed -e "s/radio.example.de/$DOMAIN/g" "$SKRIPTORDNER/Caddyfile" > "$CADDYFILE.neu"
  if [ -n "$EMAIL" ]; then
    printf '{\n\temail %s\n}\n\n' "$EMAIL" | cat - "$CADDYFILE.neu" > "$CADDYFILE.neu2" && mv "$CADDYFILE.neu2" "$CADDYFILE.neu"
  fi
  caddy validate --config "$CADDYFILE.neu" --adapter caddyfile >/dev/null || abbruch "Caddy-Einstellungen ungültig"
  mv "$CADDYFILE.neu" "$CADDYFILE"
  systemctl enable caddy >/dev/null
  systemctl reload caddy 2>/dev/null || systemctl restart caddy
  echo "Caddy holt sich das Zertifikat für $DOMAIN beim ersten Aufruf selbst."
else
  echo "übersprungen (--ohne-dienste)"
fi

# ----------------------------------------------------------------------
meldung "6/6 Firewall"
if [ "$OHNE_DIENSTE" -eq 0 ] && command -v ufw >/dev/null; then
  ufw allow OpenSSH >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  echo "ufw: SSH, 80 und 443 freigegeben (Status: $(ufw status | head -1))"
else
  echo "keine ufw - nur die Ports 22, 80 und 443 müssen offen sein."
fi

# ----------------------------------------------------------------------
if [ -n "$ZUGANG" ]; then
  if [ "$OHNE_DIENSTE" -eq 0 ]; then
    NOTIZ=/root/sendestudio-zugang.txt
    ( umask 077; printf '%s\n' "$ZUGANG" > "$NOTIZ" )
  fi
  cat <<TEXT

========================================================================
  Fertig! ${DOMAIN:+Die Website: https://$DOMAIN}

$(printf '%s\n' "$ZUGANG" | grep -E '^(Studio-Passwort|Wiederherstellungsschlüssel):' | sed 's/^/  /')

  Beides jetzt aufschreiben. ${NOTIZ:+Eine Kopie liegt in $NOTIZ -
  danach bitte löschen: rm $NOTIZ}
========================================================================
TEXT
else
  echo
  echo "Fertig – aktualisiert. ${DOMAIN:+Die Website: https://$DOMAIN}"
fi
cat <<TEXT

Nächste Schritte:
  * Zwei-Faktor-Anmeldung (sehr empfohlen):
      sudo -u sendestudio $PROGRAMM/bin/sendestudio -c $KONFIG zweifaktor
      sudo systemctl restart sendestudio
  * KI-Werkzeuge: Schlüssel in $UMGEBUNG eintragen, dann
      sudo systemctl restart sendestudio
  * Protokoll ansehen:  journalctl -u sendestudio -f
TEXT
