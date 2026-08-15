"""Der Honeypot: vorgetaeuschte Schwachstellen als Falle.

Die Idee: Ein Angreifer sucht, bevor er Passwoerter durchprobiert, erst nach
leichter Beute - ``/.env``, ``/wp-admin``, ``/phpmyadmin``, ``/.git/config``.
Diese Pfade existieren hier nicht wirklich, aber sie **antworten** so, als
gaebe es sie. Damit ist der Angreifer entlarvt, bevor er den echten Login
auch nur gesehen hat.

Drei Fallen greifen ineinander:

1. **Koeder-Pfade** - gefaelschte Schwachstellen. Ein einziger Aufruf genuegt
   fuer eine Sperre: es gibt keinen harmlosen Grund, ``/.env`` abzurufen.
2. **Koeder-Zugangsdaten** (Honeytoken) - in den gefaelschten Dateien stehen
   Zugangsdaten, die nirgends gueltig sind. Taucht so ein Benutzername spaeter
   am echten Login auf, ist das ein Beweis: derjenige hat die Koederdatei
   gelesen. Sofortige Sperre.
3. **Unsichtbares Formularfeld** - ein Eingabefeld, das Menschen nicht sehen.
   Bots fuellen jedes Feld aus, das sie finden. Wer es ausfuellt, ist keiner.

Wichtig: Der Honeypot greift nur an, wenn jemand von sich aus zugreift. Er
scannt nicht zurueck, sammelt keine fremden Daten und startet nichts gegen
den Angreifer - er sperrt ihn aus, mehr nicht.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

from .config import HoneypotConfig
from .models import Block, Reason

log = logging.getLogger("loginshield.honeypot")


@dataclass(frozen=True)
class Trap:
    """Ein Koederpfad und die Art der vorgetaeuschten Luecke."""

    pattern: str
    kind: str = "generic"

    def matches(self, path: str) -> bool:
        path = path.lower().rstrip("/") or "/"
        pattern = self.pattern.lower()
        if pattern.endswith("*"):
            return path.startswith(pattern[:-1].rstrip("/"))
        return path == pattern.rstrip("/") or path == pattern


#: Eingebaute Koeder. Bewusst nur Pfade, die kein normaler Besucher und kein
#: serioeser Crawler aufruft - jeder Treffer ist ein gezielter Scan.
DEFAULT_TRAPS: Sequence[Trap] = (
    # Konfigurationsdateien mit Zugangsdaten - das Lieblingsziel von Scannern
    Trap("/.env", "env"),
    Trap("/.env.backup", "env"),
    Trap("/.env.local", "env"),
    Trap("/config.json", "env_json"),
    # Versionsverwaltung, versehentlich mit ausgeliefert
    Trap("/.git/config", "git"),
    Trap("/.git/HEAD", "git_head"),
    # Datenbank-Oberflaechen
    Trap("/phpmyadmin*", "phpmyadmin"),
    Trap("/pma*", "phpmyadmin"),
    Trap("/adminer.php", "adminer"),
    # WordPress, auch auf Seiten ohne WordPress permanent gescannt
    Trap("/wp-admin*", "wordpress"),
    Trap("/wp-login.php", "wordpress"),
    Trap("/xmlrpc.php", "xmlrpc"),
    # Datensicherungen im Webverzeichnis
    Trap("/backup.sql", "sql_dump"),
    Trap("/dump.sql", "sql_dump"),
    Trap("/database.sql", "sql_dump"),
    Trap("/backup.zip", "archive"),
    # Admin- und Debug-Oberflaechen
    Trap("/admin.php", "admin_panel"),
    Trap("/administrator*", "admin_panel"),
    Trap("/cpanel*", "admin_panel"),
    Trap("/debug*", "debug"),
    Trap("/actuator/env", "debug"),
    Trap("/server-status", "debug"),
    # Zugangsdaten und Schluessel
    Trap("/.aws/credentials", "aws"),
    Trap("/.ssh/id_rsa", "ssh_key"),
    Trap("/credentials.txt", "credentials"),
    # Klassische Shell-Ablagen
    Trap("/shell.php", "webshell"),
    Trap("/cgi-bin*", "cgi"),
    Trap("/vendor/phpunit*", "php_exploit"),
)


class Honeypot:
    """Erkennt Zugriffe auf die Falle und loest die Sperre aus."""

    def __init__(self, config: Optional[HoneypotConfig] = None, guard=None,
                 *, secret: str = "") -> None:
        self.config = config or HoneypotConfig()
        self.guard = guard
        self._secret = (secret or "").encode("utf-8")

        base = (
            [Trap(pattern) for pattern in self.config.paths]
            if self.config.paths
            else list(DEFAULT_TRAPS)
        )
        base.extend(Trap(pattern) for pattern in self.config.extra_paths)
        excluded = {p.lower().rstrip("/") for p in self.config.exclude_paths}
        self.traps: List[Trap] = [
            trap for trap in base if trap.pattern.lower().rstrip("/") not in excluded
        ]

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    # ------------------------------------------------------------------
    # Falle 1: Koeder-Pfade
    # ------------------------------------------------------------------
    def match(self, path: str) -> Optional[Trap]:
        """Passt dieser Pfad auf einen Koeder?"""
        if not self.enabled or not path:
            return None
        clean = path.split("?", 1)[0].split("#", 1)[0]
        for trap in self.traps:
            if trap.matches(clean):
                return trap
        return None

    def conflicts_with(self, routes: Sequence[str]) -> List[str]:
        """Prueft, ob eigene Routen versehentlich als Koeder gelten.

        Vor dem Scharfschalten aufrufen - sonst sperrt der Honeypot die
        eigenen Nutzer aus.
        """
        return [route for route in routes if self.match(route) is not None]

    # ------------------------------------------------------------------
    # Falle 2: Koeder-Zugangsdaten (Honeytoken)
    # ------------------------------------------------------------------
    def credentials(self) -> Tuple[str, str]:
        """Die untergeschobenen Zugangsdaten (Benutzer, Passwort).

        Ohne feste Vorgabe wird das Passwort stabil aus dem Schluessel
        abgeleitet: bei jedem Start gleich, aber pro Installation anders.
        """
        user = self.config.decoy_user
        if self.config.decoy_password:
            return user, self.config.decoy_password
        seed = self._secret or b"loginshield-default-honeypot-seed"
        digest = hmac.new(seed, b"honeypot-decoy-password", hashlib.sha256).hexdigest()
        return user, f"Srv{digest[:12]}!"

    def is_honeytoken(self, username: Optional[str],
                      password: Optional[str] = None) -> bool:
        """Stammen diese Zugangsdaten aus einer Koederdatei?

        Der Benutzername allein genuegt als Nachweis - er steht nirgendwo
        sonst. Das Passwort wird, wenn angegeben, in konstanter Zeit
        verglichen.
        """
        if not self.enabled or not username:
            return False
        decoy_user, decoy_password = self.credentials()
        if not hmac.compare_digest(username.strip().lower(), decoy_user.lower()):
            return False
        if password is None:
            return True
        return hmac.compare_digest(password, decoy_password)

    # ------------------------------------------------------------------
    # Falle 3: Unsichtbares Formularfeld
    # ------------------------------------------------------------------
    def hidden_field_html(self) -> str:
        """HTML-Schnipsel fuer das eigene Login-Formular.

        Ausserhalb des Bildschirms statt ``display:none`` - manche Bots
        ignorieren versteckte Felder, dieses hier sehen sie.
        """
        name = self.config.hidden_field
        return (
            f'<input type="text" name="{name}" value="" tabindex="-1" '
            f'autocomplete="off" aria-hidden="true" '
            f'style="position:absolute;left:-9999px;width:1px;height:1px;'
            f'opacity:0;pointer-events:none">'
        )

    def check_hidden_field(self, form: Dict[str, object]) -> bool:
        """``True``, wenn das unsichtbare Feld ausgefuellt wurde - also ein Bot."""
        if not self.enabled or not self.config.hidden_field:
            return False
        value = form.get(self.config.hidden_field)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        return bool(value and str(value).strip())

    # ------------------------------------------------------------------
    # Ausloesen
    # ------------------------------------------------------------------
    def trigger(
        self,
        ip: Optional[str],
        *,
        route: str = "",
        reason: str = Reason.HONEYPOT_PATH,
        user_agent: str = "",
        source: str = "app",
        detail: str = "",
    ) -> Optional[Block]:
        """Meldet den Treffer und sperrt die IP sofort."""
        if self.guard is None or not self.enabled:
            return None
        return self.guard.record_honeypot(
            ip,
            route=route,
            reason=reason,
            user_agent=user_agent,
            source=source,
            detail=detail,
            seconds=self.config.block_seconds,
        )

    def tarpit(self) -> None:
        """Antwort verzoegern, um Scanner auszubremsen (synchron)."""
        if self.config.tarpit_seconds > 0:
            time.sleep(self.config.tarpit_seconds)

    # ------------------------------------------------------------------
    # Die vorgetaeuschte Luecke: glaubwuerdige Antworten
    # ------------------------------------------------------------------
    def decoy_response(self, trap: Trap) -> Tuple[int, str, bytes]:
        """Liefert ``(status, content_type, body)`` fuer einen Koeder.

        Der Angreifer soll glauben, er sei fuendig geworden - dann probiert
        er die gefundenen Zugangsdaten aus und laeuft in Falle 2.
        """
        user, password = self.credentials()
        builder = _DECOYS.get(trap.kind, _decoy_generic)
        content_type, body = builder(user, password)
        return 200, content_type, body.encode("utf-8")


# -- Inhalte der gefaelschten Dateien ------------------------------------
# Alle Adressen darin sind Dokumentationsbereiche (RFC 5737 / RFC 2606) und
# fuehren nirgendwohin. Es werden keine echten Daten preisgegeben.
def _decoy_env(user: str, password: str) -> Tuple[str, str]:
    return "text/plain; charset=utf-8", f"""APP_NAME=Portal
APP_ENV=production
APP_DEBUG=false
APP_URL=https://portal.example.com

DB_CONNECTION=mysql
DB_HOST=10.0.0.14
DB_PORT=3306
DB_DATABASE=portal_prod
DB_USERNAME={user}
DB_PASSWORD={password}

REDIS_HOST=10.0.0.15
REDIS_PASSWORD={password}

MAIL_HOST=smtp.example.com
MAIL_USERNAME={user}@example.com
MAIL_PASSWORD={password}

BACKUP_SSH_USER={user}
BACKUP_SSH_HOST=192.0.2.31
"""


def _decoy_env_json(user: str, password: str) -> Tuple[str, str]:
    return "application/json; charset=utf-8", (
        '{\n'
        '  "environment": "production",\n'
        '  "database": {\n'
        '    "host": "10.0.0.14",\n'
        f'    "user": "{user}",\n'
        f'    "password": "{password}"\n'
        '  },\n'
        f'  "admin_user": "{user}"\n'
        '}\n'
    )


def _decoy_git(user: str, password: str) -> Tuple[str, str]:
    return "text/plain; charset=utf-8", f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://{user}:{password}@git.example.com/portal/backend.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""


def _decoy_git_head(user: str, password: str) -> Tuple[str, str]:
    return "text/plain; charset=utf-8", "ref: refs/heads/main\n"


def _decoy_sql(user: str, password: str) -> Tuple[str, str]:
    # Der "Hash" ist erfunden und gehoert zu keinem Passwort.
    return "application/sql; charset=utf-8", f"""-- MySQL dump 10.13  Distrib 8.0.35
-- Host: 10.0.0.14    Database: portal_prod
-- ------------------------------------------------------

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(32) DEFAULT 'user',
  PRIMARY KEY (`id`)
);

INSERT INTO `users` VALUES
 (1,'{user}','$2y$10$9Qk3jT1vXbHm2pLwRsZ0ceUu7Nf4Yd6Ai8Bx5Cv2Ew1Gh3Jk9Lm2','admin'),
 (2,'monitoring','$2y$10$2Bd7Hn4Kq8Rt1Wy6Zc3Xe9Uv5Sa0Pf2Mg7Jl4Nb8Qd6Th1Rk5','service');

-- Zugangsdaten Backup-Dienst: {user} / {password}
"""


def _decoy_phpmyadmin(user: str, password: str) -> Tuple[str, str]:
    return "text/html; charset=utf-8", f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>phpMyAdmin 4.9.7</title></head>
<body>
<div id="page_content">
<h1>Welcome to phpMyAdmin</h1>
<!-- TODO: Standardzugang vor dem Livegang entfernen!
     user: {user} / pass: {password} -->
<form method="post" action="index.php" name="login_form">
  <input type="text" name="pma_username" placeholder="Username">
  <input type="password" name="pma_password" placeholder="Password">
  <input type="submit" value="Go">
</form>
<p class="version">Version information: 4.9.7</p>
</div>
</body></html>
"""


def _decoy_wordpress(user: str, password: str) -> Tuple[str, str]:
    return "text/html; charset=utf-8", f"""<!DOCTYPE html>
<html lang="de-DE"><head><meta charset="UTF-8">
<title>Anmelden &lsaquo; Portal &#8212; WordPress</title></head>
<body class="login">
<div id="login">
<h1><a href="#">Portal</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p><label>Benutzername<input type="text" name="log" id="user_login"></label></p>
  <p><label>Passwort<input type="password" name="pwd" id="user_pass"></label></p>
  <p><input type="submit" name="wp-submit" value="Anmelden"></p>
</form>
<!-- wartung: {user} / {password} -->
</div>
</body></html>
"""


def _decoy_admin_panel(user: str, password: str) -> Tuple[str, str]:
    return "text/html; charset=utf-8", f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>Administration</title></head>
<body>
<h1>Administrationsbereich</h1>
<form method="post" action="">
  <input name="user" placeholder="Benutzer">
  <input name="pass" type="password" placeholder="Passwort">
  <button type="submit">Anmelden</button>
</form>
<!-- Notfallzugang: {user} / {password} -->
</body></html>
"""


def _decoy_debug(user: str, password: str) -> Tuple[str, str]:
    return "application/json; charset=utf-8", (
        '{\n'
        '  "profiles": ["production"],\n'
        '  "propertySources": [{\n'
        '    "name": "applicationConfig",\n'
        '    "properties": {\n'
        '      "spring.datasource.url": "jdbc:mysql://10.0.0.14:3306/portal",\n'
        f'      "spring.datasource.username": "{user}",\n'
        f'      "spring.datasource.password": "{password}"\n'
        '    }\n'
        '  }]\n'
        '}\n'
    )


def _decoy_aws(user: str, password: str) -> Tuple[str, str]:
    return "text/plain; charset=utf-8", f"""[default]
aws_access_key_id = AKIA{hashlib.sha1(user.encode()).hexdigest()[:16].upper()}
aws_secret_access_key = {password}
region = eu-central-1

[backup]
aws_access_key_id = AKIA{hashlib.sha1(password.encode()).hexdigest()[:16].upper()}
aws_secret_access_key = {password}
"""


def _decoy_ssh_key(user: str, password: str) -> Tuple[str, str]:
    filler = hashlib.sha256(password.encode()).hexdigest()
    body = "\n".join(filler * 2 for _ in range(6))
    return "text/plain; charset=utf-8", (
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n"
        f"-----END OPENSSH PRIVATE KEY-----\n"
    )


def _decoy_credentials(user: str, password: str) -> Tuple[str, str]:
    return "text/plain; charset=utf-8", f"""# interne Notizen - nicht loeschen
Server:     192.0.2.31
SSH:        {user} / {password}
Datenbank:  {user} / {password}
Router:     admin / {password}
"""


def _decoy_generic(user: str, password: str) -> Tuple[str, str]:
    return "text/html; charset=utf-8", f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>Index</title></head>
<body>
<h1>Index of /</h1>
<pre>
<a href="backup.sql">backup.sql</a>            12-Mar-2026 03:14   4.2M
<a href="config.json">config.json</a>           12-Mar-2026 03:14   1.1K
<a href="credentials.txt">credentials.txt</a>       12-Mar-2026 03:14   312
</pre>
<!-- service account: {user} / {password} -->
</body></html>
"""


def _safe(text: str, limit: int = 60) -> str:
    """Angreifer-Eingaben nur gesaeubert protokollieren."""
    cleaned = "".join(char for char in text if char.isprintable())
    return cleaned[:limit]


class HoneypotServer:
    """Ein komplett vorgetaeuschter, verwundbar wirkender Dienst.

    Auf einem eigenen Port betrieben, z.B. dem alten Port einer abgeschalteten
    Anwendung. Dorthin verirrt sich niemand versehentlich - **jeder** Zugriff
    ist ein Scan und fuehrt zur Sperre. Der Aufrufer bekommt trotzdem eine
    glaubwuerdige Antwort und merkt nichts.

    Nicht als oeffentlichen "Lockvogel" bewerben und nicht auf fremden
    Systemen betreiben: der Zweck ist, den eigenen Server zu schuetzen.
    """

    def __init__(self, guard, honeypot: Optional[Honeypot] = None, *,
                 host: str = "0.0.0.0", port: int = 8081,
                 block_every_request: bool = True) -> None:
        self.guard = guard
        self.honeypot = honeypot or getattr(guard, "honeypot", None) or Honeypot(guard=guard)
        self.block_every_request = block_every_request
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def _handler(self):
        honeypot = self.honeypot
        block_every_request = self.block_every_request

        class Handler(BaseHTTPRequestHandler):
            # Tarnung: nach aussen ein gewoehnlicher Webserver.
            server_version = "Apache/2.4.41"
            sys_version = "(Ubuntu)"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log.debug("%s - %s", self.address_string(), fmt % args)

            def _ip(self):
                return self.client_address[0]

            def _serve(self, reason: str, detail: str = "") -> None:
                path = urlparse(self.path).path
                trap = honeypot.match(path)
                if trap is not None or block_every_request:
                    honeypot.trigger(
                        self._ip(),
                        route=path,
                        reason=reason,
                        user_agent=self.headers.get("User-Agent", ""),
                        source="honeypot",
                        detail=detail or (trap.kind if trap else "scan"),
                    )
                honeypot.tarpit()

                status, content_type, body = honeypot.decoy_response(
                    trap or Trap(path, "generic")
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                self._serve(Reason.HONEYPOT_PATH)

            def do_HEAD(self):  # noqa: N802
                self._serve(Reason.HONEYPOT_PATH)

            def do_POST(self):  # noqa: N802
                # Wer hier Zugangsdaten abschickt, probiert einen Login auf
                # einem Dienst, den es nie gab. Der Benutzername wird
                # protokolliert (gesaeubert), das Passwort nie.
                detail = "scan"
                try:
                    length = min(int(self.headers.get("Content-Length") or 0), 8192)
                    if length > 0:
                        raw = self.rfile.read(length).decode("utf-8", "replace")
                        form = parse_qs(raw)
                        for key in ("username", "user", "log", "pma_username", "login"):
                            if form.get(key):
                                detail = f"Login-Versuch als {_safe(form[key][0])}"
                                break
                except (ValueError, OSError):  # pragma: no cover - defensiv
                    pass
                self._serve(Reason.HONEYPOT_PATH, detail)

        return Handler

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


_DECOYS = {
    "env": _decoy_env,
    "env_json": _decoy_env_json,
    "git": _decoy_git,
    "git_head": _decoy_git_head,
    "sql_dump": _decoy_sql,
    "archive": _decoy_generic,
    "phpmyadmin": _decoy_phpmyadmin,
    "adminer": _decoy_phpmyadmin,
    "wordpress": _decoy_wordpress,
    "xmlrpc": _decoy_generic,
    "admin_panel": _decoy_admin_panel,
    "debug": _decoy_debug,
    "aws": _decoy_aws,
    "ssh_key": _decoy_ssh_key,
    "credentials": _decoy_credentials,
    "webshell": _decoy_generic,
    "cgi": _decoy_generic,
    "php_exploit": _decoy_generic,
    "generic": _decoy_generic,
}
