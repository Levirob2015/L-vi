"""Sendestudio - Podcasts, Radio und Dokumentationen aufnehmen und ins Netz stellen.

Kurzform::

    sendestudio init      # Konfiguration + Passwort anlegen
    sendestudio serve     # Studio auf http://127.0.0.1:8790/studio

Drei Arten von Sendungen:

* **Podcast** - Folgen mit RSS-Feed, abonnierbar in jeder Podcast-App.
* **Radio** - die veroeffentlichten Folgen laufen als Endlosprogramm nach
  der Uhr: Wer einschaltet, hoert dasselbe wie alle anderen.
* **Dokumentation** - wie ein Podcast, aber auch mit Video (Kamera oder
  Bildschirm).
"""

from .store import ARTEN, Store, slugify
from .version import __version__

__all__ = ["ARTEN", "Store", "slugify", "__version__"]
