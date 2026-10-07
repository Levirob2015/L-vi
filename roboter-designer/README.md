# ProBot

Eine einzelne HTML-Seite: Roboter beschreiben → die KI (Claude) liefert Zeichnung, Teileliste mit Kosten, Werkzeug, Bauanleitung und fertigen Code.
Der Code steht in einem bearbeitbaren Feld (kopieren, herunterladen, oder per Wunsch von der KI ändern lassen).

## Starten
`index.html` im Browser öffnen (oder z.B. `python3 -m http.server` im Ordner und http://localhost:8000 aufrufen).
Einen Anthropic API-Key eingeben (console.anthropic.com) – er wird nur lokal im Browser gespeichert.

## Neu: 3D-Druckteile, Anleitung, Test-Labor
- **3D-Druckteile:** Die KI konstruiert passende Teile (Chassis, Halter …). Vorschau im Browser, Download als **STL** (direkt in den Slicer) oder **.scad** (in OpenSCAD genau anpassen).
- **Anleitung:** Einkaufsliste, Druckeinstellungen, Verkabelung, Zusammenbau, Tipps – als .md herunterladbar.
- **Test-Labor:** Die KI simuliert den Code in einer Test-Situation (serieller Monitor, Verhalten, Prüfung von Pins/Strom/Logik).
- **Elegoo-Drucker:** Neptune 4 / 4 Plus / 4 Max / 3 Pro, Centauri Carbon (ElegooSlicer) sowie Mars 5 / Saturn 4 Resin (CHITUBOX) und Centauri Carbon 2 mit CANVAS (4 Farben: STL je Farbe). Die KI konstruiert passend zum Bauraum, jedes Teil zeigt an, ob es aufs Druckbett passt.
- **Demo-Roboter:** Funktioniert ganz ohne KI/Schlüssel zum Ausprobieren.

## ProBot-KI (gratis, ohne Anmeldung)
Standard-KI der Seite. Läuft komplett im Browser: Wissensbasis mit Bauteilen und Preisen, Pin-Belegungen,
Code-Bausteinen, 3D-Teilen und Anleitungen für 17 Roboter-Arten (Hindernis-Ausweicher, Linienfolger, Sumo, Labyrinth-Löser, Laufroboter, Pflanzen-Gießroboter, Licht-Sucher, Mars-Rover, Wach-Roboter, Mal-Roboter, Farb-Sortierer, Sonnen-Folger, Mini-Staubsauger,
Bluetooth-Auto, Greifarm, Mini-Schwarm, Haustier) plus Extras. Die Beschreibung wird per Stichworten
verstanden; optional lädt die Seite eine kleine Sprach-KI (Qwen2.5 1.5B über WebLLM, braucht WebGPU),
die freie Beschreibungen besser versteht. Claude bleibt als Option für freie Ideen.
