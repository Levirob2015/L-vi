/* Sendestudio - Oberflaeche. Ohne Bibliotheken, ohne Build-Schritt. */
(function () {
  "use strict";

  var ARTEN = { podcast: "Podcast", radio: "Radio", doku: "Dokumentation" };
  var zustand = { status: null, sendungen: [], aktiv: null };
  var $ = function (sel, wurzel) { return (wurzel || document).querySelector(sel); };

  // ------------------------------------------------------------------
  // Hilfen
  // ------------------------------------------------------------------
  function el(tag, attrs) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "class") e.className = attrs[k];
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== null && attrs[k] !== undefined && attrs[k] !== false) e.setAttribute(k, attrs[k]);
    });
    for (var i = 2; i < arguments.length; i++) {
      var kind = arguments[i];
      if (kind == null) continue;
      e.appendChild(typeof kind === "string" ? document.createTextNode(kind) : kind);
    }
    return e;
  }

  function vorlage(id) {
    var frag = document.getElementById(id).content.cloneNode(true);
    var felder = {};
    frag.querySelectorAll("[data-feld]").forEach(function (n) { felder[n.getAttribute("data-feld")] = n; });
    felder.wurzel = frag.firstElementChild;
    return felder;
  }

  function zeit(s) {
    s = Math.max(0, Math.floor(s || 0));
    var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sek = s % 60;
    return h + ":" + String(m).padStart(2, "0") + ":" + String(sek).padStart(2, "0");
  }

  function zeitLesen(text) {
    var teile = String(text).trim().split(":").map(Number);
    if (teile.some(isNaN)) return NaN;
    return teile.reduce(function (a, b) { return a * 60 + b; }, 0);
  }

  function datum(ts) {
    return ts ? new Date(ts * 1000).toLocaleDateString("de-DE", { day: "numeric", month: "long", year: "numeric" }) : "";
  }

  var toastUhr;
  function melden(text, fehler) {
    var t = $("#toast");
    t.textContent = text;
    t.className = "toast" + (fehler ? " fehler" : "");
    t.hidden = false;
    clearTimeout(toastUhr);
    toastUhr = setTimeout(function () { t.hidden = true; }, fehler ? 6000 : 3000);
  }

  function api(methode, pfad, daten) {
    var opt = { method: methode, headers: { "X-Studio": "1" }, credentials: "same-origin" };
    if (daten !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(daten);
    }
    return fetch("/api/" + pfad, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if ((r.status === 401 || r.status === 423) && pfad !== "login") { zeigeLogin(); }
        if (!r.ok) throw new Error(j.fehler || ("Fehler " + r.status));
        return j;
      });
    });
  }

  // Upload mit Fortschrittsanzeige - fetch kann das (noch) nicht.
  function hochladen(pfad, datei, balken) {
    return new Promise(function (ok, fehler) {
      var x = new XMLHttpRequest();
      x.open("PUT", "/api/" + pfad);
      x.setRequestHeader("X-Studio", "1");
      if (datei.type) x.setRequestHeader("Content-Type", datei.type);
      if (balken) {
        balken.hidden = false;
        x.upload.onprogress = function (e) {
          if (!e.lengthComputable) return;
          var p = Math.round(e.loaded / e.total * 100);
          balken.firstElementChild.style.width = p + "%";
          balken.lastElementChild.textContent = p < 100 ? "Hochladen … " + p + " %" : "Wird aufbereitet …";
        };
      }
      x.onload = function () {
        var j = {};
        try { j = JSON.parse(x.responseText); } catch (e) {}
        if (balken) balken.hidden = true;
        if (x.status >= 200 && x.status < 300) ok(j);
        else fehler(new Error(j.fehler || ("Fehler " + x.status)));
      };
      x.onerror = function () { if (balken) balken.hidden = true; fehler(new Error("Verbindung unterbrochen")); };
      x.send(datei);
    });
  }

  function mediumUrl(name) { return "/medien/" + encodeURIComponent(name); }

  function player(folge) {
    var tag = folge.mime.indexOf("video/") === 0 ? "video" : "audio";
    return el(tag, { controls: "", preload: "metadata", src: mediumUrl(folge.datei) });
  }

  // ------------------------------------------------------------------
  // Anmeldung
  // ------------------------------------------------------------------
  function zeigeLogin() {
    stoppeAufnahme();
    // Nichts Unveroeffentlichtes auf dem Bildschirm stehen lassen.
    $("#inhalt").textContent = "";
    $("#sendungsliste").textContent = "";
    $("#app").hidden = true;
    $("#login").hidden = false;
    var zf = zustand.status && zustand.status.zweifaktor;
    $("#login-code-zeile").hidden = !zf;
    $("#login-code").required = !!zf;
    $("#login-passwort").focus();
  }

  $("#login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("#login-fehler").textContent = "";
    api("POST", "login", { passwort: $("#login-passwort").value, code: $("#login-code").value })
      .then(function () { $("#login-passwort").value = ""; $("#login-code").value = ""; start(); })
      .catch(function (f) { $("#login-code").value = ""; $("#login-fehler").textContent = f.message; });
  });

  // Wer weggeht, wird auch im Browser abgemeldet - wie auf dem Server.
  var letzteAktivitaet = Date.now();
  ["pointerdown", "keydown"].forEach(function (art) {
    document.addEventListener(art, function () { letzteAktivitaet = Date.now(); }, true);
  });
  setInterval(function () {
    var st = zustand.status;
    if (!st || $("#app").hidden || (rec && rec.recorder && rec.recorder.state === "recording")) return;
    if (Date.now() - letzteAktivitaet > st.leerlauf_minuten * 60000) {
      api("POST", "logout", {}).catch(function () {}).then(zeigeLogin);
    }
  }, 30000);

  $("#knopf-abmelden").addEventListener("click", function () {
    api("POST", "logout", {}).then(zeigeLogin);
  });

  function start() {
    api("GET", "status").then(function (s) {
      zustand.status = s;
      if (!s.angemeldet) return zeigeLogin();
      $("#login").hidden = true;
      $("#app").hidden = false;
      $("#tresor-anzeige").hidden = !s.tresor;
      letzteAktivitaet = Date.now();
      return ladeSendungen().then(function () {
        if (zustand.sendungen.length) zeigeSendung(zustand.aktiv || zustand.sendungen[0].id);
        else zeigeWillkommen();
      });
    }).catch(function (f) { melden(f.message, true); });
  }

  // ------------------------------------------------------------------
  // Sendungen
  // ------------------------------------------------------------------
  function ladeSendungen() {
    return api("GET", "sendungen").then(function (liste) {
      zustand.sendungen = liste;
      var ul = $("#sendungsliste");
      ul.textContent = "";
      liste.forEach(function (s) {
        ul.appendChild(el("li", {},
          el("button", { class: s.id === zustand.aktiv ? "aktiv" : "", onclick: function () { zeigeSendung(s.id); } },
            s.titel,
            el("small", { text: ARTEN[s.art] + " · " + s.folgen_online + " online" +
              (s.folgen_gesamt > s.folgen_online ? ", " + (s.folgen_gesamt - s.folgen_online) + " Entwurf" : "") }))));
      });
    });
  }

  function inhalt(knoten) {
    stoppeAufnahme();
    var ziel = $("#inhalt");
    ziel.textContent = "";
    ziel.appendChild(knoten);
    window.scrollTo(0, 0);
  }

  function zeigeWillkommen() {
    var v = vorlage("t-willkommen");
    $("[data-aktion=neue-sendung]", v.wurzel).addEventListener("click", function () { zeigeSendungsForm(null); });
    inhalt(v.wurzel);
  }

  $("#knopf-neue-sendung").addEventListener("click", function () { zeigeSendungsForm(null); });

  function zeigeSendungsForm(s) {
    var v = vorlage("t-sendung-form");
    var f = v.form;
    if (s) {
      v.ueberschrift.textContent = "Einstellungen: " + s.titel;
      ["titel", "beschreibung", "autor", "sprache", "kategorie"].forEach(function (k) { f.elements[k].value = s[k]; });
      f.querySelector("input[name=art][value=" + s.art + "]").checked = true;
      v["cover-bereich"].hidden = false;
      if (s.cover) v["cover-bild"].src = mediumUrl(s.cover); else v["cover-bild"].hidden = true;
      v["cover-datei"].addEventListener("change", function () {
        var d = this.files[0];
        if (!d) return;
        hochladen("sendungen/" + s.id + "/cover", d).then(function (neu) {
          v["cover-bild"].src = mediumUrl(neu.cover);
          v["cover-bild"].hidden = false;
          melden("Cover gespeichert");
        }).catch(function (e) { melden(e.message, true); });
      });
      $("[data-aktion=sendung-loeschen]", v.wurzel).addEventListener("click", function () {
        if (!confirm("„" + s.titel + "“ mit allen Folgen und Dateien endgültig löschen?")) return;
        api("DELETE", "sendungen/" + s.id).then(function () {
          zustand.aktiv = null;
          melden("Gelöscht");
          start();
        }).catch(function (e) { melden(e.message, true); });
      });
    }
    $("[data-aktion=abbrechen]", v.wurzel).addEventListener("click", function () {
      if (s) zeigeSendung(s.id); else start();
    });
    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var daten = {};
      ["titel", "art", "beschreibung", "autor", "sprache", "kategorie"].forEach(function (k) { daten[k] = f.elements[k].value; });
      (s ? api("PUT", "sendungen/" + s.id, daten) : api("POST", "sendungen", daten)).then(function (neu) {
        melden(s ? "Gespeichert" : "Sendung angelegt");
        zustand.aktiv = neu.id;
        return ladeSendungen().then(function () {
          if (s) zeigeSendung(neu.id); else zeigeSendungsForm(neu);
        });
      }).catch(function (e) { melden(e.message, true); });
    });
    inhalt(v.wurzel);
  }

  function aktuelleSendung() {
    return zustand.sendungen.filter(function (s) { return s.id === zustand.aktiv; })[0];
  }

  function zeigeSendung(id) {
    zustand.aktiv = id;
    ladeSendungen().then(function () {
      var s = aktuelleSendung();
      if (!s) return zeigeWillkommen();
      return api("GET", "sendungen/" + id + "/folgen").then(function (folgen) {
        var v = vorlage("t-sendung");
        v.titel.textContent = s.titel;
        v.art.textContent = ARTEN[s.art];
        v.beschreibung.textContent = s.beschreibung;
        if (s.cover) v.cover.src = mediumUrl(s.cover);
        else v.cover.replaceWith(el("div", { class: "cover", "aria-hidden": "true" }));
        v.ansehen.href = "/s/" + s.slug + "/";
        v.ansehen.hidden = !s.folgen_online;
        $("[data-aktion=aufnehmen]", v.wurzel).addEventListener("click", function () { zeigeAufnahme(s, null); });
        $("[data-aktion=bearbeiten]", v.wurzel).addEventListener("click", function () { zeigeSendungsForm(s); });
        v.datei.addEventListener("change", function () {
          if (this.files[0]) zeigeAufnahme(s, this.files[0]);
        });
        if (!folgen.length) {
          v.folgen.appendChild(el("p", { class: "leise", text: "Noch keine Folgen – nimm die erste auf oder lade eine Datei hoch." }));
        }
        folgen.forEach(function (f) { v.folgen.appendChild(folgenKarte(s, f)); });
        inhalt(v.wurzel);
      });
    }).catch(function (e) { melden(e.message, true); });
  }

  function folgenKarte(s, f) {
    var info = [f.online ? datum(f.veroeffentlicht) : "angelegt " + datum(f.erstellt)];
    if (f.dauer) info.push(zeit(f.dauer));
    if (f.kapitel.length) info.push(f.kapitel.length + " Kapitel");
    if (f.mime.indexOf("video/") === 0) info.push("Video");
    if (!f.online && f.datei) info.push("🔒 verschlüsselt");
    var karte = el("div", { class: "karte folge" },
      el("div", {},
        el("span", { class: "etikett " + (f.online ? "online" : "entwurf"), text: f.online ? "Online" : "Entwurf" }),
        el("h3", { text: f.titel }),
        el("div", { class: "leise klein", text: info.join(" · ") + (f.datei ? "" : " · ohne Aufnahme") })));
    var knoepfe = el("div", { class: "knoepfe" });
    if (f.datei) {
      knoepfe.appendChild(el("button", { class: "knopf klein", text: "▶ Anhören", onclick: function () {
        if (!$("audio, video", karte)) karte.appendChild(player(f));
        $("audio, video", karte).play();
      } }));
    }
    knoepfe.appendChild(el("button", { class: "knopf klein leicht", text: "Bearbeiten", onclick: function () { zeigeFolge(s, f); } }));
    if (f.online) {
      knoepfe.appendChild(el("a", { class: "knopf klein leicht", href: "/s/" + s.slug + "/" + f.slug + "/", target: "_blank", rel: "noopener", text: "Ansehen ↗" }));
      knoepfe.appendChild(el("button", { class: "knopf klein leicht", text: "Zurückziehen", onclick: function () {
        api("POST", "folgen/" + f.id + "/zurueckziehen").then(function () { melden("Offline genommen"); zeigeSendung(s.id); })
          .catch(function (e) { melden(e.message, true); });
      } }));
    } else if (f.datei) {
      knoepfe.appendChild(el("button", { class: "knopf klein primaer", text: "Veröffentlichen", onclick: function () {
        api("POST", "folgen/" + f.id + "/veroeffentlichen").then(function () { melden("Ist online!"); zeigeSendung(s.id); })
          .catch(function (e) { melden(e.message, true); });
      } }));
    }
    knoepfe.appendChild(el("button", { class: "knopf klein gefahr", text: "Löschen", onclick: function () {
      if (!confirm("Folge „" + f.titel + "“ endgültig löschen?")) return;
      api("DELETE", "folgen/" + f.id).then(function () { melden("Gelöscht"); zeigeSendung(s.id); })
        .catch(function (e) { melden(e.message, true); });
    } }));
    karte.appendChild(knoepfe);
    return karte;
  }

  // ------------------------------------------------------------------
  // Kapitel-Editor (Aufnahme und Bearbeiten)
  // ------------------------------------------------------------------
  function kapitelEditor(behaelter, liste) {
    function malen() {
      behaelter.textContent = "";
      if (!liste.length) behaelter.appendChild(el("p", { class: "leise klein", text: "Keine Kapitel." }));
      liste.forEach(function (k, i) {
        var zeitFeld = el("input", { value: zeit(k.zeit), "aria-label": "Startzeit", onchange: function () {
          var w = zeitLesen(this.value);
          if (isNaN(w)) { melden("Zeit bitte als h:mm:ss", true); this.value = zeit(k.zeit); return; }
          k.zeit = w;
        } });
        var titelFeld = el("input", { value: k.titel, "aria-label": "Kapiteltitel", maxlength: "200",
          oninput: function () { k.titel = this.value; } });
        behaelter.appendChild(el("div", { class: "kapitel-zeile" }, zeitFeld, titelFeld,
          el("button", { type: "button", class: "knopf klein leicht", "aria-label": "Kapitel entfernen", text: "✕",
            onclick: function () { liste.splice(i, 1); malen(); } })));
      });
    }
    malen();
    return {
      neu: function (t, titel) { liste.push({ zeit: t || 0, titel: titel || "Kapitel " + (liste.length + 1) }); malen(); },
      liste: function () {
        return liste.slice().sort(function (a, b) { return a.zeit - b.zeit; });
      },
    };
  }

  // ------------------------------------------------------------------
  // Aufnahme
  // ------------------------------------------------------------------
  var rec = null; // laufende Studio-Sitzung

  function stoppeAufnahme() {
    if (!rec) return;
    try { if (rec.recorder && rec.recorder.state !== "inactive") rec.recorder.stop(); } catch (e) {}
    rec.streams.forEach(function (s) { s.getTracks().forEach(function (t) { t.stop(); }); });
    if (rec.ctx) rec.ctx.close();
    cancelAnimationFrame(rec.pegelUhr);
    clearInterval(rec.uhrUhr);
    $("#onair").classList.remove("an");
    rec = null;
  }

  function passendesFormat(video) {
    var kandidaten = video
      ? ["video/webm;codecs=vp9,opus", "video/webm;codecs=vp8,opus", "video/webm", "video/mp4"]
      : ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4", "audio/webm"];
    for (var i = 0; i < kandidaten.length; i++) {
      if (window.MediaRecorder && MediaRecorder.isTypeSupported(kandidaten[i])) return kandidaten[i];
    }
    return "";
  }

  function zeigeAufnahme(s, datei) {
    var v = vorlage("t-aufnahme");
    var kapitel = kapitelEditor(v.kapitel, []);
    var ergebnis = null; // { blob, dauer }

    $("[data-aktion=zurueck]", v.wurzel).addEventListener("click", function (e) { e.preventDefault(); zeigeSendung(s.id); });
    $("[data-aktion=kapitel-neu]", v.wurzel).addEventListener("click", function () { kapitel.neu(0); });
    $("[data-aktion=verwerfen]", v.wurzel).addEventListener("click", function () {
      if (confirm("Aufnahme verwerfen?")) zeigeSendung(s.id);
    });
    if (!zustand.status.ffmpeg) {
      v["normalisieren-zeile"].hidden = true;
    }

    function fertig(blob, dauer, name) {
      ergebnis = { blob: blob, dauer: dauer };
      v.vorbereitung.hidden = true;
      v.fertig.hidden = false;
      v.details.hidden = false;
      var url = URL.createObjectURL(blob);
      var istVideo = (blob.type || "").indexOf("video/") === 0;
      var p = el(istVideo ? "video" : "audio", { controls: "", src: url });
      p.addEventListener("loadedmetadata", function () {
        if (isFinite(p.duration) && p.duration > 0) ergebnis.dauer = p.duration;
      });
      v.abspieler.textContent = "";
      v.abspieler.appendChild(p);
      if (name && !v.form.elements.titel.value) v.form.elements.titel.value = name.replace(/\.[^.]+$/, "");
      v.form.elements.titel.focus();
    }

    if (datei) {
      v.pult.hidden = true;
      fertig(datei, 0, datei.name);
    } else {
      // Mikrofone auflisten (Namen gibt es erst nach der Erlaubnis).
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        navigator.mediaDevices.enumerateDevices().then(function (geraete) {
          geraete.filter(function (g) { return g.kind === "audioinput" && g.deviceId && g.deviceId !== "default"; })
            .forEach(function (g, i) { v.mikro.appendChild(el("option", { value: g.deviceId, text: g.label || "Mikrofon " + (i + 1) })); });
        });
      }
      $("[data-aktion=vorbereiten]", v.wurzel).addEventListener("click", function () {
        einschalten(v, kapitel, fertig).catch(function (e) {
          stoppeAufnahme();
          melden(e.name === "NotAllowedError" ? "Zugriff verweigert – bitte im Browser erlauben." :
            (!window.isSecureContext ? "Aufnahme braucht HTTPS (oder localhost)." : e.message), true);
        });
      });
    }

    v.form.addEventListener("submit", function (e) {
      e.preventDefault();
      var modus = e.submitter ? e.submitter.getAttribute("data-modus") : "entwurf";
      var knoepfe = v.form.querySelectorAll("button");
      knoepfe.forEach(function (b) { b.disabled = true; });
      var normalisieren = zustand.status.ffmpeg && v.form.elements.normalisieren.checked ? 1 : 0;
      var folge, hochgeladen = false;
      api("POST", "sendungen/" + s.id + "/folgen", {
        titel: v.form.elements.titel.value,
        beschreibung: v.form.elements.beschreibung.value,
        kapitel: kapitel.liste(),
      }).then(function (f) {
        folge = f;
        return hochladen("folgen/" + f.id + "/medium?normalisieren=" + normalisieren +
          "&dauer=" + encodeURIComponent(ergebnis.dauer || 0), ergebnis.blob, v.fortschritt);
      }).then(function () {
        hochgeladen = true;
        if (modus === "online") return api("POST", "folgen/" + folge.id + "/veroeffentlichen");
      }).then(function () {
        melden(modus === "online" ? "Ist online!" : "Als Entwurf gespeichert");
        zeigeSendung(s.id);
      }).catch(function (fehler) {
        melden(fehler.message, true);
        // Gespeichert ist sie - nur das Veroeffentlichen ging schief.
        if (hochgeladen) return zeigeSendung(s.id);
        knoepfe.forEach(function (b) { b.disabled = false; });
        // Die angelegte Folge ohne Datei nicht als Leiche stehen lassen.
        if (folge && !hochgeladen) api("DELETE", "folgen/" + folge.id).catch(function () {});
      });
    });

    inhalt(v.wurzel);
  }

  function einschalten(v, kapitel, fertig) {
    var quelle = v.quelle.value;
    var mikroWahl = v.mikro.value ? { deviceId: { exact: v.mikro.value } } : true;
    var audioOpt = mikroWahl === true ? { echoCancellation: false, noiseSuppression: true, autoGainControl: false }
      : Object.assign({ echoCancellation: false, noiseSuppression: true, autoGainControl: false }, mikroWahl);
    if (!navigator.mediaDevices || !window.MediaRecorder) {
      return Promise.reject(new Error("Dieser Browser kann nicht aufnehmen."));
    }
    stoppeAufnahme();
    rec = { streams: [], chunks: [], pads: [] };
    var r = rec;

    var holen;
    if (quelle === "kamera") {
      holen = navigator.mediaDevices.getUserMedia({ audio: audioOpt, video: { width: { ideal: 1920 }, height: { ideal: 1080 } } })
        .then(function (st) { r.streams.push(st); return { mikro: st, video: st.getVideoTracks()[0] }; });
    } else if (quelle === "bildschirm") {
      holen = navigator.mediaDevices.getDisplayMedia({ video: true, audio: false }).then(function (bild) {
        r.streams.push(bild);
        return navigator.mediaDevices.getUserMedia({ audio: audioOpt }).then(function (st) {
          r.streams.push(st);
          return { mikro: st, video: bild.getVideoTracks()[0] };
        });
      });
    } else {
      holen = navigator.mediaDevices.getUserMedia({ audio: audioOpt })
        .then(function (st) { r.streams.push(st); return { mikro: st, video: null }; });
    }

    return holen.then(function (q) {
      if (rec !== r) return;
      // Mischpult: Mikrofon + Jingles -> eine Tonspur
      var ctx = r.ctx = new (window.AudioContext || window.webkitAudioContext)();
      var ziel = ctx.createMediaStreamDestination();
      var mikroGain = ctx.createGain();
      var jingleGain = ctx.createGain();
      jingleGain.gain.value = parseFloat(v["jingle-lautstaerke"].value);
      var analyse = ctx.createAnalyser();
      analyse.fftSize = 1024;
      ctx.createMediaStreamSource(q.mikro).connect(mikroGain);
      mikroGain.connect(ziel);
      mikroGain.connect(analyse);
      jingleGain.connect(ziel);
      jingleGain.connect(analyse);
      jingleGain.connect(ctx.destination); // zum Mithören
      r.jingleGain = jingleGain;

      v["mikro-lautstaerke"].addEventListener("input", function () { mikroGain.gain.value = parseFloat(this.value); });
      v["jingle-lautstaerke"].addEventListener("input", function () { jingleGain.gain.value = parseFloat(this.value); });

      var spuren = ziel.stream.getAudioTracks().slice();
      if (q.video) {
        spuren.unshift(q.video);
        v.vorschau.srcObject = new MediaStream([q.video]);
        v.vorschau.hidden = false;
        v.vorschau.play();
        // Bildschirmfreigabe ueber die Browserleiste beendet = Aufnahme Ende
        q.video.addEventListener("ended", function () { if (r.recorder && r.recorder.state !== "inactive") r.recorder.stop(); });
      }
      var format = passendesFormat(!!q.video);
      r.recorder = new MediaRecorder(new MediaStream(spuren), format ? { mimeType: format, audioBitsPerSecond: 160000 } : undefined);
      r.recorder.ondataavailable = function (e) { if (e.data.size) r.chunks.push(e.data); };
      r.recorder.onstop = function () {
        var dauer = r.vergangen();
        var blob = new Blob(r.chunks, { type: (r.recorder.mimeType || format || "audio/webm").split(";")[0] });
        stoppeAufnahme();
        fertig(blob, dauer, "");
      };

      // Uhr: zaehlt nur, solange wirklich aufgenommen wird.
      var summe = 0, seit = null;
      r.vergangen = function () { return summe + (seit ? (performance.now() - seit) / 1000 : 0); };
      r.uhrUhr = setInterval(function () { v.uhr.textContent = zeit(r.vergangen()); }, 250);

      // Pegelanzeige
      var puffer = new Float32Array(analyse.fftSize);
      (function pegel() {
        analyse.getFloatTimeDomainData(puffer);
        var spitze = 0;
        for (var i = 0; i < puffer.length; i++) spitze = Math.max(spitze, Math.abs(puffer[i]));
        var db = 20 * Math.log10(spitze || 1e-6);
        v.pegel.style.width = Math.max(0, Math.min(100, (db + 60) / 60 * 100)) + "%";
        r.pegelUhr = requestAnimationFrame(pegel);
      })();

      var start = $("[data-aktion=start]", v.pult), pause = $("[data-aktion=pause]", v.pult),
        stopp = $("[data-aktion=stopp]", v.pult), marke = $("[data-aktion=marke]", v.pult);
      start.addEventListener("click", function () {
        r.recorder.start(1000);
        seit = performance.now();
        start.disabled = true; pause.disabled = false; stopp.disabled = false; marke.disabled = false;
        v.zustand.textContent = "Aufnahme läuft";
        $("#onair").classList.add("an");
        kapitel.neu(0, "Anfang");
      });
      pause.addEventListener("click", function () {
        if (r.recorder.state === "recording") {
          r.recorder.pause(); summe = r.vergangen(); seit = null;
          pause.textContent = "Weiter"; v.zustand.textContent = "Pausiert";
          $("#onair").classList.remove("an");
        } else {
          r.recorder.resume(); seit = performance.now();
          pause.textContent = "Pause"; v.zustand.textContent = "Aufnahme läuft";
          $("#onair").classList.add("an");
        }
      });
      stopp.addEventListener("click", function () {
        summe = r.vergangen(); seit = null;
        v.zustand.textContent = "Wird abgeschlossen …";
        r.recorder.stop();
      });
      marke.addEventListener("click", function () {
        kapitel.neu(Math.round(r.vergangen() * 10) / 10);
        v.details.hidden = false;
        melden("Kapitelmarke bei " + zeit(r.vergangen()));
      });

      jinglePads(v.pads, r, ctx);
      v.vorbereitung.hidden = true;
      v.pult.hidden = false;
      v.details.hidden = false;
    });
  }

  function jinglePads(behaelter, r, ctx) {
    for (var i = 0; i < 6; i++) (function (nr) {
      var pad = { puffer: null, quelle: null };
      var knopf = el("button", { class: "spielen", disabled: "", text: "Pad " + nr });
      var eingabe = el("input", { type: "file", accept: "audio/*", hidden: "" });
      var label = el("label", {}, "Datei laden", eingabe);
      eingabe.addEventListener("change", function () {
        var d = this.files[0];
        if (!d) return;
        d.arrayBuffer().then(function (b) { return ctx.decodeAudioData(b); }).then(function (puffer) {
          pad.puffer = puffer;
          knopf.textContent = d.name.replace(/\.[^.]+$/, "");
          knopf.title = d.name;
          knopf.disabled = false;
        }).catch(function () { melden("Diese Datei kann der Browser nicht lesen.", true); });
      });
      knopf.addEventListener("click", function () {
        if (pad.quelle) { pad.quelle.stop(); return; }
        if (ctx.state === "suspended") ctx.resume();
        var q = ctx.createBufferSource();
        q.buffer = pad.puffer;
        q.connect(r.jingleGain);
        q.onended = function () { pad.quelle = null; knopf.classList.remove("laeuft"); };
        q.start();
        pad.quelle = q;
        knopf.classList.add("laeuft");
      });
      behaelter.appendChild(el("div", { class: "pad" }, knopf, label));
    })(i + 1);
  }

  // ------------------------------------------------------------------
  // Folge bearbeiten
  // ------------------------------------------------------------------
  function zeigeFolge(s, f) {
    var v = vorlage("t-folge");
    var kapitel = kapitelEditor(v.kapitel, f.kapitel.slice());
    var p = f.datei ? player(f) : null;
    if (p) v.abspieler.appendChild(p);
    v.form.elements.titel.value = f.titel;
    v.form.elements.beschreibung.value = f.beschreibung;
    $("[data-aktion=zurueck]", v.wurzel).addEventListener("click", function (e) { e.preventDefault(); zeigeSendung(s.id); });
    $("[data-aktion=kapitel-neu]", v.wurzel).addEventListener("click", function () { kapitel.neu(0); });
    $("[data-aktion=kapitel-hier]", v.wurzel).addEventListener("click", function () {
      kapitel.neu(p ? Math.round(p.currentTime * 10) / 10 : 0);
    });
    v.form.addEventListener("submit", function (e) {
      e.preventDefault();
      api("PUT", "folgen/" + f.id, {
        titel: v.form.elements.titel.value,
        beschreibung: v.form.elements.beschreibung.value,
        kapitel: kapitel.liste(),
      }).then(function () { melden("Gespeichert"); zeigeSendung(s.id); })
        .catch(function (e) { melden(e.message, true); });
    });
    v.datei.addEventListener("change", function () {
      var d = this.files[0];
      if (!d) return;
      if (!confirm("Aufnahme durch „" + d.name + "“ ersetzen?")) return;
      hochladen("folgen/" + f.id + "/medium?normalisieren=0", d, v.fortschritt).then(function (neu) {
        melden("Aufnahme ersetzt");
        zeigeFolge(s, neu);
      }).catch(function (e) { melden(e.message, true); });
    });
    inhalt(v.wurzel);
  }

  // ------------------------------------------------------------------
  // Ins Netz stellen
  // ------------------------------------------------------------------
  $("#knopf-netz").addEventListener("click", function () {
    var st = zustand.status;
    var dl = $("#netz-adressen");
    dl.textContent = "";
    var basis = st.basis_url || location.origin;
    dl.appendChild(el("dt", { text: "Startseite" }));
    dl.appendChild(el("dd", {}, el("a", { href: "/", target: "_blank", rel: "noopener", text: basis + "/" })));
    var s = aktuelleSendung();
    if (s && s.folgen_online) {
      dl.appendChild(el("dt", { text: "Sendung" }));
      dl.appendChild(el("dd", {}, el("a", { href: "/s/" + s.slug + "/", target: "_blank", rel: "noopener", text: basis + "/s/" + s.slug + "/" })));
      dl.appendChild(el("dt", { text: "Podcast-Feed" }));
      dl.appendChild(el("dd", { text: basis + "/s/" + s.slug + "/feed.xml" }));
      if (s.art === "radio") {
        dl.appendChild(el("dt", { text: "Radio live" }));
        dl.appendChild(el("dd", {}, el("a", { href: "/s/" + s.slug + "/radio/", target: "_blank", rel: "noopener", text: basis + "/s/" + s.slug + "/radio/" })));
      }
    }
    $("#knopf-ftp").hidden = !st.ftp;
    $("#netz-ergebnis").textContent = "Export-Ordner: " + st.export_ziel;
    $("#netz").showModal();
  });

  function exportAktion(pfad, knopf) {
    knopf.disabled = true;
    $("#netz-ergebnis").textContent = "Läuft …";
    api("POST", pfad, {}).then(function (e) {
      var t = e.dateien + " Dateien in " + e.ziel + " (" + e.geschrieben + " Seiten neu, " + e.medien_kopiert + " Medien kopiert).";
      if (e.hochgeladen !== undefined) t += " FTP: " + e.hochgeladen + " hochgeladen, " + e.uebersprungen + " unverändert.";
      if (e.ohne_feed) t += " Hinweis: Ohne „basis_url“ in der Konfiguration gibt es keinen Podcast-Feed.";
      $("#netz-ergebnis").textContent = t;
    }).catch(function (f) {
      $("#netz-ergebnis").textContent = f.message;
    }).then(function () { knopf.disabled = false; });
  }
  $("#knopf-export").addEventListener("click", function () { exportAktion("export", this); });
  $("#knopf-ftp").addEventListener("click", function () { exportAktion("ftp", this); });

  window.addEventListener("beforeunload", function (e) {
    if (rec && rec.recorder && rec.recorder.state !== "inactive") { e.preventDefault(); e.returnValue = ""; }
  });

  start();
})();
