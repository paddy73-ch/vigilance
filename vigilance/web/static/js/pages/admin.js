document.addEventListener("alpine:init", () => {
  const ABOUT = {
    osv: "Hauptquelle über osv.dev: Pakete von Debian, Ubuntu und Alpine sowie Go-Module.",
    ghsa: "GitHub-Advisories für Pakete aus pip, npm, Go und Co., nicht für Debian-Pakete.",
    tailscale: "Security Bulletins von Tailscale; nur abgefragt, wenn tailscale installiert ist.",
    nvd: "Allgemeine CVE-Datenbank ohne Debian-Versionen, daher ungenauer.",
    debian: "Direkt vom Debian Security Tracker; meist dieselben Lücken wie OSV, sie werden zusammengeführt.",
    ubuntu: "Ubuntu Security Tracker, für Container mit Ubuntu.",
  };
  const NAMES = { osv: "OSV", ghsa: "GitHub Advisories", tailscale: "Tailscale Security Bulletins", nvd: "NVD", debian: "Debian Security Tracker", ubuntu: "Ubuntu" };

  Alpine.data("sourcesPage", () => ({
    sources: [], busy: false, switching: null,
    async init() { await this.load(); },
    async load() {
      try {
        this.sources = await V.api("/api/cve-sources");
        if (this.sources.some((s) => s.enabled && s.status === "running")) setTimeout(() => this.load(), 4000);
      } catch (e) { V.toast("Quellen nicht geladen: " + e.message, true); }
    },
    name(s) { return NAMES[s] || s; },
    about(s) { return ABOUT[s] || ""; },
    async toggle(s, ev) {
      const on = ev.target.checked;
      if (!on && s.source === "osv" && !confirm("OSV ist die Hauptquelle für Debian-Pakete. Ohne OSV verschwinden fast alle Befunde. Trotzdem ausschalten?")) {
        ev.target.checked = true;
        return;
      }
      this.switching = s.source;
      try {
        const r = await V.api("/api/cve-sources/" + s.source, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: on }) });
        V.toast(on ? this.name(s.source) + " eingeschaltet" + (r.restored ? ", " + V.plural(r.restored, "Befund", "Befunde") + " zurückgeholt" : "") + ". Abgleich läuft."
                   : this.name(s.source) + " ausgeschaltet" + (r.hidden ? ", " + V.plural(r.hidden, "Befund", "Befunde") + " ausgeblendet" : "") + ".");
        await this.load();
        if (on) setTimeout(() => this.load(), 3000);
      } catch (e) {
        ev.target.checked = !on;
        if (!e.cancelled) V.toast("Nicht umgeschaltet: " + e.message, true);
      } finally { this.switching = null; }
    },
    stateText(s) { return { success: "OK", running: "Läuft", error: "Fehler", skipped: "Nicht nötig" }[s.status] || "Noch nicht gelaufen"; },
    tagClass(s) { return { success: "tag-ok", error: "tag-crit", running: "tag-upgrade" }[s.status] || ""; },
    async sync() {
      this.busy = true;
      try {
        await V.api("/api/cves/sync", { method: "POST" });
        V.toast("Abgleich gestartet.");
        setTimeout(() => this.load(), 1500);
      } catch (e) { if (!e.cancelled) V.toast("Abgleich nicht gestartet: " + e.message, true); }
      finally { this.busy = false; }
    },
  }));

  Alpine.data("exceptionsPage", () => ({
    list: null,
    async init() { await this.load(); },
    async load() {
      try { this.list = await V.api("/api/exceptions"); } catch (e) { V.toast("Ausnahmen nicht geladen: " + e.message, true); }
    },
    async remove(e) {
      if (!confirm("Ausnahme für " + e.cve_id + " aufheben? Die Befunde erscheinen wieder als offen.")) return;
      try {
        const r = await V.api("/api/exceptions/" + e.id, { method: "DELETE" });
        V.toast("Ausnahme aufgehoben. " + V.plural(r.changed_findings, "Befund ist", "Befunde sind") + " wieder offen.");
        await this.load();
      } catch (err) { if (!err.cancelled) V.toast("Nicht aufgehoben: " + err.message, true); }
    },
  }));


  // Zeitplan für Scan / CVE-Abgleich: Intervall oder feste Uhrzeiten, Uhrzeit mit analoger Uhr
  const DIAL = 260, OUTER = 104, INNER = 68;
  const pad = (n) => String(n).padStart(2, "0");
  const scheduleMixin = () => ({
    DAYS: ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"],
    sched: { kind: null, mode: "interval", hours: 24, times: [], days: [], timezone: "", error: "", saving: false },
    clock: { open: false, step: "h", h: 3, m: 0, index: -1, drag: false },
    pad,
    kindName(kind) { return kind === "scan" ? "den Scan" : "den CVE-Abgleich"; },
    fixed(kind) { const x = this.s.schedules && this.s.schedules[kind]; return !!(x && x.mode === "times"); },
    daysText(days) {
      const d = (days || []).slice().sort();
      if (!d.length || d.length === 7) return "täglich";
      if (d.join() === "0,1,2,3,4") return "Mo–Fr";
      if (d.join() === "5,6") return "Sa, So";
      return d.map((i) => this.DAYS[i]).join(", ");
    },
    scheduleText(kind) {
      const x = this.s.schedules && this.s.schedules[kind];
      return x && x.mode === "times" ? this.daysText(x.days) + " " + x.times.join(", ") : "";
    },
    nextRunText(kind) {
      const iso = this.s.next_runs && this.s.next_runs[kind];
      if (!iso) return "";
      const d = new Date(iso);
      return "Nächster Lauf: " + d.toLocaleString("de-CH", { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
    },
    openSchedule(kind) {
      const x = (this.s.schedules && this.s.schedules[kind]) || {};
      const hours = kind === "scan" ? this.s.scan_interval_hours : this.s.cve_sync_interval_hours;
      const tz = x.timezone || (Intl.DateTimeFormat().resolvedOptions().timeZone || "Europe/Zurich");
      this.sched = { kind, mode: x.mode === "times" ? "times" : "interval", hours: hours || 24,
                     times: x.mode === "times" ? x.times.slice() : [], days: x.days && x.days.length ? x.days.slice() : [0, 1, 2, 3, 4, 5, 6],
                     timezone: tz, error: "", saving: false };
      this.clock.open = false;
    },
    closeSchedule() { this.sched.kind = null; this.clock.open = false; },
    escSchedule() { if (this.clock.open) this.clock.open = false; else this.closeSchedule(); },
    toggleDay(i) {
      const d = this.sched.days;
      const at = d.indexOf(i);
      if (at >= 0) { if (d.length > 1) d.splice(at, 1); } else d.push(i);
    },
    removeTime(i) { this.sched.times.splice(i, 1); },
    addTime() { this.openClock(-1, this.sched.times.length ? this.sched.times[this.sched.times.length - 1] : "03:00"); },
    editTime(i) { this.openClock(i, this.sched.times[i]); },
    openClock(index, t) {
      const [h, m] = t.split(":").map(Number);
      this.clock = { open: true, step: "h", h, m, index, drag: false };
      this.$nextTick(() => this.$refs.dial && this.$refs.dial.focus());
    },
    setStep(step) { this.clock.step = step; this.$nextTick(() => this.$refs.dial && this.$refs.dial.focus()); },
    clockOk() {
      const t = pad(this.clock.h) + ":" + pad(this.clock.m);
      const list = this.sched.times.filter((x, i) => i !== this.clock.index && x !== t);
      list.push(t);
      this.sched.times = list.sort();
      this.clock.open = false;
    },
    // Lage auf dem Zifferblatt: Winkel ab 12 Uhr im Uhrzeigersinn, Abstand vom Mittelpunkt
    polar(angle, r) {
      const a = (angle * Math.PI) / 180;
      return { x: DIAL / 2 + r * Math.sin(a), y: DIAL / 2 - r * Math.cos(a) };
    },
    current() {
      if (this.clock.step === "h") {
        const h = this.clock.h;
        return { angle: (h % 12) * 30, r: h === 0 || h > 12 ? INNER : OUTER };
      }
      return { angle: this.clock.m * 6, r: OUTER };
    },
    handStyle() { const c = this.current(); return { height: c.r + "px", transform: "rotate(" + c.angle + "deg)" }; },
    tipStyle() {
      const c = this.current();
      const p = this.polar(c.angle, c.r);
      const size = this.clock.step === "m" && this.clock.m % 5 ? 10 : 36;
      return { left: p.x - size / 2 + "px", top: p.y - size / 2 + "px", width: size + "px", height: size + "px" };
    },
    dialNumbers() {
      const out = [];
      const add = (v, label, angle, r, inner, sel) => {
        const p = this.polar(angle, r);
        out.push({ v, label, inner, sel, style: { left: p.x - 17 + "px", top: p.y - 17 + "px" } });
      };
      if (this.clock.step === "h") {
        for (let k = 0; k < 12; k++) {
          const outer = k === 0 ? 12 : k, inner = k === 0 ? 0 : k + 12;
          add(outer, String(outer), k * 30, OUTER, false, this.clock.h === outer);
          add(inner, pad(inner), k * 30, INNER, true, this.clock.h === inner);
        }
      } else {
        for (let m = 0; m < 60; m += 5) add(m, pad(m), m * 6, OUTER, false, this.clock.m === m);
      }
      return out;
    },
    dialPick(e) {
      const box = this.$refs.dial.getBoundingClientRect();
      const dx = e.clientX - box.left - box.width / 2, dy = e.clientY - box.top - box.height / 2;
      let angle = (Math.atan2(dx, -dy) * 180) / Math.PI;
      if (angle < 0) angle += 360;
      const r = Math.hypot(dx, dy) * (DIAL / box.width);
      if (this.clock.step === "h") {
        const k = Math.round(angle / 30) % 12;
        const inner = r < (OUTER + INNER) / 2;
        this.clock.h = inner ? (k === 0 ? 0 : k + 12) : (k === 0 ? 12 : k);
      } else {
        this.clock.m = Math.round(angle / 6) % 60;
      }
    },
    dialDown(e) {
      this.clock.drag = true;
      try { e.currentTarget.setPointerCapture(e.pointerId); } catch (err) { /* älterer Browser */ }
      this.$refs.dial.focus();
      this.dialPick(e);
    },
    dialMove(e) { if (this.clock.drag) this.dialPick(e); },
    dialUp(e) {
      if (!this.clock.drag) return;
      this.clock.drag = false;
      this.dialPick(e);
      if (this.clock.step === "h") this.clock.step = "m";
    },
    dialKey(e) {
      const step = this.clock.step;
      const keys = { ArrowUp: 1, ArrowRight: 1, ArrowDown: -1, ArrowLeft: -1, PageUp: 5, PageDown: -5 };
      if (keys[e.key] !== undefined) {
        e.preventDefault();
        if (step === "h") this.clock.h = (this.clock.h + Math.sign(keys[e.key]) + 24) % 24;
        else this.clock.m = (this.clock.m + keys[e.key] + 60) % 60;
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (step === "h") this.clock.step = "m"; else this.clockOk();
      }
    },
    async saveSchedule() {
      const x = this.sched;
      x.error = "";
      if (x.mode === "times" && !x.times.length) { x.error = "Mindestens eine Uhrzeit hinzufügen."; return; }
      x.saving = true;
      try {
        const body = { mode: x.mode, hours: x.mode === "interval" ? x.hours : null, times: x.times,
                       days: x.days.length === 7 ? [] : x.days, timezone: x.timezone };
        const r = await V.api("/api/settings/schedule/" + x.kind, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        this.s.schedules = Object.assign({}, this.s.schedules, { [x.kind]: r.schedule });
        this.s.next_runs = r.next_runs;
        if (x.mode === "interval") this.s[x.kind === "scan" ? "scan_interval_hours" : "cve_sync_interval_hours"] = x.hours;
        V.toast("Zeitplan gespeichert. " + this.nextRunText(x.kind));
        this.closeSchedule();
      } catch (e) {
        if (!e.cancelled) x.error = "Nicht gespeichert: " + e.message;
      } finally { x.saving = false; }
    },
  });

  Alpine.data("settingsPage", () => ({
    ...scheduleMixin(),
    s: {}, token: null, newToken: "", sshKey: "", saving: false, rotating: false, testing: false, savingGotify: false,
    g: { enabled: false, url: "", token: "", min_severity: "HIGH", digest_mode: false, digest_interval_minutes: 60 },
    async init() {
      try {
        const [s, token, key] = await Promise.all([V.api("/api/settings"), V.api("/api/settings/api-token"), V.api("/api/settings/ssh-key")]);
        this.s = s; this.token = token; this.sshKey = key.public_key || "";
        this.fillGotify(s.gotify);
      } catch (e) { V.toast("Einstellungen nicht geladen: " + e.message, true); }
    },
    tokenText() {
      const t = this.token;
      if (!t) return "";
      if (!t.configured) return "Noch kein Token. Erzeuge einen, sonst sind keine Änderungen möglich.";
      if (t.source === "env") return "Token aus der .env-Datei (VIGILANCE_API_TOKEN). Erzeuge einen neuen, um ihn abzulösen.";
      return "Token erzeugt am " + V.date(t.created_at) + ".";
    },
    async save() {
      this.saving = true;
      try {
        const body = { scan_interval_hours: this.s.scan_interval_hours, cve_sync_interval_hours: this.s.cve_sync_interval_hours,
                       ssh_timeout: this.s.ssh_timeout, ssh_parallel_jobs: this.s.ssh_parallel_jobs };
        await V.api("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        V.toast("Einstellungen gespeichert.");
        try { this.s.next_runs = (await V.api("/api/settings")).next_runs; } catch (e) { /* Anzeige bleibt */ }
      } catch (e) { if (!e.cancelled) V.toast("Nicht gespeichert: " + e.message, true); }
      finally { this.saving = false; }
    },
    async saveAutoinstall() {
      const on = this.s.ssh_key_autoinstall;
      try {
        await V.api("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" },
                                       body: JSON.stringify({ ssh_key_autoinstall: on }) });
        V.toast(on ? "Vigilance trägt seinen Schlüssel ab dem nächsten Scan selbst ein." : "Schlüssel wird nicht mehr selbst eingetragen.");
      } catch (e) {
        this.s.ssh_key_autoinstall = !on;
        if (!e.cancelled) V.toast("Nicht gespeichert: " + e.message, true);
      }
    },
    async rotate() {
      if (!confirm("Neuen API-Token erzeugen? Der bisherige funktioniert danach nicht mehr.")) return;
      this.rotating = true;
      try {
        const r = await V.api("/api/auth/token", { method: "POST" });
        this.newToken = r.access_token;
        window.vigilanceAuth.set(r.access_token);
        this.token = await V.api("/api/settings/api-token");
      } catch (e) { if (!e.cancelled) V.toast("Kein Token erzeugt: " + e.message, true); }
      finally { this.rotating = false; }
    },
    fillGotify(info) {
      const i = info || {};
      this.g = { enabled: !!i.enabled, url: i.url || "", token: "", min_severity: i.min_severity || "HIGH",
                 digest_mode: !!i.digest_mode, digest_interval_minutes: i.digest_interval_minutes || 60 };
    },
    gotifyState() {
      const i = this.s.gotify;
      if (!i) return "";
      if (i.ready) return "Aktiv: neue Befunde ab der gewählten Schwere gehen an Gotify" + (i.origin === "config" ? " (Werte aus .env bzw. config.yaml)." : ".");
      if (!i.enabled && (i.url || i.token_set)) return "Ausgeschaltet: es gehen keine Meldungen raus.";
      return "Noch nicht eingerichtet.";
    },
    async saveGotify() {
      this.savingGotify = true;
      try {
        const info = await V.api("/api/settings/gotify", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(this.g) });
        this.s.gotify = info;
        this.fillGotify(info);
        V.toast("Gotify gespeichert.");
      } catch (e) { if (!e.cancelled) V.toast("Nicht gespeichert: " + e.message, true); }
      finally { this.savingGotify = false; }
    },
    async testGotify() {
      this.testing = true;
      try {
        const r = await V.api("/api/settings/gotify/test", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: this.g.url, token: this.g.token }) });
        V.toast(r.success ? "Testnachricht gesendet." : r.message, !r.success);
      } catch (e) { if (!e.cancelled) V.toast("Test fehlgeschlagen: " + e.message, true); }
      finally { this.testing = false; }
    },
  }));
});
