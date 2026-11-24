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

  Alpine.data("settingsPage", () => ({
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
      } catch (e) { if (!e.cancelled) V.toast("Nicht gespeichert: " + e.message, true); }
      finally { this.saving = false; }
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
