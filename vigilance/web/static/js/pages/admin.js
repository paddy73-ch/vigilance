document.addEventListener("alpine:init", () => {
  const NAMES = { osv: "OSV", ghsa: "GitHub Advisories", tailscale: "Tailscale Security Bulletins", nvd: "NVD", debian: "Debian Security Tracker", ubuntu: "Ubuntu" };

  Alpine.data("sourcesPage", () => ({
    sources: [], disabled: [], busy: false,
    async init() { await this.load(); },
    async load() {
      try {
        const all = await V.api("/api/cves/sync/status");
        this.sources = all.filter((s) => s.enabled);
        this.disabled = all.filter((s) => !s.enabled).map((s) => s.source);
        if (this.sources.some((s) => s.status === "running")) setTimeout(() => this.load(), 4000);
      } catch (e) { V.toast("Quellen nicht geladen: " + e.message, true); }
    },
    name(s) { return NAMES[s] || s; },
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
    s: {}, token: null, newToken: "", sshKey: "", saving: false, rotating: false, testing: false,
    async init() {
      try {
        const [s, token, key] = await Promise.all([V.api("/api/settings"), V.api("/api/settings/api-token"), V.api("/api/settings/ssh-key")]);
        this.s = s; this.token = token; this.sshKey = key.public_key || "";
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
    async testGotify() {
      this.testing = true;
      try {
        const r = await V.api("/api/settings/gotify/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
        V.toast(r.success ? "Testnachricht gesendet." : r.message, !r.success);
      } catch (e) { if (!e.cancelled) V.toast("Test fehlgeschlagen: " + e.message, true); }
      finally { this.testing = false; }
    },
  }));
});
