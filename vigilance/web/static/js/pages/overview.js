document.addEventListener("alpine:init", () => {
  Alpine.data("overview", () => ({
    data: null,
    error: null,
    busy: false,
    timer: null,

    get k() { return (this.data && this.data.kpis) || {}; },

    async init() {
      await this.load();
      // refresh every minute; every 5 s while a scan is running
      this.timer = setInterval(() => this.load(), 60000);
    },

    async load() {
      try {
        this.data = await V.api("/api/overview");
        this.error = null;
        if (this.scanning()) setTimeout(() => this.load(), 5000);
      } catch (e) {
        this.error = e.message;
      }
    },

    active() { return (this.data ? this.data.hosts : []).filter((h) => h.level !== "stopped"); },
    stopped() { return (this.data ? this.data.hosts : []).filter((h) => h.level === "stopped"); },

    headline() {
      const k = this.k;
      if (!k.patchable) return "Nichts zu tun: Für keinen offenen Befund gibt es ein Update.";
      return V.plural(k.patchable, "offener Befund lässt", "offene Befunde lassen") + " sich jetzt beheben.";
    },
    subline() {
      const k = this.k;
      const parts = [];
      const hostsUp = this.active().filter((h) => h.upgrade_packages).length;
      const hostsRm = this.active().filter((h) => h.remove_packages).length;
      if (k.patchable_upgrade) parts.push(V.n(k.patchable_upgrade) + " per Update auf " + V.plural(hostsUp, "Host", "Hosts"));
      if (k.patchable_remove) parts.push(V.n(k.patchable_remove) + " durch Entfernen alter Paketversionen auf " + V.plural(hostsRm, "Host", "Hosts"));
      let s = parts.length ? parts.join(", ") + "." : "";
      if (k.without_fix) s += (s ? " " : "") + V.n(k.without_fix) + " weitere sind bekannt, für das installierte Release aber noch ohne Fix.";
      return s;
    },
    boardSummary() {
      if (!this.data) return "";
      const a = this.active();
      const need = a.filter((h) => h.level === "critical" || h.level === "warning").length;
      return need ? V.plural(need, "Host braucht", "Hosts brauchen") + " Aufmerksamkeit" : "Alle gescannten Hosts sind aktuell";
    },
    slotText(h) {
      const reason = V.scanReason(h);
      if (reason) return reason;
      if (h.level === "ok") return h.without_fix ? "Aktuell, " + V.n(h.without_fix) + " ohne Fix" : "Aktuell";
      const parts = [];
      if (h.upgrade_packages) parts.push(V.plural(h.upgrade_packages, "Update", "Updates"));
      if (h.remove_packages) parts.push(V.plural(h.remove_packages, "Altpaket", "Altpakete"));
      return parts.join(", ");
    },

    scanning() { return !!(this.data && this.data.last_scan && this.data.last_scan.status === "running"); },
    scanDot() {
      const s = this.data && this.data.last_scan;
      if (!s) return "idle";
      if (s.status === "failed" || V.hoursSince(s.completed_at || s.started_at) > 26) return "bad";
      return s.status === "running" ? "idle" : "";
    },
    scanText() {
      const s = this.data && this.data.last_scan;
      if (!s) return "Noch kein Scan";
      if (s.status === "running") return "Scan läuft seit " + V.ago(s.started_at).replace("vor ", "");
      if (s.status === "failed") return "Letzter Scan fehlgeschlagen " + V.ago(s.started_at);
      return "Scan " + V.ago(s.completed_at || s.started_at);
    },
    syncDot(s) {
      if (s.status === "error" || V.hoursSince(s.last_success_at) > 26) return "bad";
      return s.status === "skipped" ? "idle" : "";
    },
    syncText(s) {
      const name = { osv: "OSV", ghsa: "GitHub Advisories", nvd: "NVD", debian: "Debian Tracker", ubuntu: "Ubuntu" }[s.source] || s.source;
      if (s.status === "skipped") return name + ": nicht nötig";
      if (s.status === "running") return name + ": Abgleich läuft";
      if (s.status === "error") return name + ": Fehler beim Abgleich";
      return name + " " + V.ago(s.last_success_at);
    },

    trend() {
      const t = this.data && this.data.trend;
      return t && t.length >= 2 ? V.trendPaths(t, 600, 150) : null;
    },

    async scan() {
      this.busy = true;
      try {
        await V.api("/api/scans/trigger", { method: "POST" });
        V.toast("Scan gestartet. Dauert etwa eine Minute.");
        await this.load();
      } catch (e) {
        if (!e.cancelled) V.toast("Scan nicht gestartet: " + e.message, true);
      } finally { this.busy = false; }
    },
    async sync() {
      this.busy = true;
      try {
        await V.api("/api/cves/sync", { method: "POST" });
        V.toast("Abgleich gestartet. Die Zahlen aktualisieren sich in etwa 30 Sekunden.");
        setTimeout(() => this.load(), 30000);
      } catch (e) {
        if (!e.cancelled) V.toast("Abgleich nicht gestartet: " + e.message, true);
      } finally { this.busy = false; }
    },
  }));
});
