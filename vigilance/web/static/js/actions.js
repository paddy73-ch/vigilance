// Remediation dialog: preview (simulation) -> execute -> follow the runs.
// Open with: window.dispatchEvent(new CustomEvent("open-actions", { detail: { kind, hostIds, title } }))
document.addEventListener("alpine:init", () => {
  const KIND_LABEL = { suggested: "Vorschläge umsetzen", full_upgrade: "Vollständiges Upgrade", kernel_cleanup: "Kernel aufräumen" };
  const STATUS = { queued: "Wartet", running: "Läuft", ok: "Fertig", failed: "Fehler", skipped: "Übersprungen", interrupted: "Abgebrochen" };

  Alpine.data("actionDialog", () => ({
    visible: false,
    phase: "preview", // preview | running | done
    kind: "suggested",
    hostIds: null,
    title: "",
    preview: null,
    runs: [],
    batchId: null,
    error: null,
    starting: false,
    confirmHost: false,
    openLog: {},
    timer: null,

    async open(detail) {
      Object.assign(this, { visible: true, phase: "preview", kind: detail.kind, hostIds: detail.hostIds || null,
        title: detail.title || "", preview: null, runs: [], batchId: null, error: null, openLog: {}, confirmHost: false });
      try {
        this.preview = await V.api("/api/actions/preview", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind: this.kind, host_ids: this.hostIds }) });
      } catch (e) {
        if (e.cancelled) { this.visible = false; return; }
        this.error = "Vorschau nicht möglich: " + e.message;
      }
    },
    close() {
      if (this.phase === "running") { V.toast("Die Aktion läuft im Hintergrund weiter. Verlauf unter Verwaltung, Aktionen."); }
      clearTimeout(this.timer);
      this.visible = false;
      if (this.phase !== "preview") window.dispatchEvent(new CustomEvent("vigilance-changed"));
    },
    kindLabel() {
      if (this.kind === "full_upgrade" && this.hasNode()) return "dist-upgrade auf dem Proxmox-Host";
      return KIND_LABEL[this.kind];
    },
    hasNode() { return !!(this.preview && this.preview.hosts.some((h) => h.type === "node")); },
    intro() {
      if (this.kind === "kernel_cleanup") return "Entfernt die Kernel-Pakete im Container und was dadurch unbenutzt wird (purge --autoremove). Der Container läuft weiter mit dem Kernel des Proxmox-Hosts.";
      if (this.kind === "full_upgrade") return "apt-get update und " + (this.hasNode() ? "apt-get dist-upgrade" : "apt-get full-upgrade") + ". Geänderte Konfigurationsdateien bleiben, wie sie sind.";
      return "Nur die Vorschläge von Vigilance: Updates mit Fix in den Paketquellen und Altpakete, deren Risikoprüfung unbedenklich ist.";
    },
    parallelText() {
      const n = (this.preview && this.preview.parallel) || 1;
      return "Bis zu " + n + " Container laufen gleichzeitig. Ein Container mit apt-cacher-ng kommt zuerst und allein dran, weil die anderen ihre Pakete darüber laden können.";
    },
    statusLabel(s) { return STATUS[s] || s; },
    statusClass(s) { return { ok: "tag-ok", failed: "tag-crit", running: "tag-upgrade", interrupted: "tag-crit" }[s] || ""; },
    runnable() { return this.preview ? this.preview.hosts.filter((h) => !h.blocked && h.commands.length) : []; },
    idle() { return this.preview ? this.preview.hosts.filter((h) => !h.blocked && !h.commands.length) : []; },
    blocked() { return this.preview ? this.preview.hosts.filter((h) => h.blocked) : []; },
    changeText(h) {
      if (h.simulation_error) return "Simulation fehlgeschlagen";
      const c = h.changes;
      if (!c) return "";
      const parts = [];
      if (c.upgrade.length) parts.push(V.plural(c.upgrade.length, "Update", "Updates"));
      if (c.install.length) parts.push(c.install.length + " neu");
      if (c.remove.length) parts.push(c.remove.length + " entfernt");
      return parts.length ? parts.join(", ") : "apt würde nach den aktuellen Paketlisten nichts ändern";
    },
    async run() {
      this.starting = true;
      try {
        const r = await V.api("/api/actions", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind: this.kind, host_ids: this.runnable().map((h) => h.host_id), confirm_host: this.confirmHost }) });
        this.batchId = r.batch_id;
        this.phase = "running";
        this.poll();
      } catch (e) {
        if (!e.cancelled) this.error = "Nicht gestartet: " + e.message;
      } finally { this.starting = false; }
    },
    async poll() {
      try {
        const r = await V.api("/api/actions?batch_id=" + encodeURIComponent(this.batchId));
        this.runs = r.runs;
        const active = r.runs.some((x) => x.status === "queued" || x.status === "running");
        if (!active) { this.phase = "done"; return; }
      } catch (e) { /* keep polling */ }
      this.timer = setTimeout(() => this.poll(), 2500);
    },
    summary() {
      const n = (s) => this.runs.filter((r) => r.status === s).length;
      if (this.phase === "running") return "Läuft: " + n("ok") + " von " + this.runs.filter((r) => r.status !== "skipped").length + " fertig";
      const parts = [V.plural(n("ok"), "Container fertig", "Container fertig")];
      if (n("failed")) parts.push(n("failed") + " mit Fehler");
      return parts.join(", ") + ". Ein neuer Scan läuft, die Befunde aktualisieren sich in ein paar Minuten.";
    },
  }));

  Alpine.data("actionsHistory", () => ({
    runs: null, open: {}, busy: false,
    async init() { await this.load(); },
    async load() {
      try {
        const r = await V.api("/api/actions?limit=100");
        this.runs = r.runs;
        this.busy = r.busy;
        if (r.busy) setTimeout(() => this.load(), 4000);
      } catch (e) { V.toast("Verlauf nicht geladen: " + e.message, true); }
    },
    async toggle(run) {
      if (this.open[run.id]) { delete this.open[run.id]; return; }
      this.open[run.id] = { output: null };
      try { this.open[run.id] = await V.api("/api/actions/" + run.id); } catch (e) { delete this.open[run.id]; }
    },
    kindLabel(k) { return KIND_LABEL[k] || k; },
    statusLabel(s) { return STATUS[s] || s; },
    statusClass(s) { return { ok: "tag-ok", failed: "tag-crit", running: "tag-upgrade", interrupted: "tag-crit" }[s] || ""; },
  }));
});
