document.addEventListener("alpine:init", () => {
  Alpine.data("fixesPage", () => ({
    data: null, hosts: [], open: {},
    days: 7, hostId: 0,
    async init() {
      const q = new URLSearchParams(location.search);
      if (q.has("days")) this.days = Math.max(0, parseInt(q.get("days"), 10) || 0);
      if (q.has("host")) this.hostId = parseInt(q.get("host"), 10) || 0;
      try { this.hosts = await V.api("/api/hosts"); } catch (e) { this.hosts = []; }
      await this.load();
    },
    async load() {
      const q = new URLSearchParams({ days: String(this.days) });
      if (this.hostId) q.set("host_id", String(this.hostId));
      history.replaceState(null, "", "/vulnerabilities/fixed?days=" + this.days + (this.hostId ? "&host=" + this.hostId : ""));
      try {
        const d = await V.api("/api/fixes?" + q.toString());
        d.entries.forEach((e, i) => { e.key = i + "-" + e.host.id + "-" + e.package; });
        this.data = d;
        this.open = {};
      } catch (e) { V.toast("Protokoll nicht geladen: " + e.message, true); }
    },
    setDays(d) { this.days = d; this.load(); },
    summary() {
      if (!this.data) return "Lädt …";
      const span = this.days ? "in den letzten " + this.days + " Tagen" : "insgesamt";
      const vulns = this.data.entries.reduce((n, e) => n + e.vulnerabilities, 0);
      return V.plural(vulns, "Lücke", "Lücken") + " " + span + " behoben, in " +
        V.plural(this.data.entries.length, "Paket", "Paketen") + " (" + V.plural(this.data.findings, "Befund", "Befunde") + ").";
    },
    // entries grouped by local day, newest first
    days_() {
      if (!this.data) return [];
      const fmt = new Intl.DateTimeFormat("de-CH", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
      const out = [];
      let cur = null;
      for (const e of this.data.entries) {
        const d = new Date(e.resolved_at);
        const date = d.toLocaleDateString("sv-SE");
        if (!cur || cur.date !== date) { cur = { date, label: fmt.format(d), entries: [], count: 0 }; out.push(cur); }
        cur.entries.push(e);
        cur.count += e.vulnerabilities;
      }
      return out;
    },
    time(iso) { return new Date(iso).toLocaleTimeString("de-CH", { hour: "2-digit", minute: "2-digit" }); },
    how(e) {
      if (e.how === "removed") return "Paket entfernt";
      if (e.how === "updated") return "Update von " + (e.from_version || "?") + ", heute " + (e.to_version || "?");
      return "Meldung trifft nicht mehr zu";
    },
    howTitle(e) {
      if (e.how === "data") return "Version unverändert (" + (e.from_version || "?") + "); die Sicherheitsdaten der Quelle haben sich geändert.";
      if (e.how === "updated") return "„heute“ ist die jetzt installierte Version; dazwischen kann es weitere Updates gegeben haben.";
      return "";
    },
  }));
});
