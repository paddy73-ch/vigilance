document.addEventListener("alpine:init", () => {
  Alpine.data("hostsPage", () => ({
    hosts: null,
    suggested: null, // host ids with something to apply; null while checking
    async init() {
      await this.load();
      window.addEventListener("vigilance-changed", () => this.load());
    },
    async load() {
      try { this.hosts = await V.api("/api/hosts"); } catch (e) { V.toast("Hosts nicht geladen: " + e.message, true); }
      try { this.suggested = (await V.api("/api/actions/available")).suggested; } catch (e) { this.suggested = []; }
    },
    suggestTitle() {
      if (this.suggested === null) return "Prüfe, ob es Vorschläge gibt …";
      if (!this.suggested.length) return "Keine Vorschläge: kein Update mit Fix in den Paketquellen, kein unbedenkliches Altpaket.";
      return "Vorschläge auf " + V.plural(this.suggested.length, "Container", "Containern");
    },
    running() { return (this.hosts || []).filter((h) => h.level !== "stopped"); },
    stopped() { return (this.hosts || []).filter((h) => h.level === "stopped"); },
    levelText(h) {
      return { critical: "Kritisch behebbar", warning: "Behebbar", ok: "Aktuell", unknown: V.scanReason(h) || "Unbekannt" }[h.level] || h.level;
    },
    levelClass(h) { return { critical: "tag-crit", warning: "tag-remove", ok: "tag-ok" }[h.level] || ""; },
  }));
});
