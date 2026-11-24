document.addEventListener("alpine:init", () => {
  Alpine.data("hostsPage", () => ({
    hosts: null,
    only: null, // host ids from the overview (?ids=…&for=…), null = all
    onlyFor: "",
    suggested: null, // host ids with something to apply; null while checking
    async init() {
      const q = new URLSearchParams(location.search);
      if (q.get("ids")) {
        this.only = q.get("ids").split(",").map(Number).filter(Boolean);
        this.onlyFor = q.get("for") || "";
      }
      await this.load();
      window.addEventListener("vigilance-changed", () => this.load());
    },
    async load() {
      try { this.hosts = await V.api("/api/hosts"); } catch (e) { V.toast("Hosts nicht geladen: " + e.message, true); }
      try { this.suggested = (await V.api("/api/actions/available")).suggested; } catch (e) { this.suggested = []; }
    },
    hasVMs() { return (this.hosts || []).some((h) => h.type === "qemu"); },
    allWord() { return this.hasVMs() ? "Containern und VMs" : "Containern"; }, // "auf allen …"
    allGen() { return this.hasVMs() ? "Container und VMs" : "Container"; },    // "Upgrade aller …"
    allTitle() { return this.hasVMs() ? "alle Container und VMs" : "alle Container"; },
    suggestTitle() {
      if (this.suggested === null) return "Prüfe, ob es Vorschläge gibt …";
      if (!this.suggested.length) return "Keine Vorschläge: kein Update mit Fix in den Paketquellen, kein unbedenkliches Altpaket.";
      return "Vorschläge auf " + V.plural(this.suggested.length, "Host", "Hosts");
    },
    shown() { return (this.hosts || []).filter((h) => !this.only || this.only.includes(h.id)); },
    running() { return this.shown().filter((h) => h.level !== "stopped"); },
    stopped() { return this.shown().filter((h) => h.level === "stopped"); },
    showAll() { this.only = null; this.onlyFor = ""; history.replaceState(null, "", "/hosts"); },
    levelText(h) {
      return { critical: "Kritisch behebbar", warning: "Behebbar", ok: "Aktuell", unknown: V.scanReason(h) || "Unbekannt" }[h.level] || h.level;
    },
    levelClass(h) { return { critical: "tag-crit", warning: "tag-remove", ok: "tag-ok" }[h.level] || ""; },
  }));
});
