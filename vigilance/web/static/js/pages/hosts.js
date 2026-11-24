document.addEventListener("alpine:init", () => {
  Alpine.data("hostsPage", () => ({
    hosts: null,
    async init() {
      try { this.hosts = await V.api("/api/hosts"); } catch (e) { V.toast("Hosts nicht geladen: " + e.message, true); }
    },
    running() { return (this.hosts || []).filter((h) => h.level !== "stopped"); },
    stopped() { return (this.hosts || []).filter((h) => h.level === "stopped"); },
    levelText(h) {
      return { critical: "Kritisch behebbar", warning: "Behebbar", ok: "Aktuell", unknown: V.scanReason(h) || "Unbekannt" }[h.level] || h.level;
    },
    levelClass(h) { return { critical: "tag-crit", warning: "tag-remove", ok: "tag-ok" }[h.level] || ""; },
  }));
});
