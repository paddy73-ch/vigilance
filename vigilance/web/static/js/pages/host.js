document.addEventListener("alpine:init", () => {
  Alpine.data("hostPage", (id) => ({
    h: null,
    error: null,
    open: {},
    suggested: null, // true/false once checked
    async init() { await this.load(); },
    async load() {
      try { this.h = await V.api("/api/hosts/" + id); document.title = this.h.name + " – Vigilance"; }
      catch (e) { this.error = e.message; }
      try { this.suggested = (await V.api("/api/actions/available?host_id=" + id)).suggested.length > 0; }
      catch (e) { this.suggested = false; }
    },
    async setBuild(needed) {
      try {
        const r = await V.api("/api/hosts/" + id + "/build-tools", { method: "PUT", headers: { "Content-Type": "application/json" },
                                                                    body: JSON.stringify({ needed }) });
        this.h.build_tools = r.build_tools;
        V.toast(needed === false ? "In den Vorschlägen." : (needed ? "Als nötig markiert." : "Frage zurückgesetzt."));
        try { this.suggested = (await V.api("/api/actions/available?host_id=" + id)).suggested.length > 0; } catch (e) { /* bleibt */ }
      } catch (e) {
        if (!e.cancelled) V.toast("Nicht gespeichert: " + e.message, true);
      }
    },
    key(g) { return g.package + "|" + g.installed_version; },
    isOpen(g) { return !!this.open[this.key(g)]; },
    toggle(g) { this.open[this.key(g)] = !this.open[this.key(g)]; },
    folds() {
      const h = this.h;
      const count = (list) => list.reduce((a, g) => a + g.count, 0);
      return [
        { key: "without_fix", list: h.without_fix_list, title: "Offen ohne Fix (" + V.plural(count(h.without_fix_list), "Lücke", "Lücken") + ")", empty: "Keine." },
        { key: "suppressed", list: h.suppressed_list, title: "Ausnahmen (" + count(h.suppressed_list) + ")", empty: "Keine Ausnahmen für diesen Host." },
        { key: "not_affected", list: h.not_affected_list || [], title: "Nicht betroffen (" + count(h.not_affected_list || []) + ")", empty: "Keine. Hier stehen Befunde, die laut Sicherheitsdaten nur andere Systeme als Linux betreffen, und Kernel-Lücken bei Paketen, die nur Kernel-Header enthalten." },
        { key: "fixed", list: h.fixed_list, title: "Behoben in den letzten 30 Tagen (" + count(h.fixed_list) + ")", empty: "In den letzten 30 Tagen wurde nichts behoben." },
      ];
    },
    hint(key, g) {
      if (key === "without_fix") {
        const unimportant = g.advisories.filter((a) => a.urgency === "unimportant").length;
        return unimportant === g.count ? "Debian: unwichtig" : (unimportant ? unimportant + " davon laut Debian unwichtig" : "");
      }
      if (key === "fixed") return "behoben " + V.day(g.advisories[0].resolved_at);
      if (key === "not_affected") return g.advisories[0].not_affected_reason || "";
      const hinted = g.advisories.filter((a) => a.os_hint);
      if (hinted.length) return hinted.length + " laut Meldung nur " + [...new Set(hinted.map((a) => a.os_hint))].join(", ");
      return "";
    },
  }));
});
