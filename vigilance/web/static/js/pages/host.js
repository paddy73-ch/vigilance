document.addEventListener("alpine:init", () => {
  Alpine.data("hostPage", (id) => ({
    h: null,
    error: null,
    open: {},
    async init() { await this.load(); },
    async load() {
      try { this.h = await V.api("/api/hosts/" + id); document.title = this.h.name + " – Vigilance"; }
      catch (e) { this.error = e.message; }
    },
    key(g) { return g.package + "|" + g.installed_version; },
    isOpen(g) { return !!this.open[this.key(g)]; },
    toggle(g) { this.open[this.key(g)] = !this.open[this.key(g)]; },
    folds() {
      const h = this.h;
      const count = (list) => list.reduce((a, g) => a + g.count, 0);
      return [
        { key: "without_fix", list: h.without_fix_list, title: "Offen ohne Fix (" + V.plural(count(h.without_fix_list), "Befund", "Befunde") + ")", empty: "Keine." },
        { key: "suppressed", list: h.suppressed_list, title: "Ausnahmen (" + count(h.suppressed_list) + ")", empty: "Keine Ausnahmen für diesen Host." },
        { key: "fixed", list: h.fixed_list, title: "Behoben in den letzten 30 Tagen (" + count(h.fixed_list) + ")", empty: "In den letzten 30 Tagen wurde nichts behoben." },
      ];
    },
    hint(key, g) {
      if (key === "without_fix") {
        const unimportant = g.advisories.filter((a) => a.urgency === "unimportant").length;
        return unimportant === g.count ? "Debian: unwichtig" : (unimportant ? unimportant + " davon laut Debian unwichtig" : "");
      }
      if (key === "fixed") return "behoben " + V.day(g.advisories[0].resolved_at);
      return "";
    },
  }));
});
