document.addEventListener("alpine:init", () => {
  Alpine.data("vulnDrawer", () => ({
    visible: false,
    item: null,
    showForm: false,
    saving: false,
    form: { reason: "", scope: "", until: "" },

    async open(id) {
      this.visible = true;
      this.item = null;
      this.showForm = false;
      this.form = { reason: "", scope: "", until: "" };
      try {
        this.item = await V.api("/api/vulnerabilities/" + encodeURIComponent(id));
      } catch (e) {
        V.toast("Details nicht geladen: " + e.message, true);
        this.visible = false;
      }
    },
    close() { this.visible = false; },
    hosts() {
      const seen = new Map();
      (this.item ? this.item.affected : []).forEach((a) => seen.set(a.host_id, { id: a.host_id, name: a.host }));
      return [...seen.values()];
    },
    host(url) { try { return new URL(url).host; } catch (e) { return ""; } },
    statusLabel(s) { return { open: "offen", fixed: "behoben", suppressed: "Ausnahme" }[s] || s; },

    async createException() {
      this.saving = true;
      try {
        const body = { cve_id: this.item.id, reason: this.form.reason, inventory_id: this.form.scope ? Number(this.form.scope) : null,
                       expires_at: this.form.until ? this.form.until + "T23:59:59" : null };
        const r = await V.api("/api/exceptions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        V.toast("Ausnahme gespeichert. " + V.plural(r.changed_findings, "Befund", "Befunde") + " ausgeblendet.");
        await this.open(this.item.cve_entry_id);
        window.dispatchEvent(new CustomEvent("vigilance-changed"));
      } catch (e) {
        if (!e.cancelled) V.toast("Ausnahme nicht gespeichert: " + e.message, true);
      } finally { this.saving = false; }
    },
  }));
});
