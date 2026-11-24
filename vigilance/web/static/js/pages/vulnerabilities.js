document.addEventListener("alpine:init", () => {
  const DEFAULTS = { view: "package", status: "open", fix: "true", sev: "", host: "", q: "", hide: "1", page: "1" };

  Alpine.data("vulnPage", () => ({
    f: { ...DEFAULTS },
    items: [],
    total: 0,
    limit: 50,
    loading: true,
    hosts: [],
    open: {},

    get offset() { return (Number(this.f.page) - 1) * this.limit; },

    async init() {
      const p = new URLSearchParams(location.search);
      Object.keys(DEFAULTS).forEach((k) => { if (p.has(k)) this.f[k] = p.get(k); });
      // compatibility with links from the old UI / overview
      if (p.has("severity")) this.f.sev = p.get("severity");
      if (p.has("status") && p.get("status") !== "open") this.f.fix = "";
      window.addEventListener("popstate", () => location.reload());
      V.api("/api/hosts").then((h) => { this.hosts = h.filter((x) => x.tools > 0); }).catch(() => {});
      await this.load();
    },

    params() {
      return {
        status: this.f.status,
        fix: this.f.status === "open" ? this.f.fix : "",
        severity: this.f.sev,
        host_id: this.f.host,
        q: this.f.q.trim(),
        hide_unimportant: this.f.hide === "1" ? "true" : "",
      };
    },

    async load() {
      this.loading = true;
      this.open = {};
      const qs = V.qs({ ...this.params(), limit: this.limit, offset: this.offset });
      try {
        const r = await V.api((this.f.view === "cve" ? "/api/vulnerabilities?" : "/api/packages?") + qs);
        this.items = r.items;
        this.total = r.total;
      } catch (e) {
        V.toast("Liste nicht geladen: " + e.message, true);
      } finally { this.loading = false; }
    },

    set(k, v) {
      if (k === "view" && v !== this.f.view) this.items = [];
      this.f[k] = v;
      if (k !== "page") this.f.page = "1";
      const url = new URLSearchParams();
      Object.entries(this.f).forEach(([key, val]) => { if (val !== DEFAULTS[key]) url.set(key, val); });
      history.replaceState(null, "", url.toString() ? "?" + url : location.pathname);
      this.load();
    },
    page(d) { this.set("page", String(Number(this.f.page) + d)); window.scrollTo({ top: 0 }); },
    hasSev(s) { return this.f.sev.split(",").includes(s); },
    toggleSev(s) {
      const list = this.f.sev.split(",").filter(Boolean);
      this.set("sev", (list.includes(s) ? list.filter((x) => x !== s) : [...list, s]).join(","));
    },

    key(p) { return p.package + "|" + p.version; },
    async expand(p) {
      const k = this.key(p);
      if (this.open[k]) { delete this.open[k]; return; }
      this.open[k] = { items: null, total: 0 };
      try {
        const r = await V.api("/api/vulnerabilities?" + V.qs({ ...this.params(), package: p.package, version: p.version, limit: 100 }));
        this.open[k] = { items: r.items, total: r.total };
      } catch (e) { delete this.open[k]; V.toast(e.message, true); }
    },
    actionText(p) {
      if (this.f.status === "fixed") return "Behoben";
      if (this.f.status === "suppressed") return "Ausnahme";
      if (this.f.status === "not_affected") return "Anderes OS";
      if (!p.fix_available) return "Kein Fix";
      return p.action === "remove" ? "Entfernen" : "Update";
    },
    actionClass(p) {
      if (this.f.status !== "open") return this.f.status === "fixed" ? "tag-ok" : "";
      if (!p.fix_available) return "";
      return p.action === "remove" ? "tag-remove" : "tag-upgrade";
    },
    summary() {
      if (this.loading && !this.items.length) return "Lädt …";
      const unit = this.f.view === "cve" ? ["Schwachstelle", "Schwachstellen"] : ["Paket", "Pakete"];
      return V.plural(this.total, unit[0], unit[1]) + " mit diesen Filtern";
    },
    emptyText() {
      if (this.f.status === "open" && this.f.fix === "true" && !this.f.q && !this.f.sev) return "Für kein installiertes Paket gibt es einen offenen Befund mit Fix.";
      return "Filter lockern oder Suche ändern.";
    },
  }));
});
