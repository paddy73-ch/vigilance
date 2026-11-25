document.addEventListener("alpine:init", () => {
  Alpine.data("hostsPage", () => ({
    hosts: null,
    only: null, // host ids from the overview (?ids=…&for=…), null = all
    onlyFor: "",
    suggested: null, // host ids with something to apply; null while checking
    sort: { key: "", dir: 1 }, // "" = as delivered: most urgent first
    menu: { host: null, x: 0, y: 0 },
    enable: { host: null, ip: "", key: "", saving: false },
    columns: [
      { key: "name", label: "Name" },
      { key: "type", label: "Typ" },
      { key: "vmid", label: "Nr", num: true },
      { key: "os", label: "System" },
      { key: "level", label: "Zustand" },
      { key: "upgrade_packages", label: "Updates", num: true },
      { key: "remove_packages", label: "Altpakete", num: true },
      { key: "crit_high", label: "Kritisch/hoch behebbar", num: true },
      { key: "without_fix", label: "Ohne Fix", num: true },
      { key: "last_scan_at", label: "Letzter Scan" },
    ],
    async init() {
      const q = new URLSearchParams(location.search);
      if (this.columns.some((c) => c.key === q.get("sort"))) {
        this.sort = { key: q.get("sort"), dir: q.get("dir") === "desc" ? -1 : 1 };
      }
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
    running() { return this.shown().filter((h) => h.level !== "stopped" && h.level !== "not_scanned"); },
    notScanned() { return this.shown().filter((h) => h.level === "not_scanned"); },
    stopped() { return this.shown().filter((h) => h.level === "stopped"); },
    showAll() { this.only = null; this.onlyFor = ""; this.saveUrl(); },
    // --- VMs: switch scanning on/off (right click or the ⋯ button)
    contextMenu(ev, h) {
      if (h.type !== "qemu") return; // other rows keep the browser menu
      ev.preventDefault();
      this.openMenu(ev, h);
    },
    openMenu(ev, h) {
      const w = 240, hgt = 140;
      const x = ev.clientX || (ev.target.getBoundingClientRect().left);
      const y = ev.clientY || (ev.target.getBoundingClientRect().bottom);
      this.menu = { host: h, x: Math.max(8, Math.min(x, window.innerWidth - w - 8)), y: Math.max(8, Math.min(y, window.innerHeight - hgt - 8)) };
      this.menuOpenedAt = Date.now();
      this.$nextTick(() => { const b = this.$root.querySelector(".ctx-menu button:not([disabled]), .ctx-menu a"); if (b) b.focus(); });
    },
    closeMenu() { this.menu = { host: null, x: 0, y: 0 }; },
    // scrolling closes the menu, but not the scroll the browser does right before opening it
    scrolled() { if (this.menu.host && Date.now() - (this.menuOpenedAt || 0) > 300) this.closeMenu(); },
    async askEnable(h) {
      this.closeMenu();
      this.enable = { host: h, ip: h.scan_ip || "", key: "", saving: false };
      try { this.enable.key = (await V.api("/api/settings/ssh-key")).public_key || ""; } catch (e) { this.enable.key = ""; }
    },
    keyCommand() {
      return "install -d -m 700 /root/.ssh && grep -qxF '" + this.enable.key + "' /root/.ssh/authorized_keys 2>/dev/null || echo '" +
        this.enable.key + "' >> /root/.ssh/authorized_keys";
    },
    async enableScan() {
      const h = this.enable.host;
      this.enable.saving = true;
      try {
        await V.api("/api/hosts/" + h.id + "/scan", { method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: true, ip: this.enable.ip || null }) });
        this.enable.host = null;
        V.toast(h.name + " ist für den Scan aktiviert. Der Scan läuft, das Ergebnis erscheint in ein bis zwei Minuten.");
        await this.load();
      } catch (e) { if (!e.cancelled) V.toast("Nicht aktiviert: " + e.message, true); }
      finally { this.enable.saving = false; }
    },
    async disableScan(h) {
      this.closeMenu();
      try {
        await V.api("/api/hosts/" + h.id + "/scan", { method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: false }) });
        V.toast(h.name + " wird nicht mehr gescannt.");
        await this.load();
      } catch (e) { if (!e.cancelled) V.toast("Nicht geändert: " + e.message, true); }
    },
    stoppedNote(h) {
      if (!h.scan_configured) return h.os_id === "windows" ? "Windows, wird nicht gescannt" : "Nicht für den Scan aktiviert";
      if (h.last_scan_status === "unsupported") return h.last_scan_error || "Wird nicht gescannt";
      return h.patchable ? V.plural(h.patchable, "behebbarer Befund", "behebbare Befunde") : "keine Daten";
    },
    typeLabel(h) { return h.type === "node" ? "Host" : h.type === "qemu" ? "VM" : "CT"; },
    // value used for sorting a column; null/undefined sorts last in both directions
    sortValue(h, key) {
      switch (key) {
        case "name": return (h.name || "").toLowerCase();
        case "type": return { node: 0, lxc: 1, qemu: 2 }[h.type] ?? 3;
        case "vmid": return h.type === "node" ? -1 : h.vmid;
        case "os": return h.os ? h.os.toLowerCase() : null;
        case "level": return { critical: 3, warning: 2, unknown: 1, ok: 0 }[h.level] ?? -1;
        case "crit_high": return (h.patchable_critical || 0) + (h.patchable_high || 0);
        case "last_scan_at": return h.last_scan_at ? Date.parse(h.last_scan_at) : null;
        default: return h[key] ?? null;
      }
    },
    sorted(list) {
      const { key, dir } = this.sort;
      if (!key) return list;
      return [...list].sort((a, b) => {
        const x = this.sortValue(a, key), y = this.sortValue(b, key);
        if (x === null || x === undefined) return (y === null || y === undefined) ? a.name.localeCompare(b.name) : 1;
        if (y === null || y === undefined) return -1;
        const c = typeof x === "string" ? x.localeCompare(y, "de") : x - y;
        return c ? c * dir : a.name.localeCompare(b.name, "de");
      });
    },
    sortBy(key) {
      // ascending, descending, back to "most urgent first"
      if (this.sort.key !== key) this.sort = { key, dir: 1 };
      else if (this.sort.dir === 1) this.sort = { key, dir: -1 };
      else this.sort = { key: "", dir: 1 };
      this.saveUrl();
    },
    setSort(v) {
      const [key, dir] = v.split(":");
      this.sort = key ? { key, dir: Number(dir) || 1 } : { key: "", dir: 1 };
      this.saveUrl();
    },
    ariaSort(key) { return this.sort.key !== key ? "none" : this.sort.dir === 1 ? "ascending" : "descending"; },
    sortMark(key) { return this.sort.key !== key ? "" : this.sort.dir === 1 ? " ▲" : " ▼"; },
    sortHint() {
      const c = this.columns.find((x) => x.key === this.sort.key);
      const by = c ? "sortiert nach " + c.label + (this.sort.dir === 1 ? ", aufsteigend" : ", absteigend") : "der dringendste zuerst";
      return "Container, VMs aus config.yaml und Proxmox-Host, " + by + ". Spaltentitel anklicken zum Sortieren.";
    },
    saveUrl() {
      const q = new URLSearchParams();
      if (this.only) { q.set("ids", this.only.join(",")); if (this.onlyFor) q.set("for", this.onlyFor); }
      if (this.sort.key) { q.set("sort", this.sort.key); q.set("dir", this.sort.dir === 1 ? "asc" : "desc"); }
      history.replaceState(null, "", "/hosts" + (q.toString() ? "?" + q : ""));
    },
    levelText(h) {
      return { critical: "Kritisch behebbar", warning: "Behebbar", ok: "Aktuell", unknown: V.scanReason(h) || "Unbekannt" }[h.level] || h.level;
    },
    levelClass(h) { return { critical: "tag-crit", warning: "tag-remove", ok: "tag-ok" }[h.level] || ""; },
  }));
});
