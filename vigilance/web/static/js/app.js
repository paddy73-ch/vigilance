/* Vigilance – shared browser code. Loaded before Alpine (no inline scripts, CSP: script-src 'self'). */
(function () {
  "use strict";

  // ------------------------------------------------------------ write access token
  // Reading needs no token. Every non-GET /api request sends "Authorization: Bearer <token>".
  // The token is kept in this browser (localStorage) until editing is locked again.
  const KEY = "vigilance.apiToken";
  let memoryToken = null;

  const auth = {
    get() { try { return localStorage.getItem(KEY) || memoryToken; } catch (e) { return memoryToken; } },
    set(token) { memoryToken = token; try { localStorage.setItem(KEY, token); } catch (e) {} auth.render(); },
    clear() { memoryToken = null; try { localStorage.removeItem(KEY); } catch (e) {} auth.render(); },
    render() {
      const el = document.getElementById("auth-state");
      if (!el) return;
      const on = !!auth.get();
      el.dataset.unlocked = on ? "true" : "false";
      el.querySelector("[data-label]").textContent = on ? "Bearbeiten aktiv" : "Bearbeiten";
      el.title = on ? "API-Token aus diesem Browser entfernen" : "API-Token eingeben, um Änderungen zu machen";
    },
    ask(message) {
      return new Promise((resolve) => {
        const scrim = document.createElement("div");
        scrim.className = "dialog-scrim";
        scrim.id = "vigilance-token-dialog";
        const form = document.createElement("form");
        form.className = "dialog";
        form.setAttribute("autocomplete", "on");
        const h = document.createElement("h2");
        h.textContent = "API-Token eingeben";
        const p = document.createElement("p");
        p.className = "muted";
        p.textContent = message || "Änderungen brauchen den API-Token. Er bleibt in diesem Browser gespeichert, bis du die Bearbeitung wieder sperrst.";
        const user = document.createElement("input");
        Object.assign(user, { type: "text", name: "username", value: "vigilance", autocomplete: "username", hidden: true });
        const input = document.createElement("input");
        Object.assign(input, { type: "password", name: "token", autocomplete: "current-password", required: true, placeholder: "vig_…" });
        input.className = "input";
        input.setAttribute("aria-label", "API-Token");
        const actions = document.createElement("div");
        actions.className = "actions";
        const cancel = document.createElement("button");
        Object.assign(cancel, { type: "button", className: "btn", textContent: "Abbrechen" });
        const ok = document.createElement("button");
        Object.assign(ok, { type: "submit", className: "btn btn-primary", textContent: "Freischalten" });
        actions.append(cancel, ok);
        form.append(h, p, user, input, actions);
        scrim.append(form);
        const done = (value) => { scrim.remove(); resolve(value); };
        cancel.addEventListener("click", () => done(null));
        scrim.addEventListener("keydown", (e) => { if (e.key === "Escape") done(null); });
        form.addEventListener("submit", (e) => { e.preventDefault(); done(input.value.trim() || null); });
        document.body.append(scrim);
        input.focus();
      });
    },
  };
  window.vigilanceAuth = auth;

  const originalFetch = window.fetch.bind(window);
  const isWriteApi = (url, method) => {
    const m = (method || "GET").toUpperCase();
    if (m === "GET" || m === "HEAD") return false;
    try { const u = new URL(url, location.href); return u.origin === location.origin && u.pathname.startsWith("/api/"); }
    catch (e) { return false; }
  };
  const withToken = (init, token) => {
    const headers = new Headers((init && init.headers) || {});
    if (token) headers.set("Authorization", "Bearer " + token);
    return Object.assign({}, init || {}, { headers });
  };
  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : "";
    const method = (init && init.method) || "GET";
    if (!url || !isWriteApi(url, method)) return originalFetch(input, init);
    let resp = await originalFetch(input, withToken(init, auth.get()));
    if (resp.status !== 401) return resp;
    const hadToken = !!auth.get();
    if (hadToken) auth.clear();
    const token = await auth.ask(hadToken ? "Der gespeicherte Token ist nicht mehr gültig. Bitte den aktuellen Token eingeben." : null);
    if (!token) { resp.vigilanceCancelled = true; return resp; }
    resp = await originalFetch(input, withToken(init, token));
    if (resp.status === 401) toast("Token ungültig – es wurde nichts geändert.", true);
    else if (resp.status === 429) toast("Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.", true);
    else auth.set(token);
    return resp;
  };

  // ------------------------------------------------------------ helpers
  function toast(message, isError) {
    let box = document.querySelector(".toasts");
    if (!box) { box = document.createElement("div"); box.className = "toasts"; box.setAttribute("role", "status"); document.body.append(box); }
    const t = document.createElement("div");
    t.className = "toast" + (isError ? " error" : "");
    t.textContent = message;
    box.append(t);
    setTimeout(() => t.remove(), isError ? 7000 : 4000);
  }

  async function api(path, options) {
    const resp = await fetch(path, options);
    let data = null;
    try { data = await resp.json(); } catch (e) {}
    if (!resp.ok) {
      const err = new Error((data && data.detail && (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail))) || "HTTP " + resp.status);
      err.status = resp.status;
      err.cancelled = !!resp.vigilanceCancelled;
      throw err;
    }
    return data;
  }

  const SEV_LABEL = { CRITICAL: "Kritisch", HIGH: "Hoch", MEDIUM: "Mittel", LOW: "Niedrig", NONE: "Ohne Bewertung" };
  const dateFmt = new Intl.DateTimeFormat("de-CH", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  const dayFmt = new Intl.DateTimeFormat("de-CH", { day: "2-digit", month: "2-digit", year: "numeric" });
  const num = new Intl.NumberFormat("de-CH");

  const V = {
    api, toast,
    sevLabel: (s) => SEV_LABEL[s] || SEV_LABEL.NONE,
    n: (x) => num.format(x || 0),
    date(iso) { return iso ? dateFmt.format(new Date(iso)).replace(",", "") : "–"; },
    day(iso) { return iso ? dayFmt.format(new Date(iso)) : "–"; },
    ago(iso) {
      if (!iso) return "nie";
      const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
      if (s < 90) return "gerade eben";
      if (s < 3600) return "vor " + Math.round(s / 60) + " Min.";
      if (s < 86400) return "vor " + Math.round(s / 3600) + " Std.";
      const d = Math.round(s / 86400);
      return d === 1 ? "vor 1 Tag" : "vor " + d + " Tagen";
    },
    hoursSince(iso) { return iso ? (Date.now() - new Date(iso).getTime()) / 3600000 : Infinity; },
    plural(n, one, many) { return num.format(n || 0) + " " + (n === 1 ? one : many); },
    async copy(text) {
      try { await navigator.clipboard.writeText(text); toast("In die Zwischenablage kopiert."); }
      catch (e) { toast("Kopieren nicht möglich – bitte manuell markieren.", true); }
    },
    scanReason(h) {
      if (h.status !== "running") return "Gestoppt";
      if (h.last_scan_status === "no_ip") return "Nicht gescannt: keine IP-Adresse";
      if (h.last_scan_status === "unreachable") return "Nicht erreichbar" + (h.last_scan_error ? ": " + h.last_scan_error : "");
      if (!h.last_scan_status && !h.tools) return "Noch nicht gescannt";
      return null;
    },
    meter(h) {
      const parts = [["CRITICAL", h.patchable_critical], ["HIGH", h.patchable_high], ["MEDIUM", h.patchable_medium], ["LOW", h.patchable_low]];
      const total = parts.reduce((a, p) => a + p[1], 0);
      return total ? parts.filter((p) => p[1]).map((p) => ({ sev: p[0], pct: (100 * p[1]) / total })) : [];
    },
    // Trend chart as SVG path strings (no chart library)
    trendPaths(points, width, height) {
      if (!points || points.length < 2) return null;
      const keys = ["patchable", "without_fix", "fixed_total"];
      const pad = 6;
      const max = Math.max(1, ...points.flatMap((p) => keys.map((k) => p[k] || 0)));
      const x = (i) => pad + (i * (width - 2 * pad)) / (points.length - 1);
      const y = (v) => height - pad - ((v || 0) * (height - 2 * pad)) / max;
      const path = (k) => points.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p[k]).toFixed(1)).join(" ");
      return { patchable: path("patchable"), without_fix: path("without_fix"), fixed: path("fixed_total"), max };
    },
    notes: {
      goModule: "Über die Go-Sicherheitsdaten des Herstellers geprüft. Diese Daten sagen oft nicht, welches Betriebssystem betroffen ist.",
      debianData: "Debian hat ein gleichnamiges Paket, installiert ist aber der Build dieser Paketquelle. Vigilance nutzt die Debian-Daten; Treffer und Fix-Versionen können deshalb ungenau sein.",
      noData: "Für diese Pakete gibt es keine Sicherheitsdaten, die Vigilance abfragt. Lücken darin werden nicht erkannt.",
    },
    hostLabel(h) { return h.type === "node" ? "Proxmox-Host" : "CT " + h.vmid; },
    // ---- solution and removal risk (see /api remedy objects)
    replacementText(rem) {
      const r = rem.replacement;
      const base = "Ältere Version, die neben einer neueren installiert geblieben ist, zum Beispiel nach einem Release-Upgrade. Sie bekommt keine Updates mehr.";
      return r && r.packages.length ? base + " Bereits installiert: " + r.packages.join(", ") + "." : base;
    },
    riskHead(risk) {
      if (!risk || risk.status === "unknown") return "Risiko noch nicht geprüft";
      return risk.status === "ok" ? "Geprüft: unbedenklich" : "Vor dem Entfernen prüfen";
    },
    riskLines(risk) {
      if (!risk) return [];
      const when = risk.checked_at ? " (Scan vom " + V.date(risk.checked_at) + ")" : "";
      const lines = [];
      if (risk.status === "unknown") {
        lines.push(risk.errors && risk.errors.length
          ? "Die Prüfung beim Scan ist fehlgeschlagen: " + risk.errors.join("; ")
          : "Vigilance prüft das beim nächsten Scan. Bis dahin zuerst mit apt-get -s purge simulieren.");
        return lines;
      }
      const limited = "Laufende Programme anderer Benutzer konnten nicht geprüft werden, weil Vigilance hier ohne Root-Rechte prüft.";
      const kernel = "Kernel: Ein älterer Kernel ist die Rückfallebene, falls der neue nicht startet. Erst entfernen, wenn der neue Kernel nach einem Neustart läuft.";
      if (risk.status === "ok") {
        lines.push("apt würde nur " + risk.would_remove.join(", ") + " entfernen" + when + ".");
        if (risk.libraries_checked && !risk.process_check_limited) lines.push("Kein laufendes Programm benutzt die alte Bibliothek, und nichts unter /usr/local oder /opt verweist darauf.");
        if (risk.libraries_checked && risk.process_check_limited) lines.push("Nichts unter /usr/local oder /opt verweist auf die alte Bibliothek.");
        if (risk.process_check_limited && risk.libraries_checked) lines.push(limited);
        if (risk.kernel) lines.push(kernel);
        return lines;
      }
      (risk.running_kernel || []).forEach((k) => lines.push(k + " ist der laufende Kernel. Erst nach einem Neustart in einen neueren Kernel entfernen."));
      if (risk.extra.length) lines.push("apt würde zusätzlich entfernen, weil diese Pakete davon abhängen: " + risk.extra.join(", ") + ". Prüfe, ob du sie noch brauchst.");
      risk.in_use.forEach((u) => lines.push("Wird noch benutzt von PID " + u.pid + ": " + (u.command || "?") + ". Vermutlich seit dem Upgrade nicht neu gestartet. Es läuft nach dem Entfernen weiter; danach neu starten und prüfen."));
      if (risk.external.length) lines.push("Programme ausserhalb von apt verweisen auf die Bibliothek und starten danach vermutlich nicht mehr: " + risk.external.join(", ") + ".");
      if (risk.process_check_limited && risk.libraries_checked) lines.push(limited);
      if (risk.kernel && !(risk.running_kernel || []).length) lines.push(kernel);
      if (when) lines.push("Stand" + when + ".");
      return lines;
    },
    // Hosts with the same command and the same check result are shown as one block
    groupRemedies(hosts) {
      const groups = new Map();
      (hosts || []).forEach((h) => {
        const r = h.risk || {};
        const sig = JSON.stringify([h.action, h.command, h.target, h.replacement && h.replacement.packages, r.status, r.would_remove,
          r.extra, r.in_use, r.external, r.errors, r.not_reinstallable, r.libraries_checked]);
        if (!groups.has(sig)) groups.set(sig, { key: sig, hosts: [], rem: { action: "remove", ...h } });  // action from h wins
        groups.get(sig).hosts.push({ id: h.host_id, name: h.host });
      });
      return [...groups.values()];
    },
    // Is the fix offered by the host's package sources? (remedy.availability)
    availabilityText(rem) {
      const a = rem.availability;
      if (!a || a.status === "unknown" || a.status === "available") return "";
      const lists = a.lists_at ? " Stand der Paketlisten: " + V.date(a.lists_at) + "." : "";
      const where = a.missing_on && a.missing_on.length ? " Betrifft: " + a.missing_on.join(", ") + "." : "";
      if (a.status === "missing") return "Der Fix ist nicht in den Paketquellen" + (a.missing_on ? "" : " dieses Hosts")
        + ". apt kann ihn so nicht installieren; apt-cache policy zeigt, aus welcher Quelle das Paket stammt." + where + lists;
      if (a.status === "older") return "Die Paketquellen bieten nur eine ältere Version als den Fix." + where + lists;
      return "Nicht für alle betroffenen Pakete oder Hosts ist der Fix in den Paketquellen; der Befehl enthält nur die installierbaren." + where + lists;
    },
    reinstallText(risk, binaries) {
      if (!risk || risk.status === "unknown" || !risk.not_reinstallable) return "";
      const gone = risk.not_reinstallable;
      if (!gone.length) return "Lässt sich bei Bedarf wieder installieren, die Version ist noch in einer Paketquelle.";
      const all = !binaries || gone.length >= binaries.length;
      return "Nicht rückgängig zu machen: " + (all ? "Diese Version ist" : gone.join(", ") + " ist")
        + " in keiner Paketquelle mehr und lässt sich danach nicht wieder installieren.";
    },

    qs(params) {
      const u = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => { if (v !== "" && v !== null && v !== undefined && v !== false) u.set(k, v); });
      return u.toString();
    },
  };
  window.V = V;

  // ------------------------------------------------------------ page chrome
  document.addEventListener("DOMContentLoaded", async () => {
    auth.render();
    const el = document.getElementById("auth-state");
    if (el) el.addEventListener("click", async () => {
      if (auth.get()) { auth.clear(); toast("Bearbeitung gesperrt."); return; }
      const token = await auth.ask();
      if (!token) return;
      const resp = await originalFetch("/api/auth/me", { headers: { Authorization: "Bearer " + token } });
      if (resp.ok) { auth.set(token); toast("Bearbeitung freigeschaltet."); }
      else toast(resp.status === 429 ? "Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen." : "Token ungültig.", true);
    });
    const token = auth.get();
    if (token) {
      const resp = await originalFetch("/api/auth/me", { headers: { Authorization: "Bearer " + token } });
      if (resp.status === 401) auth.clear();
    }
  });
})();
