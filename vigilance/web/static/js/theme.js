/* Hell/Dunkel. Läuft synchron im <head>, damit beim Laden nichts aufblitzt.
   Ohne gespeicherte Wahl folgt Vigilance der Einstellung des Systems. */
(function () {
  var KEY = "vigilance-theme";
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function stored() {
    try { var t = localStorage.getItem(KEY); return t === "light" || t === "dark" ? t : null; } catch (e) { return null; }
  }
  function system() { return media && media.matches ? "dark" : "light"; }
  function label(btn, theme) {
    var text = theme === "dark" ? "Zum hellen Modus wechseln" : "Zum dunklen Modus wechseln";
    btn.setAttribute("aria-label", text);
    btn.setAttribute("title", text);
  }
  function apply(theme) {
    root.dataset.theme = theme;
    var btn = document.getElementById("theme-toggle");
    if (btn) label(btn, theme);
  }

  apply(stored() || system());

  if (media && media.addEventListener) {
    media.addEventListener("change", function () { if (!stored()) apply(system()); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    label(btn, root.dataset.theme);
    btn.addEventListener("click", function () {
      var next = root.dataset.theme === "dark" ? "light" : "dark";
      try { localStorage.setItem(KEY, next); } catch (e) { /* gilt dann nur bis zum Neuladen */ }
      apply(next);
    });
  });
})();
