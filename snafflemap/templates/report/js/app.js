/* SM:app — bootstrap, view routing, theme, keyboard */
(function () {
  "use strict";
  var raw = document.getElementById("sm-data").textContent || "{}";
  var SM = JSON.parse(raw);
  var model = SMData.buildModel(SM);
  var store = SMStore.makeBrowserStore(SM);
  var APP = {
    SM: SM, model: model, store: store,
    query: "", groupBy: null, sortCol: null, sortDesc: false,
    selectedId: null, selection: {}, view: "workbench",
    showSuppressed: false,
    filtered: model.findings.slice(),
  };
  window.APP = APP;

  function applyQuery() {
    var pred = SMQuery.parseQuery(APP.query);
    APP.filtered = APP.model.findings.filter(function (r) {
      if (!APP.showSuppressed && store.isSuppressed(r)) return false;
      return pred(r);
    });
    if (window.SMList) SMList.render(APP);
    if (window.SMRail) SMRail.refreshCounts(APP);
    if (APP.view === "map" && window.SMMap) SMMap.render(APP);
    if (APP.view === "report" && window.SMReport) SMReport.render(APP);
    updateFilterIndicator();
  }
  APP.applyQuery = applyQuery;

  function updateFilterIndicator() {
    var btn = document.getElementById("smRailToggle");
    if (btn) btn.classList.toggle("has-filter", !!((APP.query && APP.query.trim()) || APP.groupBy));
  }

  function setRail(open) { document.getElementById("sm-rail").setAttribute("data-open", open ? "true" : "false"); }
  function toggleRail() { setRail(document.getElementById("sm-rail").getAttribute("data-open") !== "true"); }

  function setView(view) {
    APP.view = view;
    document.querySelectorAll("#sm-view-switch button").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-view") === view);
    });
    document.getElementById("sm-list").hidden = view !== "workbench";
    document.getElementById("sm-detail").hidden = view !== "workbench";
    document.getElementById("sm-map").hidden = view !== "map";
    document.getElementById("sm-report").hidden = view !== "report";
    if (view === "map" && window.SMMap) SMMap.render(APP);
    if (view === "report" && window.SMReport) SMReport.render(APP);
  }
  APP.setView = setView;

  function applyTheme(t) { document.documentElement.setAttribute("data-theme", t); localStorage.setItem(store.K.theme, t); }
  applyTheme(localStorage.getItem(store.K.theme) || "dark");

  function actionBtn(id, label, title, onClick) {
    return SMDom.el("button", { id: id, class: "sm-icon-btn", title: title, onclick: onClick, text: label });
  }
  var actions = document.getElementById("sm-actions");
  actions.appendChild(actionBtn("smActTheme", "◐", "Toggle theme", function () {
    applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
  }));
  actions.appendChild(actionBtn("smActSave", "↓H", "Save HTML", function () { window.SMStore_save_html(); }));
  actions.appendChild(actionBtn("smActExport", "↓T", "Export triage JSON", function () { if (window.SMActions) SMActions.exportTriage(APP); }));
  actions.appendChild(actionBtn("smActImport", "↑T", "Import triage JSON", function () { if (window.SMActions) SMActions.importTriage(APP); }));
  actions.appendChild(actionBtn("smActLoot", "↓L", "Download loot script", function () { if (window.SMActions) SMActions.lootScript(APP); }));

  // Filters affordance: a funnel button at the head of the header opens the
  // facet rail. Without this the rail is only reachable via the `f` shortcut.
  var header = document.getElementById("sm-header");
  var filterBtn = SMDom.el("button", { id: "smRailToggle", class: "sm-rail-toggle", title: "Filters  (f)",
    onclick: function () { toggleRail(); } });
  filterBtn.innerHTML =
    '<svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">' +
    '<path fill="currentColor" d="M1.3 2.2h13.4a.5.5 0 0 1 .38.82L10 9.3v4.2a.5.5 0 0 1-.72.45l-2.4-1.2a.5.5 0 0 1-.28-.45V9.3L.92 3.02a.5.5 0 0 1 .38-.82Z"/>' +
    '</svg><span class="sm-rail-dot" aria-hidden="true"></span>';
  header.insertBefore(filterBtn, header.firstChild);

  // Click-away scrim behind the rail.
  var scrim = document.getElementById("sm-rail-scrim");
  if (scrim) scrim.addEventListener("click", function () { setRail(false); });

  var qbar = document.getElementById("sm-query");
  qbar.addEventListener("input", function () { APP.query = qbar.value; applyQuery(); });

  document.querySelectorAll("#sm-view-switch button").forEach(function (b) {
    b.addEventListener("click", function () { setView(b.getAttribute("data-view")); });
  });

  document.addEventListener("keydown", function (ev) {
    var t = ev.target;
    // Never fire list shortcuts while typing in any editable control (B1).
    var typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
    if (typing) { if (ev.key === "Escape" && t.blur) t.blur(); return; }
    if (ev.key === "Escape") {
      if (document.getElementById("sm-rail").getAttribute("data-open") === "true") { ev.preventDefault(); setRail(false); }
      return;
    }
    if (ev.key === "/") { ev.preventDefault(); qbar.focus(); return; }
    if (ev.key === "f" || ev.key === "F") { ev.preventDefault(); toggleRail(); return; }
    if (window.SMList && SMList.handleKey) SMList.handleKey(APP, ev);
  });

  // Transient toast with an optional action (used by Suppress → Undo).
  window.SMToast = (function () {
    var host = null, timer = null;
    function ensure() { if (!host) { host = SMDom.el("div", { id: "sm-toast" }); document.body.appendChild(host); } return host; }
    function hide() { if (host) host.setAttribute("data-show", "false"); if (timer) { clearTimeout(timer); timer = null; } }
    function show(message, actionLabel, onAction) {
      var h = ensure(); h.textContent = "";
      h.appendChild(SMDom.el("span", { class: "sm-toast-msg", text: message }));
      if (actionLabel) h.appendChild(SMDom.el("button", { class: "sm-toast-act", text: actionLabel,
        onclick: function () { hide(); if (onAction) onAction(); } }));
      h.appendChild(SMDom.el("button", { class: "sm-toast-x", title: "Dismiss", text: "✕", onclick: hide }));
      h.setAttribute("data-show", "true");
      if (timer) clearTimeout(timer);
      timer = setTimeout(hide, 6000);
    }
    return { show: show, hide: hide };
  })();

  window.SMStore_save_html = function () {
    var clone = document.documentElement.cloneNode(true);
    var html = "<!DOCTYPE html>\n" + clone.outerHTML;
    var blob = new Blob([html], { type: "text/html;charset=utf-8" });
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "snafflemap-report-saved.html"; document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(a.href);
  };

  if (window.SMRail) SMRail.init(APP);
  applyQuery();
  setView("workbench");
})();
