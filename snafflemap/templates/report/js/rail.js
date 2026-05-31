/* SM:rail — slide-over facet rail + saved views */
var SMRail = (function () {
  var PRESETS = [
    { name: "Crackable creds", q: "crackable:true" },
    { name: "Black/Red only", q: "sev:black|red" },
    { name: "New since baseline", q: "delta:new" },
    { name: "Writable shares", q: "type:share writable:true" },
  ];
  function init(APP) {
    var rail = document.getElementById("sm-rail");
    rail.textContent = "";
    rail.appendChild(SMDom.el("button", { class: "sm-rail-close", text: "✕", onclick: function () { rail.setAttribute("data-open", "false"); } }));
    rail.appendChild(SMDom.el("button", { class: "sm-rail-clear", text: "Clear all filters", onclick: function () { APP.query = ""; document.getElementById("sm-query").value = ""; APP.applyQuery(); } }));

    var views = SMDom.el("div", { class: "sm-rail-views" }, [SMDom.el("h4", { text: "Saved views" })]);
    PRESETS.concat(APP.store.state.views || []).forEach(function (v) {
      views.appendChild(SMDom.el("button", { class: "sm-view-chip", text: v.name, title: v.q,
        onclick: function () { APP.query = v.q; document.getElementById("sm-query").value = v.q; APP.applyQuery(); } }));
    });
    views.appendChild(SMDom.el("button", { class: "sm-view-save", text: "+ Save current",
      onclick: function () { var n = window.prompt("Name this view:"); if (n && n.trim()) { APP.store.state.views.push({ name: n, q: APP.query }); APP.store.save(); init(APP); } } }));
    rail.appendChild(views);

    var gb = SMDom.el("div", { class: "sm-rail-group" }, [SMDom.el("h4", { text: "Group by" })]);
    [["None", null], ["Severity", "severity"], ["Host", "host"], ["Rule", "rule"], ["Share", "share"]].forEach(function (g) {
      gb.appendChild(SMDom.el("button", { class: "sm-gb-chip" + (APP.groupBy === g[1] ? " active" : ""), text: g[0],
        onclick: function () { APP.groupBy = g[1]; init(APP); SMList.render(APP); } }));
    });
    rail.appendChild(gb);

    var sups = (APP.store.state.suppressions || []).filter(function (s) { return s.kind === "rule"; });
    if (sups.length) {
      var sup = SMDom.el("div", { class: "sm-rail-sup" }, [SMDom.el("h4", { text: "Suppressed" })]);
      sups.forEach(function (s) {
        var count = APP.model.findings.filter(function (r) { return r.rule === s.value; }).length;
        var chip = SMDom.el("button", { class: "sm-sup-chip", title: "Restore " + s.value + " (" + count + ")" }, [
          SMDom.el("span", { class: "sm-sup-x", text: "✕" }),
          SMDom.el("span", { class: "sm-sup-name", text: s.value }),
          SMDom.el("span", { class: "sm-sup-count", text: String(count) })]);
        chip.addEventListener("click", function () {
          APP.store.removeSuppression(s.value); APP.applyQuery(); init(APP);
        });
        sup.appendChild(chip);
      });
      var show = SMDom.el("label", { class: "sm-sup-show" }, [
        (function () { var c = SMDom.el("input", { type: "checkbox" }); c.checked = !!APP.showSuppressed;
          c.addEventListener("change", function () { APP.showSuppressed = c.checked; APP.applyQuery(); }); return c; })(),
        document.createTextNode(" Show suppressed (dimmed)")]);
      sup.appendChild(show);
      rail.appendChild(sup);
    }

    rail.appendChild(SMDom.el("div", { class: "sm-rail-facets", id: "sm-facets" }));
    refreshCounts(APP);
  }
  function refreshCounts(APP) {
    var box = document.getElementById("sm-facets"); if (!box) return;
    box.textContent = "";
    var facets = SMFacets.computeFacets(APP.filtered);
    Object.keys(SMFacets.FACET_FIELDS).forEach(function (facet) {
      var counts = facets[facet] || {}, keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
      if (!keys.length) return;
      var section = SMDom.el("div", { class: "sm-facet" }, [SMDom.el("h5", { text: facet })]);
      var active = SMFacets.activeFacetValues(APP.query, facet);
      keys.forEach(function (val) {
        var on = active.indexOf(val) !== -1;
        var chip = SMDom.el("label", { class: "sm-facet-item" + (on ? " on" : "") }, [
          SMDom.el("span", { class: "sm-facet-name", text: val }),
          SMDom.el("span", { class: "sm-facet-count", text: String(counts[val]) })]);
        chip.addEventListener("click", function () {
          APP.query = SMFacets.toggleFacet(APP.query, facet, val);
          document.getElementById("sm-query").value = APP.query; APP.applyQuery();
        });
        section.appendChild(chip);
      });
      box.appendChild(section);
    });
  }
  return { init: init, refreshCounts: refreshCounts, PRESETS: PRESETS };
})();
