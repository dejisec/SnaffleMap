/* SM:report — clean narrative deliverable view (print-friendly) */
var SMReport = (function () {
  var SEV_ORDER = ["Black", "Red", "Yellow", "Green", "Gray"];
  function render(APP) {
    var host = document.getElementById("sm-report"); host.textContent = "";
    var useFiltered = true;
    var ctrl = SMDom.el("div", { class: "sm-rep-ctrl" }, [
      SMDom.el("button", { class: "sm-rep-print", text: "Print / Save PDF", onclick: function () { window.print(); } })]);
    var scope = SMDom.el("label", { class: "sm-rep-scope" }, [
      (function () { var c = SMDom.el("input", { type: "checkbox" }); c.checked = true;
        c.addEventListener("change", function () { useFiltered = c.checked; body(); }); return c; })(),
      document.createTextNode(" current filter only")]);
    ctrl.appendChild(scope); host.appendChild(ctrl);
    var content = SMDom.el("div", { class: "sm-rep-body" }); host.appendChild(content);

    function body() {
      content.textContent = "";
      var recs = useFiltered ? APP.filtered : APP.model.findings;
      content.appendChild(SMDom.el("h1", { text: "SnaffleMap — " + APP.store.state.reportId }));
      var counts = {}; recs.forEach(function (r) { counts[r.severity] = (counts[r.severity] || 0) + 1; });
      content.appendChild(SMDom.el("p", { class: "sm-rep-summary",
        text: recs.length + " findings · " + SEV_ORDER.filter(function (s) { return counts[s]; })
          .map(function (s) { return counts[s] + " " + s; }).join(" · ") }));

      var resolved = (APP.SM && APP.SM.resolved) || [];
      var deltaCounts = {}; recs.forEach(function (r) { if (r.delta_status) deltaCounts[r.delta_status] = (deltaCounts[r.delta_status] || 0) + 1; });
      var deltaKeys = Object.keys(deltaCounts);
      if (deltaKeys.length || resolved.length) {
        content.appendChild(SMDom.el("p", { class: "sm-rep-delta",
          text: "Delta: " + deltaKeys.map(function (k) { return deltaCounts[k] + " " + k; })
            .concat(resolved.length ? [resolved.length + " resolved"] : []).join(" · ") }));
      }

      SEV_ORDER.forEach(function (sev) {
        var grp = SMSort.sortFindings(recs.filter(function (r) { return r.severity === sev; }), null, false);
        if (!grp.length) return;
        content.appendChild(SMDom.el("h2", { class: "sev-" + sev.toLowerCase(), text: sev + " (" + grp.length + ")" }));
        grp.forEach(function (r) {
          var block = SMDom.el("div", { class: "sm-rep-finding" }, [
            SMDom.el("div", { class: "sm-rep-path" }, [SMDom.el("code", { text: r.path })]),
            SMDom.el("div", { class: "sm-rep-meta", text: r.rule + (r.size != null ? " · " + SMList.humanSize(r.size) : "") })]);
          if (r.snippet) { var pre = SMDom.el("pre", { class: "sm-rep-snippet" }); SMDom.highlightInto(pre, r.snippet, r.matched); block.appendChild(pre); }
          content.appendChild(block);
        });
      });

      if (resolved.length) {
        content.appendChild(SMDom.el("h2", { class: "sm-rep-resolved-h", text: "Resolved — gone since baseline (" + resolved.length + ")" }));
        resolved.forEach(function (r) {
          var p = r.file_path || r.share_path || r.dir_path || "";
          content.appendChild(SMDom.el("div", { class: "sm-rep-finding sm-rep-resolved" }, [
            SMDom.el("div", { class: "sm-rep-path" }, [SMDom.el("code", { text: p })]),
            SMDom.el("div", { class: "sm-rep-meta", text: (r.severity || "") + " · " + (r.rule_name || "") })]));
        });
      }
    }
    body();
  }
  return { render: render };
})();
