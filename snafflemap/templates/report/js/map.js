/* SM:map — host -> share -> finding tree, click a node to filter the workbench */
var SMMap = (function () {
  var SEV = SMSort.SEV;
  function worst(items) { var b = "Gray"; items.forEach(function (r) { if ((SEV[r.severity] == null ? 9 : SEV[r.severity]) < (SEV[b] == null ? 9 : SEV[b])) b = r.severity; }); return b; }
  function group(arr, key) { var o = {}; arr.forEach(function (r) { (o[r[key] || "(unknown)"] = o[r[key] || "(unknown)"] || []).push(r); }); return o; }

  function render(APP) {
    var host = document.getElementById("sm-map"); host.textContent = "";
    var recs = APP.filtered;
    var total = APP.model.findings.length;
    if (recs.length !== total) {
      host.appendChild(SMDom.el("div", { class: "sm-map-note",
        text: "Showing " + recs.length + " of " + total + " findings (filtered). Clear filters to see the full map." }));
    }
    if (!recs.length) { host.appendChild(SMDom.el("div", { class: "sm-map-note", text: "No findings match the current filter." })); return; }
    var byHost = group(recs, "host");
    Object.keys(byHost).sort().forEach(function (hn) {
      var hostItems = byHost[hn];
      var hEl = SMDom.el("details", { class: "sm-map-host", open: "" });
      hEl.appendChild(SMDom.el("summary", { class: "sm-map-sum sev-" + worst(hostItems).toLowerCase() }, [
        SMDom.el("span", { text: hn }), SMDom.el("span", { class: "sm-map-count", text: String(hostItems.length) })]));
      var byShare = group(hostItems, "share");
      Object.keys(byShare).sort().forEach(function (sh) {
        var shareItems = byShare[sh];
        var sEl = SMDom.el("details", { class: "sm-map-share" });
        var sum = SMDom.el("summary", { class: "sm-map-sum sev-" + worst(shareItems).toLowerCase() }, [
          SMDom.el("span", { text: sh === "(unknown)" ? "(host-level)" : sh }), SMDom.el("span", { class: "sm-map-count", text: String(shareItems.length) })]);
        var jump = SMDom.el("button", { class: "sm-map-jump", text: "filter →" });
        jump.addEventListener("click", function (ev) {
          ev.preventDefault(); ev.stopPropagation();
          APP.query = "host:" + hn + (sh !== "(unknown)" ? " share:" + sh : "");
          document.getElementById("sm-query").value = APP.query; APP.applyQuery(); APP.setView("workbench");
        });
        sum.appendChild(jump); sEl.appendChild(sum);
        SMSort.sortFindings(shareItems, null, false).forEach(function (r) {
          var leaf = SMDom.el("div", { class: "sm-map-leaf sev-" + r.severity.toLowerCase(), title: r.path, text: r.name });
          leaf.addEventListener("click", function () { APP.setView("workbench"); SMList.select(APP, r.id); });
          sEl.appendChild(leaf);
        });
        hEl.appendChild(sEl);
      });
      host.appendChild(hEl);
    });
  }
  return { render: render };
})();
