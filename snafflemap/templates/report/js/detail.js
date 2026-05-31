/* SM:detail — detail pane for the selected finding */
var SMDetail = (function () {
  function row(label, valueNode) {
    return SMDom.el("div", { class: "sm-d-row" }, [
      SMDom.el("span", { class: "sm-d-label", text: label }), valueNode]);
  }
  // ISO timestamp -> "YYYY-MM-DD HH:MM" (drops seconds / timezone noise).
  function fmtDate(s) {
    var str = String(s || "");
    var d = str.slice(0, 10), t = str.slice(11, 16);
    return t ? d + " " + t : d;
  }
  function copyBtn(text) {
    var b = SMDom.el("button", { class: "sm-copy", title: "Copy", text: "⧉" });
    b.addEventListener("click", function () { SMDom.copy(text); });
    return b;
  }
  function render(APP, fid) {
    var pane = document.getElementById("sm-detail");
    pane.setAttribute("data-open", "true");
    pane.textContent = "";
    var r = APP.model.findings.find(function (x) { return x.id === fid; });
    if (!r) { pane.appendChild(SMDom.el("p", { class: "sm-d-empty", text: "Select a finding" })); return; }

    pane.appendChild(SMDom.el("div", { class: "sm-d-head" }, [
      SMDom.el("span", { class: "sm-pill sev-" + r.severity.toLowerCase(), text: r.severity }),
      SMDom.el("span", { class: "sm-d-score", text: "score " + r.score + (r.tier ? " · " + r.tier : "") }),
    ]));

    var pathWrap = SMDom.el("div", { class: "sm-d-path" }, [
      SMDom.el("code", { text: r.path }), copyBtn(r.path)]);
    pane.appendChild(pathWrap);

    pane.appendChild(row("Rule", SMDom.el("span", { text: r.rule })));
    pane.appendChild(row("Host", SMDom.el("span", { text: r.host + " · " + r.share })));
    if (r.size != null) pane.appendChild(row("Size", SMDom.el("span", { text: SMList.humanSize(r.size) })));
    if (r.modified) pane.appendChild(row("Modified", SMDom.el("span", { text: fmtDate(r.modified) })));
    if (r.delta_status) pane.appendChild(row("Delta", SMDom.el("span", { class: "sm-delta " + r.delta_status, text: r.delta_status })));

    if (r.snippet) {
      var pre = SMDom.el("pre", { class: "sm-d-snippet" });
      SMDom.highlightInto(pre, r.snippet, r.matched);
      var unesc = SMDom.el("label", { class: "sm-d-unescape" }, [
        (function () { var c = SMDom.el("input", { type: "checkbox" });
          c.addEventListener("change", function () {
            pre.textContent = "";
            var text = c.checked ? r.snippet.replace(/\\r\\n|\\n/g, "\n").replace(/\\t/g, "\t") : r.snippet;
            SMDom.highlightInto(pre, text, r.matched);
          }); return c; })(),
        document.createTextNode(" unescape")]);
      pane.appendChild(SMDom.el("div", { class: "sm-d-snipwrap" }, [unesc, pre]));
    }

    if (r.actions && r.actions.length) {
      var acts = SMDom.el("div", { class: "sm-d-actions" });
      r.actions.forEach(function (a) {
        var line = SMDom.el("div", { class: "sm-d-action" }, [
          SMDom.el("code", { text: a.cmd }), copyBtn(a.cmd)]);
        line.setAttribute("title", a.label || "");
        acts.appendChild(line);
      });
      pane.appendChild(row("Actions", acts));
    }
    var loot = SMStore.lootCommands(r.path);
    if (loot.length) {
      var lwrap = SMDom.el("div", { class: "sm-d-actions" });
      loot.forEach(function (cmd) { lwrap.appendChild(SMDom.el("div", { class: "sm-d-action" }, [SMDom.el("code", { text: cmd }), copyBtn(cmd)])); });
      pane.appendChild(row("Retrieve", lwrap));
    }

    pane.appendChild(triageControls(APP, r));
  }

  function triageControls(APP, r) {
    var e = APP.store.entry(r.id);
    var wrap = SMDom.el("div", { class: "sm-d-triage" });
    var sel = SMDom.el("select", { class: "sm-status" });
    SMStore.STATUSES.forEach(function (s) {
      var o = SMDom.el("option", { value: s, text: s }); if (e.status === s) o.selected = true; sel.appendChild(o);
    });
    sel.addEventListener("change", function () { APP.store.setStatus(r.id, sel.value); SMList.render(APP); });
    wrap.appendChild(row("Status", sel));

    var starBtn = SMDom.el("button", { class: "sm-d-starbtn" + (e.star ? " starred" : ""), text: e.star ? "★ Starred" : "☆ Star" });
    starBtn.addEventListener("click", function () { APP.store.toggleStar(r.id); SMDetail.render(APP, r.id); SMList.render(APP); });
    wrap.appendChild(starBtn);

    if (r.rule) {
      var supCount = APP.model.findings.filter(function (x) { return x.rule === r.rule; }).length;
      var supBtn = SMDom.el("button", { class: "sm-d-supbtn", text: "⊘ Suppress rule (" + supCount + ")",
        title: "Hide all " + supCount + " findings for rule " + r.rule });
      supBtn.addEventListener("click", function () {
        var rule = r.rule;
        APP.store.suppressRule(rule); APP.selectedId = null; APP.applyQuery();
        var pane = document.getElementById("sm-detail"); pane.setAttribute("data-open", "false"); pane.textContent = "";
        if (window.SMRail) SMRail.init(APP);
        if (window.SMToast) SMToast.show("Suppressed " + rule + " · " + supCount + " hidden", "Undo", function () {
          APP.store.removeSuppression(rule); APP.applyQuery(); if (window.SMRail) SMRail.init(APP);
        });
      });
      wrap.appendChild(supBtn);
    }

    var noteIn = SMDom.el("input", { class: "sm-note-in", type: "text", placeholder: "Add note…" });
    noteIn.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" && noteIn.value.trim()) { APP.store.addNote(r.id, noteIn.value.trim()); noteIn.value = ""; SMDetail.render(APP, r.id); }
    });
    wrap.appendChild(noteIn);
    (e.notes || []).forEach(function (n) {
      wrap.appendChild(SMDom.el("div", { class: "sm-note" }, [
        SMDom.el("span", { class: "sm-note-by", text: (n.by || "") + " · " + (n.at || "").slice(0, 16) }),
        SMDom.el("div", { text: n.text || "" })]));
    });
    return wrap;
  }
  return { render: render };
})();
