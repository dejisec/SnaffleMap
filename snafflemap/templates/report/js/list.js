/* SM:list — findings list with windowed rendering, sort, group-by, selection */
var SMList = (function () {
  // ROW_H must equal the .sm-row height set in app.css (Task 17). Used for windowed scroll math.
  var ROW_H = 30, OVERSCAN = 8;
  var SEV_CLASS = { Black: "sev-black", Red: "sev-red", Yellow: "sev-yellow", Green: "sev-green", Gray: "sev-gray" };

  function header(APP) {
    var cols = [["severity", "Sev"], ["name", "File"], ["rule", "Rule"], ["size", "Size"], ["modified", "Date"]];
    var tr = SMDom.el("div", { class: "sm-row sm-head" });
    tr.appendChild(SMDom.el("span", { class: "sm-cell sm-sel" }));
    cols.forEach(function (c) {
      var th = SMDom.el("span", { class: "sm-cell sm-col-" + c[0], text: c[1] });
      th.addEventListener("click", function () {
        if (APP.sortCol === c[0]) APP.sortDesc = !APP.sortDesc; else { APP.sortCol = c[0]; APP.sortDesc = false; }
        render(APP);
      });
      tr.appendChild(th);
    });
    tr.appendChild(SMDom.el("span", { class: "sm-cell sm-star" }));
    return tr;
  }

  function rowEl(APP, r) {
    var row = SMDom.el("div", { class: "sm-row " + (SEV_CLASS[r.severity] || ""), "data-fid": r.id });
    if (r.id === APP.selectedId) row.classList.add("selected");
    if (APP.store.isSuppressed(r)) row.classList.add("suppressed");
    var sel = SMDom.el("input", { type: "checkbox", class: "sm-rowsel" });
    sel.checked = !!APP.selection[r.id];
    sel.addEventListener("click", function (e) { e.stopPropagation(); APP.selection[r.id] = sel.checked; if (window.SMBulk) SMBulk.refresh(APP); });
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-sel" }, [sel]));
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-col-severity" }, [SMDom.el("span", { class: "sm-pill " + (SEV_CLASS[r.severity] || ""), text: r.severity })]));
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-col-name", title: r.path, text: r.name }));
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-col-rule", text: r.rule }));
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-col-size", text: r.size == null ? "" : humanSize(r.size) }));
    row.appendChild(SMDom.el("span", { class: "sm-cell sm-col-modified", text: (r.modified || "").slice(0, 10) }));
    var e = APP.store.state.triage[r.id];
    var star = SMDom.el("span", { class: "sm-cell sm-star" + (e && e.star ? " starred" : ""), text: e && e.star ? "★" : "☆" });
    star.addEventListener("click", function (ev) {
      ev.stopPropagation(); APP.store.toggleStar(r.id);
      var on = APP.store.entry(r.id).star;
      star.classList.toggle("starred", on); star.textContent = on ? "★" : "☆";
    });
    row.appendChild(star);
    row.addEventListener("click", function () { select(APP, r.id); });
    return row;
  }
  function humanSize(n) {
    var u = ["B", "KB", "MB", "GB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  }

  function select(APP, fid) {
    APP.selectedId = fid;
    document.querySelectorAll("#sm-list .sm-row.selected").forEach(function (n) { n.classList.remove("selected"); });
    var row = document.querySelector('#sm-list .sm-row[data-fid="' + cssEsc(fid) + '"]');
    if (row) row.classList.add("selected");
    ensureVisible(APP, fid);
    if (window.SMDetail) SMDetail.render(APP, fid);
  }
  function cssEsc(s) { return String(s).replace(/"/g, '\\"'); }

  // Scroll the selected row into view in both windowed (.sm-vp) and normal modes.
  function ensureVisible(APP, fid) {
    var idx = (APP._order || []).indexOf(fid);
    var vp = document.querySelector("#sm-list .sm-vp");
    if (vp && idx >= 0) {
      var top = idx * ROW_H, bot = top + ROW_H;
      if (top < vp.scrollTop) vp.scrollTop = top;
      else if (bot > vp.scrollTop + vp.clientHeight) vp.scrollTop = bot - vp.clientHeight;
      return;
    }
    var rown = document.querySelector('#sm-list .sm-row[data-fid="' + cssEsc(fid) + '"]');
    if (rown && rown.scrollIntoView) rown.scrollIntoView({ block: "nearest" });
  }

  function render(APP) {
    var host = document.getElementById("sm-list");
    host.textContent = "";
    host.appendChild(header(APP));
    var groups = SMSort.groupFindings(APP.filtered, APP.groupBy, APP.sortCol, APP.sortDesc);
    // Flat list of ids in *displayed* order — keyboard nav and ensureVisible rely on this.
    APP._order = groups.reduce(function (a, g) { return a.concat(g.items.map(function (r) { return r.id; })); }, []);
    if (!APP.groupBy && APP.filtered.length > 400) return renderWindowed(APP, host, groups[0].items);
    // Grouped/ungrouped non-windowed render with a soft cap so huge grouped
    // sets can't lock up the DOM (B11). Windowed path above has no cap.
    var CAP = 2000, shown = 0, capped = false;
    groups.forEach(function (g) {
      if (capped) return;
      if (g.key !== null) host.appendChild(SMDom.el("div", { class: "sm-group-head", text: g.key + "  (" + g.items.length + ")" }));
      for (var i = 0; i < g.items.length; i++) {
        if (shown >= CAP) { capped = true; break; }
        host.appendChild(rowEl(APP, g.items[i])); shown++;
      }
    });
    if (capped) host.appendChild(SMDom.el("div", { class: "sm-cap-note",
      text: "Showing first " + CAP + " of " + APP.filtered.length + " — refine your search or filters to see the rest." }));
    counter(APP);
  }

  function renderWindowed(APP, host, items) {
    var vp = SMDom.el("div", { class: "sm-vp" });
    var spacer = SMDom.el("div", { class: "sm-vp-spacer" });
    spacer.style.height = items.length * ROW_H + "px";
    var pool = SMDom.el("div", { class: "sm-vp-pool" });
    spacer.appendChild(pool); vp.appendChild(spacer); host.appendChild(vp);
    function draw() {
      var top = vp.scrollTop, h = vp.clientHeight;
      var start = Math.max(0, Math.floor(top / ROW_H) - OVERSCAN);
      var end = Math.min(items.length, Math.ceil((top + h) / ROW_H) + OVERSCAN);
      pool.textContent = ""; pool.style.transform = "translateY(" + start * ROW_H + "px)";
      for (var i = start; i < end; i++) pool.appendChild(rowEl(APP, items[i]));
    }
    vp.addEventListener("scroll", draw); draw(); counter(APP);
  }

  function counter(APP) {
    var n = APP.filtered.length, total = APP.model.findings.length;
    var el = document.getElementById("sm-count") || (function () {
      var c = SMDom.el("span", { id: "sm-count", class: "sm-count" }); document.getElementById("sm-actions").appendChild(c); return c;
    })();
    el.textContent = n + " / " + total;
  }

  function handleKey(APP, ev) {
    if (!APP.filtered.length) return;
    // Navigate in displayed order (sorted/grouped), not raw model order (B2).
    var ids = APP._order && APP._order.length ? APP._order : APP.filtered.map(function (r) { return r.id; });
    var i = ids.indexOf(APP.selectedId);
    if (ev.key === "j") { ev.preventDefault(); select(APP, ids[Math.min(ids.length - 1, i + 1)]); }
    else if (ev.key === "k") { ev.preventDefault(); select(APP, ids[Math.max(0, i - 1)]); }
    else if (ev.key === "s" && APP.selectedId) { APP.store.toggleStar(APP.selectedId); render(APP); ensureVisible(APP, APP.selectedId); }
    else if (ev.key === "x" && APP.selectedId) { APP.selection[APP.selectedId] = !APP.selection[APP.selectedId]; render(APP); ensureVisible(APP, APP.selectedId); if (window.SMBulk) SMBulk.refresh(APP); }
    else if ("12345".indexOf(ev.key) !== -1 && APP.selectedId) { APP.store.setStatus(APP.selectedId, SMStore.STATUSES[+ev.key - 1]); if (window.SMDetail) SMDetail.render(APP, APP.selectedId); }
  }
  return { render: render, select: select, handleKey: handleKey, humanSize: humanSize };
})();
