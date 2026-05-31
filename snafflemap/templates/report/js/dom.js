/* SM:dom — DOM helpers; pure functions are unit-tested, builders used in browser */
var SMDom = (function () {
  function escapeText(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function highlightParts(text, term) {
    text = String(text == null ? "" : text);
    if (!term) return [{ t: text, hit: false }];
    var out = [], lc = text.toLowerCase(), lt = term.toLowerCase(), i = 0, idx;
    while ((idx = lc.indexOf(lt, i)) !== -1) {
      if (idx > i) out.push({ t: text.slice(i, idx), hit: false });
      out.push({ t: text.slice(idx, idx + term.length), hit: true });
      i = idx + term.length;
    }
    if (i < text.length) out.push({ t: text.slice(i), hit: false });
    return out.length ? out : [{ t: text, hit: false }];
  }
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "class") n.className = attrs[k];
      else if (k === "text") n.textContent = attrs[k];
      else if (k.slice(0, 2) === "on" && typeof attrs[k] === "function")
        n.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] != null) n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) {
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }
  function highlightInto(node, text, term) {
    highlightParts(text, term).forEach(function (p) {
      if (p.hit) node.appendChild(el("mark", { text: p.t }));
      else node.appendChild(document.createTextNode(p.t));
    });
    return node;
  }
  function copy(textToCopy) {
    if (navigator.clipboard) return navigator.clipboard.writeText(textToCopy);
    var ta = document.createElement("textarea"); ta.value = textToCopy;
    document.body.appendChild(ta); ta.select(); document.execCommand("copy");
    document.body.removeChild(ta);
  }
  return { escapeText: escapeText, highlightParts: highlightParts, el: el, highlightInto: highlightInto, copy: copy };
})();
if (typeof module !== "undefined" && module.exports) module.exports = SMDom;
if (typeof globalThis !== "undefined") globalThis.SMDom = SMDom;
