(function () {
  var lib = window.Search4Vuln;
  var vulns = window.VULNS;
  var $ = function (id) { return document.getElementById(id); };
  var els = { vuln: $("vuln"), scope: $("scope"), value: $("value"), valueLabel: $("value-label"), help: $("scope-help"),
    error: $("scope-error"), info: $("info"), cards: $("cards"), share: $("share") };

  function el(tag, props, children) {
    var n = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) { n[k] = props[k]; });
    (children || []).forEach(function (c) { n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }

  function list(title, items) {
    if (!items || !items.length) return null;
    var wrap = el("div", {}, [el("h3", { textContent: title })]);
    wrap.appendChild(el("ul", {}, items.map(function (t) { return el("li", { textContent: t }); })));
    return wrap;
  }

  function copy(text, button) {
    var done = function () {
      var old = button.textContent;
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = old; }, 1200);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  }

  function fallbackCopy(text) {
    var ta = el("textarea", { value: text });
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  function currentVuln() {
    return vulns.filter(function (v) { return v.id === els.vuln.value; })[0] || vulns[0];
  }

  function renderInfo(v) {
    els.info.textContent = "";
    var panel = el("details", { className: "panel", open: true }, [el("summary", { textContent: v.title }), el("p", { textContent: v.summary })]);
    var cves = el("div", {}, [el("h3", { textContent: "CVEs" })]);
    cves.appendChild(el("ul", {}, v.cves.map(function (c) {
      return el("li", { textContent: c.id + (c.ghsa ? " (" + c.ghsa + ")" : "") + ": " + c.text });
    })));
    panel.appendChild(cves);
    [list("Affected", v.affected), list("Not affected", v.notAffected), list("Fixed versions", v.fixed),
      list("Temporary mitigations", v.mitigations), list("Caveats", v.caveats)].forEach(function (s) { if (s) panel.appendChild(s); });
    if (v.reported) panel.appendChild(el("p", { className: "muted", textContent: v.reported }));
    var links = el("div", {}, [el("h3", { textContent: "Sources" })]);
    links.appendChild(el("ul", {}, v.links.map(function (l) {
      return el("li", {}, [el("a", { href: l.url, textContent: l.label, target: "_blank", rel: "noopener noreferrer" })]);
    })));
    panel.appendChild(links);
    els.info.appendChild(panel);
  }

  function renderCards(v, q) {
    els.cards.textContent = "";
    var tabs = el("div", { className: "tabs", role: "tablist" });
    lib.TABS.forEach(function (t) {
      var count = v.cards.filter(function (c) { return c.tab === t.id; }).length;
      var b = el("button", { type: "button", className: "tab", role: "tab", textContent: t.label + " (" + count + ")" });
      b.setAttribute("aria-selected", String(t.id === currentTab));
      b.addEventListener("click", function () { currentTab = t.id; update(); });
      tabs.appendChild(b);
    });
    els.cards.appendChild(tabs);
    var tab = lib.TABS.filter(function (t) { return t.id === currentTab; })[0];
    els.cards.appendChild(el("p", { className: "tab-intro", textContent: tab.intro }));
    if (currentTab === "pinned" && v.ruledOut && v.ruledOut.length) {
      var ruled = el("div", { className: "ruled-out" }, [el("strong", { textContent: "Ruled out or lower concern" })]);
      ruled.appendChild(el("ul", {}, v.ruledOut.map(function (t) { return el("li", { textContent: t }); })));
      els.cards.appendChild(ruled);
    }
    v.cards.filter(function (c) { return c.tab === currentTab; }).forEach(function (card) {
      var shown = lib.buildQuery(q.ok ? q.qualifier : "<scope>", card.query);
      var open = el("button", { type: "button", className: "primary", textContent: "Open on GitHub", disabled: !q.ok });
      open.addEventListener("click", function () { window.open(lib.searchUrl(shown), "_blank", "noopener,noreferrer"); });
      var cp = el("button", { type: "button", textContent: "Copy query", disabled: !q.ok });
      cp.addEventListener("click", function () { copy(shown, cp); });
      els.cards.appendChild(el("article", { className: "card" }, [
        el("h3", { textContent: card.title }),
        el("p", { textContent: card.finds }),
        el("pre", { className: "query", textContent: shown }),
        el("div", { className: "actions" }, [open, cp])
      ]));
    });
  }

  var currentTab = lib.TABS[0].id;

  function readState() {
    var p = new URLSearchParams(location.search);
    var vuln = p.get("vuln");
    if (vulns.some(function (v) { return v.id === vuln; })) els.vuln.value = vuln;
    var scope = p.get("scope");
    if (scope && lib.SCOPES[scope]) els.scope.value = scope;
    els.value.value = p.get("value") || "";
    var tab = p.get("tab");
    if (lib.TABS.some(function (t) { return t.id === tab; })) currentTab = tab;
  }

  function shareUrl() {
    var p = new URLSearchParams();
    p.set("vuln", els.vuln.value);
    p.set("tab", currentTab);
    p.set("scope", els.scope.value);
    if (els.scope.value !== "none" && els.value.value.trim()) p.set("value", els.value.value.trim());
    return "?" + p;
  }

  var shownInfo = null;

  function update() {
    var type = els.scope.value;
    var scope = lib.SCOPES[type];
    var needsValue = !!scope.qualifier;
    els.valueLabel.hidden = !needsValue;
    els.value.placeholder = scope.hint || "";
    els.help.textContent = scope.help || "Searches all public code on GitHub. Pick a narrower scope for a useful result.";
    var q = lib.scopeQualifier(type, els.value.value);
    var showError = !q.ok && els.value.value.trim() !== "";
    els.error.hidden = !showError;
    els.error.textContent = showError ? q.error : "";
    var v = currentVuln();
    if (v.id !== shownInfo) { renderInfo(v); shownInfo = v.id; }
    renderCards(v, q);
    history.replaceState(null, "", shareUrl());
  }

  vulns.forEach(function (v) { els.vuln.appendChild(el("option", { value: v.id, textContent: v.name })); });
  Object.keys(lib.SCOPES).forEach(function (k) { els.scope.appendChild(el("option", { value: k, textContent: lib.SCOPES[k].label })); });
  els.scope.value = "org";
  readState();
  ["change", "input"].forEach(function (evt) {
    els.vuln.addEventListener(evt, update);
    els.scope.addEventListener(evt, update);
    els.value.addEventListener(evt, update);
  });
  els.share.addEventListener("click", function () { copy(new URL(shareUrl(), location.href).href, els.share); });
  update();
})();
