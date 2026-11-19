// Query and URL builder. Works in the browser (window.Search4Vuln) and in Node (require).
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Search4Vuln = factory();
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/;
  var REPO_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}\/[A-Za-z0-9._-]{1,100}$/;

  // Maps a scope type to the GitHub code search qualifier it produces.
  var SCOPES = {
    none: { label: "Everything on GitHub (very broad)", qualifier: null },
    org: { label: "Organization", qualifier: "org", pattern: NAME_RE, hint: "my-org", help: "Full organization name. Partial names and regex are not supported by GitHub." },
    enterprise: { label: "Enterprise", qualifier: "enterprise", pattern: NAME_RE, hint: "my-enterprise", help: "Enterprise slug. Searches repos owned by orgs in the enterprise (user-owned repos are excluded)." },
    user: { label: "User", qualifier: "user", pattern: NAME_RE, hint: "octocat", help: "Full user name. Searches repos owned by that user." },
    repo: { label: "Repository", qualifier: "repo", pattern: REPO_RE, hint: "owner/name", help: "Full repository name including the owner." }
  };

  // Confidence tabs. A repo can never confirm exploitability, so labels only speak of version evidence.
  var TABS = [
    {
      id: "pinned",
      label: "Pinned in affected range",
      intro: "These queries match an explicit patch-level build that falls inside the affected range, so the referenced runtime contains the " +
        "vulnerable code unless it is a vendor-fixed build. This is the strongest signal repo content can give, but a repo can never confirm " +
        "exploitability: hardware, server configuration, vendor-patched images, mitigations and network reachability are invisible to code search."
    },
    {
      id: "potential",
      label: "Potential (unpinned or unknown)",
      intro: "These queries show a possibly affected runtime line: floating or major-only tags, language-level declarations, bundled-product images " +
        "and similar. The actual build is decided by the image pull time, CI, platform or host, so every hit needs an artifact-level check " +
        "(java -version, jcmd <PID> VM.version, php -v, an image scanner or an SBOM)."
    }
  ];

  // Returns { ok, qualifier, error }. qualifier is "" for the "none" scope.
  function scopeQualifier(type, value) {
    var scope = SCOPES[type];
    if (!scope) return { ok: false, qualifier: "", error: "Unknown scope type." };
    if (!scope.qualifier) return { ok: true, qualifier: "" };
    var v = String(value || "").trim();
    if (!v) return { ok: false, qualifier: "", error: "Enter a value for the " + scope.label.toLowerCase() + " scope." };
    if (!scope.pattern.test(v)) return { ok: false, qualifier: "", error: "That does not look like a valid " + scope.label.toLowerCase() + " (expected e.g. " + scope.hint + ")." };
    return { ok: true, qualifier: scope.qualifier + ":" + v };
  }

  // Scope qualifier first, then the card query.
  function buildQuery(qualifier, body) {
    return (qualifier ? qualifier + " " : "") + body;
  }

  function searchUrl(query) {
    return "https://github.com/search?type=code&q=" + encodeURIComponent(query);
  }

  return { SCOPES: SCOPES, TABS: TABS, scopeQualifier: scopeQualifier, buildQuery: buildQuery, searchUrl: searchUrl };
});
