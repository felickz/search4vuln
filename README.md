# search4vuln

A static, no-build GitHub Pages site that turns an org, enterprise, user or repo name into ready-made
[GitHub code search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
queries. The queries find repos that reference runtime versions affected by recent runtime CVEs.

Live site: https://felickz.github.io/search4vuln/

Current entries:

- **Java4Shell** (CVE-2026-114938): OpenJDK Base64 AVX-512 VBMI heap overwrite.
- **PHP2Shell** (CVE-2026-109618, CVE-2026-109619): PHP core memory corruption RCE.

## Important: results are candidates, not confirmation

A match means a repo references a runtime version that could be affected. It does not prove exposure.

- Floating tags (`17`, `8.3-apache`) change over time.
- Bundled JDKs and vendor products are invisible to code search.
- The real runtime is decided by CI, the base image or the host, not by what a repo declares.
- Code search only covers what GitHub has indexed (default branches, size limits apply).

Verify built images and hosts with `java -version`, `jcmd <PID> VM.version`, `php -v`, or an image scanner or SBOM.

## Using it

1. Choose a vulnerability.
2. Choose a scope and enter a value:

   | Scope | Qualifier added | Notes |
   | --- | --- | --- |
   | Organization | `org:NAME` | Full name, no partial match or regex |
   | Enterprise | `enterprise:NAME` | Repos owned by orgs in the enterprise, user-owned repos are excluded |
   | User | `user:NAME` | Full name |
   | Repository | `repo:OWNER/NAME` | Full name with owner |
   | None | (nothing) | Searches all of GitHub, very broad |

3. Pick a confidence tab (also stored in the link as `tab=pinned` or `tab=potential`):
   - **Pinned in affected range**: queries that match an explicit patch-level build inside the affected range (for example
     `eclipse-temurin:17.0.9_9` or `php:8.3.10-apache`). Fixed builds and unaffected lines cannot match. A short "ruled out" note lists
     what is not affected.
   - **Potential (unpinned or unknown)**: floating or major-only tags, language-level declarations, bundled-product images and similar.
     These show a possibly affected runtime line only. The real build is decided by the image pull time, CI, platform or host.

   Neither tab can confirm exploitability. Hardware (AVX-512 VBMI for Java4Shell), SAPI (mod_php for PHP2Shell), vendor-patched images,
   mitigations and reachability are invisible to code search.
4. Each query card shows what it finds, the query text and the full search URL. **Open on GitHub** is a normal link (opens in a new tab,
   and middle-click, ctrl/cmd-click and right-click work, so you can open many cards quickly). **Copy query** and **Copy URL** copy the text.
5. **Copy share link** copies a URL such as `?vuln=php2shell&tab=pinned&scope=org&value=acme`. Opening it prefills the form.

You must be signed in to GitHub to use code search, and you can only see repos you have access to.
Enterprise scope needs an enterprise you belong to.

## Files

| File | Purpose |
| --- | --- |
| `index.html`, `style.css`, `app.js` | The page (vanilla JS, no dependencies, works offline) |
| `lib.js` | Scope validation, query and URL builder (also used by the tests) |
| `vulns.js` | The vulnerability catalog: info panels and query cards |
| `test/test.js` | Node tests for the builder and regex sanity checks |

Run the tests with `node test/test.js` (no install needed). To preview locally, open `index.html` in a browser or run
`python -m http.server` in the repo root.

## Adding a vulnerability

Append an object to the array returned by `vulns.js`. Nothing else needs to change; the dropdown, info panel and cards are
generated from it.

```js
{
  id: "myvuln",                      // used in ?vuln=myvuln
  name: "MyVuln",                    // dropdown label
  title: "MyVuln: short description (CVE-XXXX-NNNN)",
  summary: "One or two sentences.",
  cves: [{ id: "CVE-XXXX-NNNN", ghsa: "GHSA-xxxx-xxxx-xxxx", text: "What it is." }],
  affected: ["..."], notAffected: ["..."], fixed: ["..."], mitigations: ["..."],
  reported: "", // optional extra note
  links: [{ label: "Advisory", url: "https://..." }],
  caveats: ["..."],
  ruledOut: ["What is NOT affected (shown on the Pinned tab)."],
  cards: [
    {
      id: "docker-images",           // unique within the vuln
      tab: "pinned",                 // "pinned" or "potential" (required)
      title: "Card title",
      finds: "What this query finds.",
      query: String.raw`/regex/ path:/(^|\/)Dockerfile$/`   // no scope qualifier
    }
  ]
}
```

Put a card on the **pinned** tab only when its regex needs an explicit patch version inside the affected range and cannot match fixed
builds; everything else goes on **potential**. Then add sample lines for each new card to `test/test.js` (lines that must match and
lines that must not, including boundary versions just below, at and above the fixed release) and run it.
The test fails if a card has no samples or no valid tab.

### Query writing rules

- A card `query` has no `org:`/`enterprise:` part. The page puts the scope first: `org:acme <query>`.
- Wrap regexes in slashes and escape literal slashes as `\/`. Use `String.raw` so backslashes stay readable.
- Keep regexes simple: character classes, alternation, groups, `?`, `*`, `+`. No lookaround or backreferences.
- Anchor on `FROM`, `image:`, `ARG`, `ENV`, `java-version:`, download URLs or `JAVA_HOME` instead of bare words such as `jdk17`, which
  match comments and code constants (for example `isAtLeastJDK17`).
- Put a version boundary before pinned versions (`[^0-9.]`) so `117.0.9` or `1.17.0.9` cannot match.
- Prefer `[0-9]` over shorthand classes and avoid relying on case-insensitivity.
- Use `path:` (glob like `path:*.md` or regex like `path:/(^|\/)pom\.xml$/`) to limit file types. Use `NOT` to exclude.
- Keep boolean logic in parentheses when mixing `OR` and `AND`.
- Do not use em dashes in any text.

## Limits and what is not verified

- The queries are validated against sample lines with JavaScript regexes and unit tests for the builder. They have not been
  executed against GitHub's search engine by the author of this repo (code search needs a signed-in session). If a card
  returns a syntax error or surprising results, please open an issue.
- Facts were taken from the public sources below. The primary pages (Calif, OpenJDK, php.net) could not be fetched
  directly while building, so some details come from secondary reports that quote them. Re-check the primary sources.
- Vendor fix status changes quickly. The Java4Shell fixed-build list reflects 18 Nov 2026.

## Sources

- Java4Shell: [Calif write-up](https://calif.io/java4shell),
  [OpenJDK advisory 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17),
  [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-java4shell-cve-2026-114938-20261119-csa-st/),
  [SentinelOne](https://www.sentinelone.com/blog/java4shell-vulnerability-in-openjdk-enables-rce-on-avx-512-cpus/)
- PHP2Shell: [Calif write-up](https://calif.io/php2shell/),
  [PHP security announcements](https://www.php.net/archive/2026.php),
  [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/),
  [Bishop Fox](https://bishopfox.com/blog/responder-guidance-for-php2shell)
- [GitHub code search syntax](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
