// Vulnerability catalog. To add an entry, append an object to the array below
// (see "Adding a vulnerability" in README.md). Each card "query" is a GitHub code search
// query WITHOUT the scope qualifier; the page prepends org:/enterprise:/user:/repo:.
// Regexes are kept simple (no lookarounds, no backreferences) for GitHub code search.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.VULNS = factory();
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  var raw = String.raw;

  // Shared path filters (GitHub path: regex).
  var P_CONTAINER = raw`path:/(^|\/)[^\/]*(Dockerfile|Containerfile)[^\/]*$|\.ya?ml$/`;
  var P_DOCKERFILE = raw`path:/(^|\/)[^\/]*(Dockerfile|Containerfile)[^\/]*$/`;
  var P_WORKFLOW = raw`path:/(^|\/)\.github\/workflows\/[^\/]+\.ya?ml$/`;

  // ---------- Java4Shell ----------
  var JV = "(17|21|25|27)";
  var JNAMES = "(temurin|corretto|openjdk|zulu|liberica|sapmachine|graalvm|semeru|dragonwell|jdk|jre|java)";
  var JSEP = raw`([-a-z_.:\/]*[-:_.\/])?`;

  var java4shell = {
    id: "java4shell",
    name: "Java4Shell",
    title: "Java4Shell: OpenJDK Base64 AVX-512 heap overwrite (CVE-2026-114938)",
    summary:
      "A memory corruption bug in the HotSpot x86-64 Base64 decoder intrinsic lets malformed Base64 input overwrite the heap, " +
      "which Calif turned into unauthenticated remote code execution against several default Java server installs.",
    cves: [
      { id: "CVE-2026-114938", text: "OpenJDK Base64 AVX-512 VBMI intrinsic heap overwrite. CVSS 4.0 9.2 (Calif), CVSS 3.1 8.1 (OpenJDK advisory)." }
    ],
    affected: [
      "OpenJDK-based builds 17.0.6 and later, plus Java 21, 25 and 27 (Oracle Java SE, OpenJDK, GraalVM, Corretto, Temurin, Microsoft, Zulu, Liberica, SapMachine, Red Hat and distro openjdk packages).",
      "Oracle Java 8 Enterprise Performance Pack (8u511b33-perf and similar).",
      "Only on x86-64 CPUs with AVX-512 VBMI (for example Intel Ice Lake and later, AMD Zen 4 and later). ARM64 (including Graviton) is not affected."
    ],
    notAffected: ["Standard Java 8, Java 11, and Java 17.0.0 to 17.0.5."],
    fixed: [
      "Oracle: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf.",
      "Amazon Corretto: 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4.",
      "As of 18 Nov 2026 other vendors (Temurin, Microsoft, Zulu, Liberica, SapMachine, Red Hat, distro packages) had not shipped fixes. Check each vendor."
    ],
    mitigations: [
      "-XX:-UseBASE64Intrinsics disables the vulnerable intrinsic. Recommended by Calif; not mentioned in the Oracle or OpenJDK advisories.",
      "-XX:UseAVX=2 also stops the overflow but disables all AVX-512 optimizations (also suggested by the Canadian Cyber Centre).",
      "These do not replace patching. Check hosts for the AVX-512 VBMI CPU flag."
    ],
    reported: "Public reporting says Calif achieved pre-auth RCE on default installs of Keycloak, Atlassian Jira and Confluence, JFrog Artifactory, Jenkins and PingFederate.",
    links: [
      { label: "Calif write-up", url: "https://calif.io/java4shell" },
      { label: "OpenJDK advisory 2026-11-17", url: "https://openjdk.org/groups/vulnerability/advisories/2026-11-17" },
      { label: "CSA research note (secondary)", url: "https://labs.cloudsecurityalliance.org/research/csa-research-note-java4shell-cve-2026-114938-20261119-csa-st/" },
      { label: "SentinelOne analysis (secondary)", url: "https://www.sentinelone.com/blog/java4shell-vulnerability-in-openjdk-enables-rce-on-avx-512-cpus/" }
    ],
    caveats: [
      "Floating tags such as 17 or 21 resolve to different patch levels over time. A match is not proof of an affected or unpatched build.",
      "Vendor products often bundle their own JDK, which these searches cannot see.",
      "Build targets (pom.xml, Gradle) are not the runtime. The runtime comes from CI, the base image or the host.",
      "Verify with: java -version, jcmd <PID> VM.version, an image scanner or an SBOM."
    ],
    cards: [
      {
        id: "docker-images",
        title: "Container base images: Java 17, 21, 25, 27",
        finds: "Dockerfiles that reference a Java runtime image or package with a major version of 17, 21, 25 or 27 (temurin, corretto, openjdk, zulu, liberica, sapmachine, graalvm, distroless java, apt/apk packages). Patch level is not checked.",
        query: raw`/${JNAMES}${JSEP}${JV}([^0-9]|$)/ ${P_DOCKERFILE}`
      },
      {
        id: "yaml-images",
        title: "Compose, Kubernetes and CI image: references",
        finds: "YAML files with an image: or container image line that names a Java runtime at 17, 21, 25 or 27.",
        query: raw`/image:.*${JNAMES}${JSEP}${JV}([^0-9]|$)/ path:/\.ya?ml$/`
      },
      {
        id: "pinned-17-0-6",
        title: "Pinned Java 17.0.6 or later image tags",
        finds: "Image tags pinned to Java 17.0.6 through 17.0.99, the affected range for 17. Tags at 17.0.21 and later may be Oracle or Corretto fixed builds, so check the vendor.",
        query: raw`/${JNAMES}${JSEP}17\.0\.([6-9]|[1-9][0-9])([^0-9]|$)/ ${P_CONTAINER}`
      },
      {
        id: "devcontainer",
        title: "Dev containers using Java 17, 21, 25, 27",
        finds: "devcontainer.json files that reference a Java image or feature at an affected major version.",
        query: raw`/${JNAMES}${JSEP}${JV}([^0-9]|$)/ path:/(^|\/)devcontainer\.json$/`
      },
      {
        id: "setup-java",
        title: "GitHub Actions setup-java and Java matrices",
        finds: "Workflows with java-version, java or jdk keys set to 17, 21, 25 or 27 (including inline matrices). CI runtime is often not the production runtime.",
        query: raw`/(java|jdk)([-_]version)?:.*[^0-9.]${JV}([^0-9]|$)/ ${P_WORKFLOW}`
      },
      {
        id: "version-files",
        title: ".java-version files",
        finds: "Repos with a .java-version file naming Java 17, 21, 25 or 27.",
        query: raw`/(^|[^0-9.])${JV}([^0-9]|$)/ path:/(^|\/)\.java-version$/`
      },
      {
        id: "tool-versions",
        title: ".sdkmanrc, .tool-versions and mise.toml pins",
        finds: "Tool version files that pin java to 17, 21, 25 or 27.",
        query: raw`/java[^0-9\n]*${JV}([^0-9]|$)/ path:/(^|\/)(\.sdkmanrc|\.tool-versions|\.?mise\.toml)$/`
      },
      {
        id: "maven",
        title: "Maven Java version properties",
        finds: "pom.xml files that set java.version, maven.compiler.release, source or target to 17, 21, 25 or 27. These are build targets, a hint that the project runs on a modern JDK.",
        query: raw`/<(java\.version|jdk\.version|maven\.compiler\.(release|source|target)|release|source|target)>${JV}([^0-9]|$)/ path:/(^|\/)pom\.xml$/`
      },
      {
        id: "gradle",
        title: "Gradle toolchains and Java compatibility",
        finds: "build.gradle and build.gradle.kts files that use JavaLanguageVersion.of, jvmToolchain, sourceCompatibility, targetCompatibility or jvmTarget with 17, 21, 25 or 27.",
        query: raw`/(JavaLanguageVersion\.of\(${JV}|(sourceCompatibility|targetCompatibility|jvmTarget|jvmToolchain)[^0-9]*${JV}([^0-9]|$))/ path:/(^|\/)build\.gradle(\.kts)?$/`
      },
      {
        id: "java-installs",
        title: "Scripted JDK installs (apt, apk, yum, sdkman)",
        finds: "Provisioning scripts and configs (excluding Markdown) that install openjdk, temurin, corretto or zulu packages at 17, 21, 25 or 27, or run sdk install java.",
        query: raw`/(openjdk|temurin|corretto|zulu|java|jdk)[-_]?${JV}([^0-9]|$)/ NOT path:*.md NOT ${P_DOCKERFILE}`
      },
      {
        id: "bundled-products",
        title: "Images of products reported as exploitable (bundled JDK)",
        finds: "Image references to Keycloak, Jenkins, Atlassian Jira and Confluence, JFrog Artifactory and PingFederate, which bundle their own JDK. A hint list only, not a complete product list.",
        query: raw`/(image:|FROM).*(keycloak\/keycloak|jenkins\/jenkins|atlassian\/(jira|confluence)|jfrog\/artifactory|pingidentity\/pingfederate)/ ${P_CONTAINER}`
      },
      {
        id: "mitigation-flags",
        title: "Mitigation flags already in use",
        finds: "Repos that already pass -XX:-UseBASE64Intrinsics or -XX:UseAVX=2. Review whether they are applied to every JVM.",
        query: raw`/(-XX:-UseBASE64Intrinsics|-XX:UseAVX=2)/`
      }
    ]
  };

  // ---------- PHP2Shell ----------
  var PV_ALL = raw`(5\.[4-6]|7\.[0-4]|8\.[0-5])`;
  var PV_EOL = raw`(5\.[4-6]|7\.[0-4]|8\.[01])`;
  var PIMG = raw`php[-a-z\/]*[:-]?`;
  // Patch releases below the fixed 21 Oct 2026 builds: 8.2.35, 8.3.36, 8.4.27, 8.5.12.
  var PBELOW = raw`(8\.2\.([0-9]|[12][0-9]|3[0-4])|8\.3\.([0-9]|[12][0-9]|3[0-5])|8\.4\.([0-9]|1[0-9]|2[0-6])|8\.5\.([0-9]|1[01]))`;

  var php2shell = {
    id: "php2shell",
    name: "PHP2Shell",
    title: "PHP2Shell: PHP core memory corruption RCE (CVE-2026-109618, CVE-2026-109619)",
    summary:
      "Two critical PHP core bugs allow unauthenticated remote code execution in default configurations. " +
      "All web SAPIs are affected (PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed), with mod_php at highest risk.",
    cves: [
      { id: "CVE-2026-109618", ghsa: "GHSA-w8hw-w9fx-j79w", text: "RCE via out-of-memory corruption while parsing a request. CVSS 4.0 9.2." },
      { id: "CVE-2026-109619", ghsa: "GHSA-6wmf-4rv5-p3rp", text: "RCE via stale global state reused by a later request in the same worker. CVSS 4.0 9.2." }
    ],
    affected: [
      "PHP 5.4.0 and later, in every web SAPI. Highest risk under Apache mod_php.",
      "Calif reports pre-auth RCE on WordPress, Drupal, Joomla, MediaWiki, Roundcube, Magento, phpMyAdmin, Nextcloud, Laravel, Symfony and WHMCS."
    ],
    notAffected: [],
    fixed: [
      "PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (21 Oct 2026).",
      "PHP 8.1 and older are no longer supported by the PHP project (minimal source backports exist for 7.4, 8.0 and 8.1). Distros and LTS vendors may backport fixes, check your vendor.",
      "Separate later releases on 19 Nov 2026 (8.5.13, 8.4.28, 8.3.37, 8.2.36) fix a different batch of issues, most needing non-default configuration. They are not the October CVEs. See the php.net archive for details."
    ],
    mitigations: [
      "Partial and temporary: memory_limit=-1, ideally via php_admin_value in the FPM pool or Apache config so apps cannot override it (do not use RLIMIT_AS or RLIMIT_DATA).",
      "session.upload_progress.enabled=0 (and fatal_error_backtraces=0 on PHP 8.5), then restart all workers.",
      "These do not replace patching."
    ],
    reported: "",
    links: [
      { label: "Calif write-up", url: "https://calif.io/php2shell/" },
      { label: "PHP security announcements 2026", url: "https://www.php.net/archive/2026.php" },
      { label: "JFrog Security Research (secondary)", url: "https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/" },
      { label: "Bishop Fox responder guidance (secondary)", url: "https://bishopfox.com/blog/responder-guidance-for-php2shell" }
    ],
    caveats: [
      "Floating tags such as 8.3 or 8.3-apache resolve to different patch levels over time. A match is not proof of an unpatched build.",
      "Distro PHP packages may carry backported fixes without changing the upstream version string.",
      "Runtime comes from CI, the base image or the host, not from composer.json constraints.",
      "Verify with: php -v, phpinfo(), an image scanner or an SBOM."
    ],
    cards: [
      {
        id: "docker-apache",
        title: "Apache (mod_php) PHP images, highest risk",
        finds: "Dockerfiles and YAML that use php or php-apache images with an apache variant, which run PHP as mod_php. Any tag, so check the patch level.",
        query: raw`/php[-a-z\/]*(apache|:[-a-z0-9.]*apache)/ ${P_CONTAINER}`
      },
      {
        id: "cms-images",
        title: "CMS and app images built on PHP",
        finds: "Image references to wordpress, drupal, joomla, mediawiki, nextcloud, phpmyadmin, roundcube or matomo (many default to Apache mod_php). A hint list, not complete.",
        query: raw`/(image:|FROM).*[^a-z0-9-](wordpress|drupal|joomla|mediawiki|nextcloud|phpmyadmin|roundcube|matomo)([^a-z0-9._\/-]|$)/ ${P_CONTAINER}`
      },
      {
        id: "docker-any",
        title: "Any PHP 5.4 to 8.5 image or package",
        finds: "Dockerfiles and YAML that reference php (php:8.3-fpm, php8.2-cli, frankenphp, serversideup/php, and similar) at any version from 5.4 to 8.5.",
        query: raw`/${PIMG}${PV_ALL}([^0-9]|$)/ ${P_CONTAINER}`
      },
      {
        id: "pinned-below-fixed",
        title: "Pinned tags below the fixed releases",
        finds: "Image tags pinned to 8.2.0 to 8.2.34, 8.3.0 to 8.3.35, 8.4.0 to 8.4.26 or 8.5.0 to 8.5.11, which are older than the 21 Oct 2026 fixes. Vendor backports can still apply.",
        query: raw`/php[-a-z\/]*:${PBELOW}([^0-9]|$)/ ${P_CONTAINER}`
      },
      {
        id: "eol",
        title: "End-of-life lines: PHP 5.x, 7.x, 8.0, 8.1",
        finds: "Images and packages on PHP lines no longer supported upstream. Fixes exist only as minimal source backports or via vendor LTS.",
        query: raw`/${PIMG}${PV_EOL}([^0-9]|$)/ ${P_CONTAINER}`
      },
      {
        id: "composer-php",
        title: "composer.json PHP requirement or platform",
        finds: "Projects that declare a PHP version in require.php or config.platform.php. A broad list of PHP projects, constraints are lower bounds and not the runtime.",
        query: raw`/"php"\s*:\s*"[^"]*[0-9]/ path:/(^|\/)composer\.json$/`
      },
      {
        id: "composer-apps",
        title: "composer.json requiring affected CMS or frameworks",
        finds: "Projects requiring Laravel, Symfony, Drupal core, WordPress (roots or johnpbloch), Magento, MediaWiki, Joomla, Nextcloud, phpMyAdmin or Roundcube. Apps Calif reports as exploitable. A hint list, not complete.",
        query: raw`/"(laravel\/framework|symfony\/(symfony|framework-bundle)|drupal\/(core|core-recommended)|roots\/wordpress|johnpbloch\/wordpress(-core)?|magento\/product-community-edition|mediawiki\/core|joomla\/joomla-cms|nextcloud\/server|phpmyadmin\/phpmyadmin|roundcube\/roundcubemail)"/ path:/(^|\/)composer\.json$/`
      },
      {
        id: "setup-php",
        title: "GitHub Actions setup-php and PHP matrices",
        finds: "Workflows with php-version or php keys set to a version from 5.4 to 8.5. CI runtime is often not the production runtime.",
        query: raw`/php(-version)?:.*[^0-9.]${PV_ALL}([^0-9]|$)/ ${P_WORKFLOW}`
      },
      {
        id: "php-version-file",
        title: ".php-version files",
        finds: "Repos with a .php-version file naming a version from 5.4 to 8.5.",
        query: raw`/(^|[^0-9.])${PV_ALL}/ path:/(^|\/)\.php-version$/`
      },
      {
        id: "tool-versions",
        title: ".tool-versions and mise.toml PHP pins",
        finds: "Tool version files that pin php to a version from 5.4 to 8.5.",
        query: raw`/php[^0-9\n]*${PV_ALL}([^0-9]|$)/ path:/(^|\/)(\.tool-versions|\.?mise\.toml)$/`
      },
      {
        id: "mod-php",
        title: "mod_php in Apache config or package installs",
        finds: "Configs and scripts that install or load mod_php (libapache2-mod-php, LoadModule php_module). The SAPI at highest risk. Markdown is excluded.",
        query: raw`/(libapache2-mod-php|LoadModule\s+php[0-9]*_module)/ NOT path:*.md`
      },
      {
        id: "mitigation-config",
        title: "Mitigation settings already in config",
        finds: "php.ini, FPM pool, .htaccess, Dockerfile or other config that sets memory_limit to -1 or turns session.upload_progress.enabled off. Review whether they are enforced for every pool and cannot be overridden.",
        query: raw`/(memory_limit[^\n]{0,20}-1|upload_progress\.enabled[^\n]{0,20}(0|[Oo]ff|false|[Nn]o))/ NOT path:*.md`
      }
    ]
  };

  return [java4shell, php2shell];
});
