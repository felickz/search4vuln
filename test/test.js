// Run with: node test/test.js
const assert = require("assert");
const lib = require("../lib.js");
const vulns = require("../vulns.js");

let failures = 0;
function check(name, fn) {
  try { fn(); } catch (e) { failures++; console.error("FAIL " + name + ": " + e.message); }
}

// ---- scope and URL builder ----
check("scope org", () => assert.deepStrictEqual(lib.scopeQualifier("org", " acme "), { ok: true, qualifier: "org:acme" }));
check("scope enterprise", () => assert.strictEqual(lib.scopeQualifier("enterprise", "my-ent").qualifier, "enterprise:my-ent"));
check("scope user", () => assert.strictEqual(lib.scopeQualifier("user", "octocat").qualifier, "user:octocat"));
check("scope repo", () => assert.strictEqual(lib.scopeQualifier("repo", "octo/hello.world").qualifier, "repo:octo/hello.world"));
check("scope none", () => assert.deepStrictEqual(lib.scopeQualifier("none", ""), { ok: true, qualifier: "" }));
check("scope empty", () => assert.strictEqual(lib.scopeQualifier("org", "").ok, false));
check("scope injection", () => {
  ["acme OR org:other", "acme path:/x/", "a b", "-acme", "acme/evil"].forEach((v) => assert.strictEqual(lib.scopeQualifier("org", v).ok, false, v));
  ["octo", "octo/a/b", "octo/a b", "/x"].forEach((v) => assert.strictEqual(lib.scopeQualifier("repo", v).ok, false, v));
});
check("buildQuery", () => {
  assert.strictEqual(lib.buildQuery("org:acme", "/x/"), "org:acme /x/");
  assert.strictEqual(lib.buildQuery("", "/x/"), "/x/");
});
check("searchUrl", () => {
  const url = lib.searchUrl("org:acme /a\\.b[0-9]+/ path:*.md");
  assert.strictEqual(url, "https://github.com/search?type=code&q=org%3Aacme%20%2Fa%5C.b%5B0-9%5D%2B%2F%20path%3A*.md");
  const q = new URL(url).searchParams;
  assert.strictEqual(q.get("type"), "code");
  assert.strictEqual(q.get("q"), "org:acme /a\\.b[0-9]+/ path:*.md");
});

// ---- catalog structure ----
// Pull regex tokens (content and path:) out of a query. Slashes inside a regex are escaped.
function extract(query) {
  const out = [];
  let i = 0;
  while (i < query.length) {
    let kind = "content";
    if (query.startsWith("path:/", i)) { kind = "path"; i += 5; }
    else if (query.startsWith("NOT ", i)) { i += 4; continue; }
    if (query[i] === "/") {
      let j = i + 1;
      while (j < query.length && query[j] !== "/") j += query[j] === "\\" ? 2 : 1;
      assert.ok(j < query.length, "unterminated regex in: " + query);
      out.push({ kind, re: new RegExp(query.slice(i + 1, j)), src: query.slice(i + 1, j) });
      i = j + 1;
    } else {
      while (i < query.length && query[i] !== " ") i++;
    }
    while (query[i] === " ") i++;
  }
  return out;
}

function balanced(s) {
  let d = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\") { i++; continue; }
    if (s[i] === "(") d++;
    if (s[i] === ")") d--;
    if (d < 0) return false;
  }
  return d === 0;
}

const ids = new Set();
vulns.forEach((v) => {
  check(v.id + " unique", () => { assert.ok(!ids.has(v.id)); ids.add(v.id); });
  const cardIds = new Set();
  v.cards.forEach((c) => {
    const where = v.id + "/" + c.id;
    check(where + " shape", () => {
      assert.ok(!cardIds.has(c.id), "duplicate card id");
      cardIds.add(c.id);
      assert.ok(c.title && c.finds && c.query);
      assert.ok(balanced(c.query), "unbalanced parentheses");
      assert.ok(extract(c.query).length >= 1, "no regex found");
    });
  });
});

// No em dashes anywhere in shipped text.
check("no em dashes", () => {
  const fs = require("fs"), path = require("path");
  ["index.html", "app.js", "lib.js", "vulns.js", "style.css", "README.md"].forEach((f) => {
    const p = path.join(__dirname, "..", f);
    if (fs.existsSync(p)) assert.ok(!fs.readFileSync(p, "utf8").includes("\u2014"), f);
  });
});

// ---- regex sanity against sample lines ----
// Each entry is [lines that must match, lines that must not match], for content and path regexes.
const samples = {
  "java4shell/docker-images": {
    content: [["FROM eclipse-temurin:17-jre", "FROM amazoncorretto:21-al2023", "FROM openjdk:21-slim", "FROM mcr.microsoft.com/openjdk/jdk:25-ubuntu",
      "FROM azul/zulu-openjdk:17", "FROM gcr.io/distroless/java17-debian12", "FROM maven:3.9.6-eclipse-temurin-21", "FROM gradle:8.5-jdk21",
      "FROM ghcr.io/graalvm/jdk-community:27", "RUN apt-get install -y openjdk-17-jdk", "FROM sapmachine:21.0.5"],
    ["FROM eclipse-temurin:11-jre", "FROM openjdk:8-jdk", "FROM node:20-alpine", "FROM eclipse-temurin:11.0.17_8-jdk", "FROM python:3.12"]],
    path: [["Dockerfile", "svc/Dockerfile.prod", "build/app.Dockerfile", "a/Containerfile"], ["README.md", "src/Main.java"]]
  },
  "java4shell/yaml-images": {
    content: [["    image: eclipse-temurin:21-jdk", "image: \"amazoncorretto:17\"", "image: maven:3.9-eclipse-temurin-21"], ["image: nginx:1.25", "image: eclipse-temurin:11"]],
    path: [["docker-compose.yml", "k8s/deploy.yaml"], ["a.json"]]
  },
  "java4shell/pinned-17-0-6": {
    content: [["FROM eclipse-temurin:17.0.6_10-jre", "FROM amazoncorretto:17.0.9-al2023", "image: openjdk:17.0.21.1", "FROM eclipse-temurin:17.0.12"],
      ["FROM eclipse-temurin:17.0.5_8-jre", "FROM eclipse-temurin:17-jre", "FROM eclipse-temurin:17.0.0", "FROM openjdk:11.0.17"]]
  },
  "java4shell/devcontainer": {
    content: [["\"image\": \"mcr.microsoft.com/devcontainers/java:21\"", "\"image\": \"eclipse-temurin:17\""], ["\"image\": \"mcr.microsoft.com/devcontainers/java:11\""]],
    path: [[".devcontainer/devcontainer.json", "devcontainer.json"], ["devcontainer.json.bak"]]
  },
  "java4shell/setup-java": {
    content: [["          java-version: '21'", "java-version: 17", "        java: [ 11, 17, 21 ]", "java-version: 21.0.5", "jdk: ['17','21']", "java_version: 25"],
      ["java-version: '11'", "java-version: 1.8", "java: [8, 11]", "java-version: ${{ matrix.java }}"]],
    path: [[".github/workflows/ci.yml", ".github/workflows/build.yaml"], [".github/dependabot.yml", "docs/workflows/ci.yml"]]
  },
  "java4shell/version-files": {
    content: [["17.0.9", "21", "temurin-21.0.2", "openjdk64-17.0.2"], ["11.0.17", "1.8", "8"]],
    path: [[".java-version", "app/.java-version"], ["java-version"]]
  },
  "java4shell/tool-versions": {
    content: [["java=21.0.5-tem", "java temurin-21.0.2", "java = \"temurin-17\"", "java 17.0.9"], ["java=11.0.21-tem", "nodejs 21.0.0", "java 8"]],
    path: [[".sdkmanrc", ".tool-versions", "mise.toml", ".mise.toml"], ["tool-versions.md"]]
  },
  "java4shell/maven": {
    content: [["<java.version>17</java.version>", "<maven.compiler.release>21</maven.compiler.release>", "    <source>17</source>", "<maven.compiler.target>25</maven.compiler.target>"],
      ["<java.version>11</java.version>", "<java.version>1.8</java.version>", "<version>17.2.1</version>"]],
    path: [["pom.xml", "module/pom.xml"], ["pom.xml.bak", "mypom.xml"]]
  },
  "java4shell/gradle": {
    content: [["languageVersion = JavaLanguageVersion.of(21)", "sourceCompatibility = JavaVersion.VERSION_17", "jvmToolchain(21)", "jvmTarget = \"17\"", "kotlinOptions.jvmTarget = '21'"],
      ["languageVersion = JavaLanguageVersion.of(11)", "sourceCompatibility = '1.8'", "jvmToolchain(11)"]],
    path: [["build.gradle", "app/build.gradle.kts"], ["settings.gradle", "build.gradle.bak"]]
  },
  "java4shell/java-installs": {
    content: [["sudo apt-get install openjdk-17-jdk", "apk add openjdk21", "dnf install temurin-17-jdk", "java-21-openjdk"],
      ["apt-get install openjdk-11-jdk", "npm install java-8"]]
  },
  "java4shell/bundled-products": {
    content: [["image: quay.io/keycloak/keycloak:26.0", "FROM jenkins/jenkins:lts-jdk17", "image: atlassian/jira-software:9", "FROM --platform=linux/amd64 jfrog/artifactory-oss"],
      ["image: nginx", "# keycloak notes"]]
  },
  "java4shell/mitigation-flags": {
    content: [["JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", "-XX:UseAVX=2 -Xmx2g"], ["-XX:+UseG1GC", "-XX:UseAVX=3"]]
  },
  "php2shell/docker-apache": {
    content: [["FROM php:8.3-apache", "FROM php:apache", "FROM php:8.2.12-apache-bookworm", "image: webdevops/php-apache:8.2"], ["FROM php:8.3-fpm", "FROM php:8.3-cli-alpine", "FROM nginx:apache-like"]]
  },
  "php2shell/cms-images": {
    content: [["FROM wordpress:6.5-php8.2-apache", "image: drupal:10", "image: \"nextcloud:29\"", "FROM --platform=linux/amd64 wordpress", "image: bitnami/wordpress:6"],
      ["image: wordpress-cli-tools", "image: ghost:5", "FROM node:20"]]
  },
  "php2shell/docker-any": {
    content: [["FROM php:8.3-fpm", "FROM php:7.4-apache", "FROM php:8.5-cli", "RUN apt-get install php8.2-fpm", "FROM serversideup/php:8.4-fpm-nginx", "image: dunglas/frankenphp:1.2-php8.3"],
      ["FROM php:9.0-cli", "FROM node:8.3", "image: phpmyadmin:5.2"]]
  },
  "php2shell/pinned-below-fixed": {
    content: [["FROM php:8.3.10-apache", "FROM php:8.2.0-fpm", "FROM php:8.2.34-cli", "FROM php:8.3.35-fpm", "FROM php:8.4.26", "FROM php:8.5.11-apache", "FROM php:8.5.0", "FROM php:8.4.9-fpm"],
      ["FROM php:8.2.35-apache", "FROM php:8.3.36", "FROM php:8.4.27-fpm", "FROM php:8.5.12", "FROM php:8.5.13-cli", "FROM php:8.3-apache", "FROM php:8.2.100"]]
  },
  "php2shell/eol": {
    content: [["FROM php:7.4-apache", "FROM php:8.1-fpm", "FROM php:8.0.30-cli", "FROM php:5.6-apache", "RUN apt install php7.4-fpm"], ["FROM php:8.2-fpm", "FROM php:8.10", "FROM php:8.3-apache"]]
  },
  "php2shell/composer-php": {
    content: [["        \"php\": \"^8.1\",", "\"php\": \">=7.4\"", "\"php\": \"8.2.0\""], ["\"php-http/client\": \"^1.0\"", "\"ext-json\": \"*\""]],
    path: [["composer.json", "app/composer.json"], ["composer.lock", "mycomposer.json"]]
  },
  "php2shell/composer-apps": {
    content: [["\"laravel/framework\": \"^10.0\"", "\"drupal/core-recommended\": \"^10\"", "\"roots/wordpress\": \"6.5\"", "\"symfony/framework-bundle\": \"6.4.*\""], ["\"symfony/console\": \"6.4\"", "\"monolog/monolog\": \"3\""]]
  },
  "php2shell/setup-php": {
    content: [["          php-version: '8.3'", "php-version: 8.2", "        php: [ '8.1', '8.2' ]", "php-version: 7.4"], ["php-version: '9.0'", "php-version: ${{ matrix.php }}", "node-version: 8.3"]],
    path: [[".github/workflows/tests.yml"], ["workflows/tests.yml"]]
  },
  "php2shell/php-version-file": {
    content: [["8.3.1", "7.4", "8.2"], ["9.0", "18.4.0"]],
    path: [[".php-version", "x/.php-version"], ["php-version"]]
  },
  "php2shell/tool-versions": {
    content: [["php 8.3.1", "php = \"8.2\"", "php 7.4.33"], ["nodejs 8.3.1", "php 9.1"]]
  },
  "php2shell/mod-php": {
    content: [["RUN apt-get install -y libapache2-mod-php8.2", "LoadModule php_module modules/libphp.so", "LoadModule php8_module /usr/lib/libphp8.so"], ["LoadModule rewrite_module modules/mod_rewrite.so"]]
  },
  "php2shell/mitigation-config": {
    content: [["memory_limit = -1", "php_admin_value[memory_limit] = -1", "session.upload_progress.enabled = 0", "session.upload_progress.enabled=Off", "php_value session.upload_progress.enabled off"],
      ["memory_limit = 256M", "session.upload_progress.enabled = 1", "session.upload_progress.enabled=On"]]
  }
};

vulns.forEach((v) => v.cards.forEach((c) => {
  const key = v.id + "/" + c.id;
  const s = samples[key];
  check(key + " has samples", () => assert.ok(s, "missing sample lines"));
  if (!s) return;
  const toks = extract(c.query);
  ["content", "path"].forEach((kind) => {
    if (!s[kind]) return;
    const re = toks.filter((t) => t.kind === kind).map((t) => t.re);
    check(key + " " + kind + " regex present", () => assert.ok(re.length >= 1));
    if (!re.length) return;
    s[kind][0].forEach((line) => check(key + " " + kind + " should match: " + line, () => assert.ok(re.every((r) => r.test(line)))));
    s[kind][1].forEach((line) => check(key + " " + kind + " should not match: " + line, () => assert.ok(!re.every((r) => r.test(line)))));
  });
}));

if (failures) { console.error(failures + " failure(s)"); process.exit(1); }
console.log("all tests passed");
