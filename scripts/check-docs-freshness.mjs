#!/usr/bin/env node
// Docs freshness check (BEDU-287). Extends the compatibility-contract
// pattern to the volatile values docs quote from source: relayer routes,
// package/registry IDs, public relayer URLs, SDK version references, and
// source-derived limits. Fails CI when docs drift from code.
//
// Scope: the whole docs tree. No check is pinned to a named page. The
// script derives canonical values from the workspace, then indexes every
// docs/**/*.md(x) page and validates whatever quotes those values,
// wherever it lives. Moving a section between pages does not break the
// check, and a value restated on a second page is checked there too, so
// the docs do not need a separate script per section.
//
// Truth sources:
//   routes        services/server/src/main.rs
//   versions      services/server/src/compatibility.rs, Cargo.toml
//   limits        services/server/src/types.rs, routes/admin.rs
//   testnet IDs   apps/app/.env.example (active testnet block)
//   mainnet IDs   apps/app/.env.example (mainnet block)
//   relayer URLs  packages/mcp/src/index.ts (env presets)

import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const failures = [];

function read(relPath) {
    return fs.readFileSync(path.join(root, relPath), "utf8");
}

function capture(label, text, regex) {
    const match = text.match(regex);
    if (!match) throw new Error(`Missing ${label}`);
    return match[1];
}

function fail(message) {
    failures.push(message);
}

function assertContains(where, text, expected, label) {
    if (!text.includes(expected)) {
        fail(`${where}: missing ${label} (${expected})`);
    }
}

// Slice a markdown section: from its heading to the next heading of the
// same or higher level.
function section(docText, heading) {
    const start = docText.indexOf(heading);
    if (start === -1) return null;
    const level = heading.match(/^#+/)[0].length;
    const rest = docText.slice(start + heading.length);
    const next = rest.search(new RegExp(`^#{1,${level}} `, "m"));
    return heading + (next === -1 ? rest : rest.slice(0, next));
}

// ── Sources ─────────────────────────────────────────────────────────
const mainRs = read("services/server/src/main.rs");
const typesRs = read("services/server/src/types.rs");
const adminRs = read("services/server/src/routes/admin.rs");
const compatibilityRs = read("services/server/src/compatibility.rs");
const serverCargo = read("services/server/Cargo.toml");
const appEnvExample = read("apps/app/.env.example");
const mcpIndex = read("packages/mcp/src/index.ts");

// ── The docs tree ───────────────────────────────────────────────────
function* docPaths(dir) {
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
        const rel = `${dir}/${entry.name}`;
        if (entry.isDirectory()) yield* docPaths(rel);
        else if (/\.mdx?$/.test(entry.name)) yield rel;
    }
}

const docs = [...docPaths("docs")].map((relPath) => ({ path: relPath, text: read(relPath) }));

// Every page that carries the given heading, so a value documented in
// more than one place is validated in each of them.
function sectionsEverywhere(heading) {
    const found = [];
    for (const doc of docs) {
        const body = section(doc.text, heading);
        if (body) found.push({ path: doc.path, body });
    }
    return found;
}

// ── 1. Route coverage: main.rs <-> the whole docs tree ──────────────
// Registered routes, `{param}` normalized to the docs' `:param` form.
const sourceRoutes = [...mainRs.matchAll(/\.route\(\s*"([^"]+)"/g)]
    .map((m) => m[1].replace(/\{([^}]+)\}/g, ":$1"));
const sourceRouteSet = new Set(sourceRoutes);

// Routes deliberately kept out of the public reference. Listing them
// here is the explicit decision: removing an entry makes the check
// demand documentation for it again.
const undocumentedByDesign = new Set([
    "/restricted",
    "/security-delete",
    "/api/security-delete-auth/request",
    "/api/security-delete-auth/verify",
    "/api/security-deletable-blobs",
    "/api/security-deletions",
    "/api/security-deletions/:batch_id",
    "/api/security-deletions/:batch_id/submit",
    // Admin surface, gated by ADMIN_API_KEY rather than the signed-header
    // auth the public reference describes. #525 scoped it out of that page.
    "/api/admin/wallets",
    "/api/admin/upload-errors",
    "/api/admin/config",
    "/api/admin/activity",
    // The OAuth consent flow the dashboard drives between /oauth/authorize
    // and the redirect back to the client. The browser calls these with an
    // opaque session id; no integrator writes against them, so the public
    // surface is the OAuth endpoints themselves, which are documented.
    "/api/oauth/session/:session_id",
    "/api/oauth/session/:session_id/account",
    "/api/oauth/session/:session_id/complete",
    "/api/oauth/session/:session_id/cancel",
]);

// RFC 9728 lets a resource publish its metadata at the bare well-known path
// or at that path with the resource's own path appended. Both registrations
// serve one documented resource, so documenting the bare form covers the
// suffixed one.
function wellKnownParent(route) {
    const match = route.match(/^(\/\.well-known\/[^/]+)\/.+$/);
    return match ? match[1] : null;
}

// A route counts as documented if any page mentions it in backticks.
for (const route of sourceRouteSet) {
    if (undocumentedByDesign.has(route)) continue;
    const parent = wellKnownParent(route);
    const forms = parent ? [route, parent] : [route];
    const documentedIn = docs.filter((doc) =>
        forms.some((form) => doc.text.includes(`\`${form}\``) || doc.text.includes(` ${form}\``)),
    );
    if (documentedIn.length === 0) {
        fail(`registered route ${route} is not documented on any docs page`);
    }
}

// Every documented endpoint heading, anywhere, must exist in main.rs.
for (const doc of docs) {
    const documentedRoutes = [...doc.text.matchAll(/^#{2,4} `(?:GET|POST|DELETE) ([^`]+)`/gm)]
        .map((m) => m[1]);
    for (const route of documentedRoutes) {
        if (!sourceRouteSet.has(route)) {
            fail(`${doc.path}: documents ${route}, which main.rs does not register`);
        }
    }
}

// ── 2. Version references, wherever the health example appears ──────
const cargoVersion = capture("server package version", serverCargo, /^version\s*=\s*"([^"]+)"/m);
const apiVersion = capture("RELAYER_API_VERSION", compatibilityRs, /RELAYER_API_VERSION:\s*&str\s*=\s*"([^"]+)"/);
const minTs = capture("MIN_TYPESCRIPT_SDK_VERSION", compatibilityRs, /MIN_TYPESCRIPT_SDK_VERSION:\s*&str\s*=\s*"([^"]+)"/);
const minPy = capture("MIN_PYTHON_SDK_VERSION", compatibilityRs, /MIN_PYTHON_SDK_VERSION:\s*&str\s*=\s*"([^"]+)"/);
const minMcp = capture("MIN_MCP_PACKAGE_VERSION", compatibilityRs, /MIN_MCP_PACKAGE_VERSION:\s*&str\s*=\s*"([^"]+)"/);

const healthSections = sectionsEverywhere("### `GET /health`");
if (healthSections.length === 0) {
    fail("no docs page documents `GET /health`");
}
for (const { path: where, body } of healthSections) {
    assertContains(`${where} health example`, body, `"version": "${cargoVersion}"`, "server version");
    assertContains(`${where} health example`, body, `"apiVersion": "${apiVersion}"`, "API version");
    assertContains(`${where} health example`, body, `"typescript": "${minTs}"`, "min TypeScript SDK");
    assertContains(`${where} health example`, body, `"python": "${minPy}"`, "min Python SDK");
    assertContains(`${where} health example`, body, `"mcp": "${minMcp}"`, "min MCP package");
}

// Any page that states a compatibility version must state the current one.
const versionClaims = [
    ["apiVersion", apiVersion],
    ["typescript", minTs],
    ["python", minPy],
    ["mcp", minMcp],
];
for (const doc of docs) {
    for (const [key, expected] of versionClaims) {
        for (const match of doc.text.matchAll(new RegExp(`"${key}":\\s*"([^"]+)"`, "g"))) {
            if (match[1] !== expected) {
                fail(`${doc.path}: "${key}" reads ${match[1]}, source says ${expected}`);
            }
        }
    }
}

// ── 3. Package and registry IDs, wherever docs assign them ──────────
const testnetPackageId = capture("testnet package ID", appEnvExample, /^VITE_MEMWAL_PACKAGE_ID=(0x[0-9a-f]{64})\s*$/m);
const testnetRegistryId = capture("testnet registry ID", appEnvExample, /^VITE_MEMWAL_REGISTRY_ID=(0x[0-9a-f]{64})\s*$/m);
const mainnetPackageId = capture("mainnet package ID", appEnvExample, /#\s*VITE_MEMWAL_PACKAGE_ID=(0x[0-9a-f]{64})/);
const mainnetRegistryId = capture("mainnet registry ID", appEnvExample, /#\s*VITE_MEMWAL_REGISTRY_ID=(0x[0-9a-f]{64})/);

const canonicalPackageIds = new Set([testnetPackageId, mainnetPackageId]);
const canonicalRegistryIds = new Set([testnetRegistryId, mainnetRegistryId]);

// Only IDs the docs assign to a known variable are checked, so example
// object IDs and blob IDs in prose are left alone.
const idAssignment = /(VITE_)?MEMWAL_(PACKAGE|REGISTRY)_ID\s*[=:]\s*["']?(0x[0-9a-f]{64})/g;
const seenIds = new Set();
for (const doc of docs) {
    for (const match of doc.text.matchAll(idAssignment)) {
        const kind = match[2];
        const value = match[3];
        seenIds.add(value);
        const allowed = kind === "PACKAGE" ? canonicalPackageIds : canonicalRegistryIds;
        if (!allowed.has(value)) {
            fail(`${doc.path}: MEMWAL_${kind}_ID ${value} is not a canonical ${kind.toLowerCase()} ID`);
        }
    }
}

// Both networks must still be documented somewhere.
for (const [label, value] of [
    ["testnet package ID", testnetPackageId],
    ["testnet registry ID", testnetRegistryId],
    ["mainnet package ID", mainnetPackageId],
    ["mainnet registry ID", mainnetRegistryId],
]) {
    if (!seenIds.has(value)) {
        fail(`no docs page documents the ${label} (${value})`);
    }
}

// ── 4. Public relayer URLs across all docs ──────────────────────────
// Any *.memory.walrus.xyz relayer hostname a doc mentions must be one of
// the presets the MCP package ships.
const allowedRelayerHosts = new Set(
    [...mcpIndex.matchAll(/relayer:\s*"https:\/\/([^"]+)"/g)].map((m) => m[1]),
);
if (allowedRelayerHosts.size === 0) {
    fail("packages/mcp/src/index.ts: no relayer presets found (truth source moved?)");
}

for (const doc of docs) {
    for (const match of doc.text.matchAll(/(relayer[a-z0-9-]*\.memory\.walrus\.xyz)/g)) {
        if (!allowedRelayerHosts.has(match[1])) {
            fail(`${doc.path}: unknown relayer host ${match[1]} (not an MCP package preset)`);
        }
    }
}

// ── 5. Source-derived limits, wherever the endpoint is documented ───
const maxBulk = capture("MAX_BULK_ITEMS", typesRs, /MAX_BULK_ITEMS:\s*usize\s*=\s*(\d+)/);
const defaultLimit = capture("default_limit", typesRs, /fn default_limit\(\)\s*->\s*usize\s*\{\s*(\d+)/);
const restoreDefault = capture("default_restore_limit", typesRs, /fn default_restore_limit\(\)\s*->\s*usize\s*\{\s*(\d+)/);
const askClamp = adminRs.match(/\.unwrap_or\((\d+)\)\.min\((\d+)\)/);

const limitChecks = [
    ["### `POST /api/remember/bulk`", `up to ${maxBulk} memories`, "MAX_BULK_ITEMS"],
    ["### `POST /api/recall`", `defaults to \`${defaultLimit}\``, "recall default limit"],
    ["### `POST /api/restore`", `defaults to \`${restoreDefault}\``, "restore default limit"],
];
if (askClamp) {
    limitChecks.push(["### `POST /api/ask`", `defaults to \`${askClamp[1]}\``, "ask default limit"]);
}

for (const [heading, expected, label] of limitChecks) {
    for (const { path: where, body } of sectionsEverywhere(heading)) {
        assertContains(where, body, expected, label);
    }
}

// ── Report ──────────────────────────────────────────────────────────
if (failures.length > 0) {
    console.error(`docs freshness check failed (${failures.length} finding${failures.length === 1 ? "" : "s"}):`);
    for (const message of failures) console.error(`  - ${message}`);
    process.exit(1);
}
console.log(
    `docs freshness OK (${docs.length} pages, ${sourceRouteSet.size} routes, IDs, URLs, versions, limits)`,
);
