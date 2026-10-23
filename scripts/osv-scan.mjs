#!/usr/bin/env node
// Match npm lockfileVersion 2 and 3 against https://api.osv.dev.
// Stdout is one JSON document. Progress goes to stderr. No dependencies.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ECOSYSTEM = "npm";
const API = "https://api.osv.dev/v1";
const BATCH = 800;
const PAGE_LIMIT = 20;
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

function fail(error) {
  process.stdout.write(JSON.stringify({ ecosystem: ECOSYSTEM, error }, null, 2) + "\n");
  process.exit(1);
}

export function walkLockfiles(dir, root, out, warnings) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    const message = `cannot read ${path.relative(root, dir) || dir}: ${err.message}`;
    if (dir === root) fail(message);
    warnings.push(message);
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkLockfiles(full, root, out, warnings);
    else if (entry.isFile() && entry.name === "package-lock.json") {
      out.push(path.relative(root, full) || "package-lock.json");
    }
  }
}

function packageNameFromPath(pkgPath) {
  const marker = "node_modules/";
  const idx = pkgPath.lastIndexOf(marker);
  if (idx === -1) return null;
  return pkgPath.slice(idx + marker.length);
}

function ownerName(pkgPath, meta) {
  if (!pkgPath) return meta.name || "(root)";
  if (!pkgPath.includes("node_modules/")) return meta.name || pkgPath;
  // Dependency keys use the install name. For an alias, meta.name is the target.
  return packageNameFromPath(pkgPath) || meta.name;
}

function nonRegistryReason(meta) {
  if (meta.link === true) return "link";
  if (typeof meta.resolved !== "string" || meta.resolved.length === 0) return null;
  const resolved = meta.resolved.toLowerCase();
  if (resolved.startsWith("https://") || resolved.startsWith("http://")) return null;
  if (resolved.startsWith("file:")) return "file";
  const gitPrefixes = ["git+", "git:", "github:", "gitlab:", "bitbucket:"];
  if (gitPrefixes.some((prefix) => resolved.startsWith(prefix))) return "git";
  return "non-registry";
}

export function introducedBy(name, parents, direct) {
  if (direct.has(name)) return [];
  const found = new Set();
  const seen = new Set([name]);
  const queue = [name];
  while (queue.length) {
    const current = queue.shift();
    for (const parent of parents.get(current) || []) {
      if (direct.has(parent)) {
        found.add(parent);
        continue;
      }
      if (!seen.has(parent)) {
        seen.add(parent);
        queue.push(parent);
      }
    }
  }
  return [...found].sort();
}

export function collectLockfileData(data, rel = "package-lock.json") {
  const version = Number(data.lockfileVersion);
  if (version !== 2 && version !== 3) {
    return {
      error: `${rel}: lockfileVersion ${data.lockfileVersion ?? "missing"} is not supported (need 2 or 3)`,
    };
  }
  const packages = data.packages ?? {};
  const directProd = new Set();
  const directDev = new Set();
  const parents = new Map();

  const addParent = (dep, parent) => {
    if (!parents.has(dep)) parents.set(dep, new Set());
    parents.get(dep).add(parent);
  };

  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (!meta || typeof meta !== "object") continue;
    const insideModules = pkgPath.includes("node_modules/");
    const owner = ownerName(pkgPath, meta);
    if (!insideModules) {
      const devHere = new Set(Object.keys(meta.devDependencies ?? {}));
      for (const name of Object.keys(meta.dependencies ?? {})) directProd.add(name);
      for (const name of devHere) directDev.add(name);
      for (const name of Object.keys(meta.optionalDependencies ?? {})) {
        if (!devHere.has(name)) directProd.add(name);
      }
    }
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      for (const name of Object.keys(meta[field] ?? {})) addParent(name, owner);
    }
  }

  const direct = new Set([...directProd, ...directDev]);
  const installs = new Map();
  const skippedBy = new Map();
  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (!pkgPath || typeof meta?.version !== "string") continue;
    const lockedName = packageNameFromPath(pkgPath);
    const name = meta.name || lockedName;
    if (!name || !lockedName) continue;
    const key = `${name}@${meta.version}`;
    const reason = nonRegistryReason(meta);
    if (reason) {
      if (!skippedBy.has(key)) skippedBy.set(key, reason);
      continue;
    }
    let row = installs.get(key);
    if (!row) {
      row = {
        name,
        lockedNames: new Set(),
        version: meta.version,
        production: false,
      };
      installs.set(key, row);
    }
    row.lockedNames.add(lockedName);
    if (!meta.dev) row.production = true;
  }

  const skipped = [...skippedBy.entries()]
    .filter(([key]) => !installs.has(key))
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, reason]) => `${key} is a ${reason} install and was not queried`);

  return { rel, installs, directProd, direct, parents, skipped };
}

export function locationFor(row, item) {
  const names = [...row.lockedNames, row.name];
  const direct = names.some((name) => item.direct.has(name));
  const introducers = new Set();
  if (!direct) {
    for (const name of row.lockedNames) {
      for (const parent of introducedBy(name, item.parents, item.direct)) introducers.add(parent);
    }
  }
  return {
    lockfile: item.rel,
    production: row.production,
    direct,
    directProduction: names.some((name) => item.directProd.has(name)),
    introducedBy: [...introducers].sort(),
  };
}

function parseSemver(value) {
  const match = String(value).match(
    /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/,
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    pre: match[4] ? match[4].split(".") : null,
  };
}

// Null when either side is not semver. Callers must not treat that as an order.
export function compareVersions(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  if (pa.patch !== pb.patch) return pa.patch - pb.patch;
  if (!pa.pre && !pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  const length = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < length; i += 1) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn && Number(x) !== Number(y)) return Number(x) - Number(y);
    if (xn !== yn) return xn ? -1 : 1;
    if (x !== y) return x.localeCompare(y);
  }
  return 0;
}

function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function cvssV3(vector) {
  if (!vector || !vector.startsWith("CVSS:3")) return null;
  const metrics = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((part) => part.split(":"))
      .filter((pair) => pair.length === 2 && pair[0] && pair[1]),
  );
  if (metrics.S !== "U" && metrics.S !== "C") return null;
  const changed = metrics.S === "C";
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.AV];
  const ac = { L: 0.77, H: 0.44 }[metrics.AC];
  const pr = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[metrics.PR];
  const ui = { N: 0.85, R: 0.62 }[metrics.UI];
  const c = { N: 0, L: 0.22, H: 0.56 }[metrics.C];
  const i = { N: 0, L: 0.22, H: 0.56 }[metrics.I];
  const a = { N: 0, L: 0.22, H: 0.56 }[metrics.A];
  if ([av, ac, pr, ui, c, i, a].some((n) => n === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const exploit = 8.22 * av * ac * pr * ui;
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
  return roundUp(raw);
}

function numericScore(rec) {
  const db = rec.database_specific ?? {};
  if (typeof db.cvss?.score === "number") return db.cvss.score;
  if (typeof db.cvss_score === "number") return db.cvss_score;
  const scores = (rec.severity ?? [])
    .map((item) => (typeof item.score === "string" ? cvssV3(item.score) : null))
    .filter((n) => n !== null);
  return scores.length ? Math.max(...scores) : null;
}

function publisherSeverity(rec) {
  const raw = rec.database_specific?.severity;
  if (typeof raw !== "string" || !raw.trim()) return null;
  const label = raw.trim().toUpperCase();
  if (label === "MODERATE") return "MEDIUM";
  if (label === "CRITICAL" || label === "HIGH" || label === "MEDIUM" || label === "LOW") {
    return label;
  }
  return null;
}

function labelFromScore(score) {
  if (score === null) return "UNKNOWN";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}

function fixedVersions(rec, name) {
  const fixed = new Set();
  for (const affected of rec.affected ?? []) {
    const pkg = affected.package;
    if (!pkg || pkg.ecosystem !== ECOSYSTEM || pkg.name !== name) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed];
}

export function lowestFix(versions, installed) {
  const later = versions.filter((version) => {
    const cmp = compareVersions(version, installed);
    return cmp !== null && cmp > 0;
  });
  later.sort((a, b) => compareVersions(a, b));
  return later[0] ?? null;
}

class UnionFind {
  constructor() {
    this.parent = new Map();
  }
  find(value) {
    if (!this.parent.has(value)) this.parent.set(value, value);
    const parent = this.parent.get(value);
    if (parent !== value) {
      const root = this.find(parent);
      this.parent.set(value, root);
      return root;
    }
    return value;
  }
  union(a, b) {
    const pa = this.find(a);
    const pb = this.find(b);
    if (pa !== pb) this.parent.set(pa, pb);
  }
}

export function groupRecords(records) {
  const groups = new UnionFind();
  for (const rec of records) {
    if (rec.withdrawn) continue;
    for (const alias of rec.aliases ?? []) groups.union(rec.id, alias);
  }
  const buckets = new Map();
  for (const rec of records) {
    if (rec.withdrawn) continue;
    const rootId = groups.find(rec.id);
    if (!buckets.has(rootId)) buckets.set(rootId, []);
    buckets.get(rootId).push(rec);
  }
  return [...buckets.values()];
}

export function summarizeGroup(group, packageName, installed) {
  const published = group
    .map((rec) => publisherSeverity(rec))
    .filter((label) => label);
  const pool = published.length
    ? published
    : group.map((rec) => labelFromScore(numericScore(rec)));
  pool.sort((a, b) => (RANK[b] ?? 0) - (RANK[a] ?? 0));
  const scores = group.map((rec) => numericScore(rec)).filter((score) => score !== null);
  const primary =
    group.find((rec) => rec.id.startsWith("GHSA-") && rec.summary) ??
    group.find((rec) => rec.id.startsWith("GHSA-")) ??
    group.find((rec) => rec.summary) ??
    group[0];
  const aliases = [
    ...new Set(group.flatMap((rec) => [rec.id, ...(rec.aliases ?? [])])),
  ]
    .filter((id) => id !== primary.id)
    .sort();
  const fixes = [...new Set(group.flatMap((rec) => fixedVersions(rec, packageName)))];
  return {
    id: primary.id,
    aliases,
    summary: primary.summary ?? "",
    severity: pool[0] ?? "UNKNOWN",
    score: scores.length ? Math.max(...scores) : null,
    fixed: lowestFix(fixes, installed),
    url: `https://osv.dev/vulnerability/${primary.id}`,
  };
}

function readLockfile(root, rel) {
  const full = path.join(root, rel);
  try {
    return collectLockfileData(JSON.parse(fs.readFileSync(full, "utf8")), rel);
  } catch (err) {
    return { error: `${rel}: ${err.message}` };
  }
}

async function requestJson(url, options) {
  let lastErr;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(30000),
      });
      if (response.status === 429 || response.status >= 500) {
        lastErr = new Error(`${response.status} ${url}`);
        await new Promise((resolve) => setTimeout(resolve, 400 * attempt));
        continue;
      }
      if (!response.ok) {
        const text = await response.text();
        const error = new Error(`${response.status} ${url}: ${text.slice(0, 300)}`);
        error.permanent = true;
        throw error;
      }
      return await response.json();
    } catch (err) {
      if (err.permanent) throw err;
      lastErr = err;
      if (attempt === 4) break;
      await new Promise((resolve) => setTimeout(resolve, 400 * attempt));
    }
  }
  throw lastErr;
}

function upgradeTo(advisories) {
  if (!advisories.every((item) => item.fixed)) return null;
  return advisories
    .map((item) => item.fixed)
    .sort((a, b) => compareVersions(a, b) ?? 0)
    .at(-1);
}

async function main() {
  const root = path.resolve(process.argv[2] || process.cwd());
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    fail(`not a directory: ${root}`);
  }

  const lockfiles = [];
  const warnings = [];
  walkLockfiles(root, root, lockfiles, warnings);
  lockfiles.sort();
  if (!lockfiles.length) fail(`no package-lock.json found under ${root}`);

  const parsed = lockfiles.map((rel) => readLockfile(root, rel));
  for (const item of parsed) {
    if (item.error) warnings.push(item.error);
    else for (const line of item.skipped) warnings.push(`${item.rel}: ${line}`);
  }
  if (parsed.every((item) => item.error)) fail(warnings.join("; "));

  const byKey = new Map();
  for (const item of parsed) {
    if (item.error) continue;
    for (const row of item.installs.values()) {
      const key = `${row.name}@${row.version}`;
      let entry = byKey.get(key);
      if (!entry) {
        entry = { name: row.name, version: row.version, locations: [] };
        byKey.set(key, entry);
      }
      entry.locations.push(locationFor(row, item));
    }
  }

  const packages = [...byKey.values()];
  console.error(`lockfiles: ${parsed.filter((item) => !item.error).length}`);
  console.error(`package versions: ${packages.length}`);

  const queries = packages.map((pkg) => ({
    version: pkg.version,
    package: { name: pkg.name, ecosystem: ECOSYSTEM },
  }));
  const results = [];
  for (let i = 0; i < queries.length; i += BATCH) {
    const chunk = queries.slice(i, i + BATCH);
    console.error(`querybatch ${i + 1}-${i + chunk.length} of ${queries.length}`);
    const data = await requestJson(`${API}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk }),
    });
    if (!Array.isArray(data.results) || data.results.length !== chunk.length) {
      fail(
        `OSV querybatch returned ${data.results?.length ?? 0} results for ${chunk.length} queries`,
      );
    }
    results.push(...data.results);
  }

  for (let i = 0; i < packages.length; i += 1) {
    let token = results[i]?.next_page_token;
    const vulns = [...(results[i]?.vulns ?? [])];
    let pages = 0;
    while (token) {
      pages += 1;
      if (pages > PAGE_LIMIT) fail(`OSV kept paging ${packages[i].name}@${packages[i].version}`);
      const page = await requestJson(`${API}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          version: packages[i].version,
          package: { name: packages[i].name, ecosystem: ECOSYSTEM },
          page_token: token,
        }),
      });
      vulns.push(...(page.vulns ?? []));
      token = page.next_page_token;
    }
    packages[i].vulnIds = [...new Set(vulns.map((vuln) => vuln.id))];
  }

  const hits = packages.filter((pkg) => pkg.vulnIds.length);
  const ids = [...new Set(hits.flatMap((pkg) => pkg.vulnIds))];
  console.error(`advisory ids: ${ids.length}`);

  const records = new Map();
  let cursor = 0;
  async function worker() {
    while (cursor < ids.length) {
      const id = ids[cursor];
      cursor += 1;
      records.set(id, await requestJson(`${API}/vulns/${encodeURIComponent(id)}`));
    }
  }
  await Promise.all(Array.from({ length: 12 }, () => worker()));

  const findings = [];
  for (const hit of hits) {
    const present = hit.vulnIds.map((id) => records.get(id)).filter(Boolean);
    const advisories = groupRecords(present)
      .map((group) => summarizeGroup(group, hit.name, hit.version))
      .sort((a, b) => {
        const bySeverity = (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0);
        if (bySeverity !== 0) return bySeverity;
        return (b.score ?? -1) - (a.score ?? -1) || a.id.localeCompare(b.id);
      });
    if (!advisories.length) continue;
    findings.push({
      name: hit.name,
      version: hit.version,
      severity: advisories[0].severity,
      upgradeTo: upgradeTo(advisories),
      locations: hit.locations.sort((a, b) => a.lockfile.localeCompare(b.lockfile)),
      advisories,
    });
  }

  findings.sort((a, b) => {
    const aProd = a.locations.some((loc) => loc.production) ? 0 : 1;
    const bProd = b.locations.some((loc) => loc.production) ? 0 : 1;
    if (aProd !== bProd) return aProd - bProd;
    const bySev = (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0);
    if (bySev !== 0) return bySev;
    return (
      a.name.localeCompare(b.name) ||
      (compareVersions(a.version, b.version) ?? a.version.localeCompare(b.version))
    );
  });

  console.error(`vulnerable versions: ${findings.length}`);
  const report = {
    ecosystem: ECOSYSTEM,
    scannedAt: new Date().toISOString(),
    root,
    lockfiles: parsed.filter((item) => !item.error).map((item) => item.rel),
    packageVersions: packages.length,
    vulnerablePackageVersions: findings.length,
    findings,
  };
  if (warnings.length) report.warnings = warnings;
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedDirectly) {
  main().catch((err) => fail(err.message || String(err)));
}
