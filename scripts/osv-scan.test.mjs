import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  collectLockfileData,
  compareVersions,
  cvssV3,
  groupRecords,
  introducedBy,
  locationFor,
  lowestFix,
  summarizeGroup,
  walkLockfiles,
} from "./osv-scan.mjs";

const HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N";

test("semver order treats a pre-release as older than the release", () => {
  assert.equal(compareVersions("1.2.3", "1.2.4") < 0, true);
  assert.equal(compareVersions("1.0.0-alpha", "1.0.0") < 0, true);
  assert.equal(compareVersions("1.2.3", "1.2.3"), 0);
  assert.equal(compareVersions("1.2.3", "not-a-version"), null);
});

test("the lowest fix is the next semver above the install", () => {
  assert.equal(lowestFix(["1.0.0", "1.2.4", "2.0.0"], "1.2.3"), "1.2.4");
  assert.equal(lowestFix(["not-a-version", "1.2.3"], "1.2.3"), null);
});

test("a known CVSS v3 critical vector scores 9.8", () => {
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvssV3(HIGH_VECTOR), 7.5);
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), 8.8);
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2);
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"), null);
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"), null);
});

test("GitHub MODERATE is kept when an alias only has a high CVSS vector", () => {
  const advisory = summarizeGroup(
    [
      {
        id: "GHSA-aaaa-bbbb-cccc",
        summary: "example",
        aliases: ["CVE-2026-1"],
        database_specific: { severity: "MODERATE" },
      },
      {
        id: "CVE-2026-1",
        aliases: ["GHSA-aaaa-bbbb-cccc"],
        severity: [{ type: "CVSS_V3", score: HIGH_VECTOR }],
      },
    ],
    "uuid",
    "9.0.1",
  );
  assert.equal(advisory.severity, "MEDIUM");
  assert.equal(advisory.score, 7.5);
  assert.equal(advisory.id, "GHSA-aaaa-bbbb-cccc");
  assert.deepEqual(advisory.aliases, ["CVE-2026-1"]);
});

test("a withdrawn record does not merge two live advisories", () => {
  const groups = groupRecords([
    { id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2026-1"] },
    { id: "GHSA-dddd-eeee-ffff", aliases: ["CVE-2026-2"] },
    { id: "OSV-dead", aliases: ["CVE-2026-1", "CVE-2026-2"], withdrawn: true },
  ]);
  assert.deepEqual(
    groups.map((group) => group[0].id).sort(),
    ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"],
  );
});

test("records that share an alias id collapse even when that id was not fetched", () => {
  const groups = groupRecords([
    { id: "GHSA-1111-2222-3333", aliases: ["CVE-2026-9"] },
    { id: "OSV-2026-1", aliases: ["CVE-2026-9"] },
    { id: "GHSA-9999-8888-7777", aliases: ["CVE-2020-1"], withdrawn: true },
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(
    groups[0].map((rec) => rec.id).sort(),
    ["GHSA-1111-2222-3333", "OSV-2026-1"],
  );
});

test("an optional dependency stays direct production when another workspace lists it as dev", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": {},
      "packages/b": { name: "b", devDependencies: { foo: "^1.0.0" } },
      "packages/a": { name: "a", optionalDependencies: { foo: "^1.0.0" } },
      "node_modules/foo": { version: "1.0.0" },
    },
  });
  const foo = collected.installs.get("foo@1.0.0");
  assert.equal(collected.directProd.has("foo"), true);
  assert.equal(foo.production, true);
});

test("lockfileVersion 1 is rejected", () => {
  const collected = collectLockfileData({ lockfileVersion: 1 });
  assert.match(collected.error, /lockfileVersion 1/);
});

test("registry tarballs are queried and git, file, and link installs are not", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": {},
      "node_modules/real": {
        version: "2.0.0",
        resolved: "https://registry.npmjs.org/real/-/real-2.0.0.tgz",
      },
      "node_modules/pkg/node_modules/real": { version: "2.0.0", link: true },
      "node_modules/left-pad": {
        version: "1.0.0",
        resolved: "git+https://github.com/example/left-pad.git#abc",
      },
      "node_modules/local": { version: "1.0.0", resolved: "file:../local" },
      "node_modules/app": { version: "1.0.0", link: true, resolved: "packages/app" },
      "node_modules/bundled": { version: "3.0.0", inBundle: true },
    },
  });
  assert.deepEqual([...collected.installs.keys()].sort(), ["bundled@3.0.0", "real@2.0.0"]);
  assert.deepEqual(collected.skipped, [
    "app@1.0.0 is a link install and was not queried",
    "left-pad@1.0.0 is a git install and was not queried",
    "local@1.0.0 is a file install and was not queried",
  ]);
});

test("an npm alias is direct when the alias name is declared", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { alias: "npm:real@1.2.3" } },
      "node_modules/alias": { name: "real", version: "1.2.3" },
    },
  });
  const row = collected.installs.get("real@1.2.3");
  const location = locationFor(row, collected);
  assert.equal(location.directProduction, true);
  assert.equal(location.direct, true);
  assert.deepEqual(location.introducedBy, []);
});

test("a dependency of an npm alias is introduced by the alias", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { alias: "npm:real@1.2.3" } },
      "node_modules/alias": {
        name: "real",
        version: "1.2.3",
        dependencies: { transitive: "^1.0.0" },
      },
      "node_modules/transitive": { version: "1.0.0" },
    },
  });
  assert.deepEqual(introducedBy("transitive", collected.parents, collected.direct), ["alias"]);
});

test("introducedBy follows a peer dependency to the direct package", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { "some-lib": "^1.0.0" } },
      "node_modules/some-lib": {
        version: "1.0.0",
        peerDependencies: { react: "^18.0.0" },
      },
      "node_modules/react": { version: "18.2.0" },
    },
  });
  assert.equal(collected.direct.has("react"), false);
  assert.deepEqual(introducedBy("react", collected.parents, collected.direct), ["some-lib"]);
});

test("introducedBy names the direct dependency, not the root", () => {
  const collected = collectLockfileData({
    lockfileVersion: 3,
    packages: {
      "": {
        name: "app",
        dependencies: { express: "^4.0.0" },
        devDependencies: { vitest: "^1.0.0" },
      },
      "node_modules/express": { version: "4.18.2", dependencies: { qs: "^6.0.0" } },
      "node_modules/qs": { version: "6.11.0" },
      "node_modules/vitest": { version: "1.0.0", dev: true },
    },
  });
  assert.equal(collected.direct.has("express"), true);
  assert.equal(collected.direct.has("vitest"), true);
  assert.equal(collected.directProd.has("vitest"), false);
  assert.deepEqual(introducedBy("qs", collected.parents, collected.direct), ["express"]);
  assert.deepEqual(introducedBy("express", collected.parents, collected.direct), []);
});

test("walk finds a lockfile under dist and skips node_modules and symlinks", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "osv-npm-scan-"));
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.mkdirSync(path.join(root, "node_modules", "pkg"), { recursive: true });
    fs.writeFileSync(path.join(root, "dist", "package-lock.json"), "{}");
    fs.writeFileSync(path.join(root, "node_modules", "pkg", "package-lock.json"), "{}");
    fs.symlinkSync(path.join(root, "dist"), path.join(root, "linked"));
    const found = [];
    const warnings = [];
    walkLockfiles(root, root, found, warnings);
    assert.deepEqual(found, ["dist/package-lock.json"]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
