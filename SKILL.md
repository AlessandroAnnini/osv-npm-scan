---
name: osv-npm-scan
description: >-
  Scans Node.js projects for known vulnerabilities by matching installed
  package-lock.json versions against the OSV.dev API. Use whenever the user
  asks about vulnerabilities, CVEs, security advisories, dependency risk, npm
  audit, or whether a Node, npm, or JavaScript project is affected, including
  when they mention osv.dev or a package-lock.json. Do not use this skill for
  C#, NuGet, Python, or PyPI projects.
license: MIT
compatibility: Requires Node.js 18 or newer and network access to https://api.osv.dev. Reads npm lockfileVersion 2 and 3 only.
metadata:
  author: Alessandro Filippo Annini
  version: "1.0.0"
  ecosystem: npm
---

# osv-npm-scan

Match every installed version in a project's `package-lock.json` files against [OSV.dev](https://osv.dev). Report the advisories the API returns. Do not reimplement the scan, and do not edit the script.

This skill is the npm member of a set. A later NuGet skill and a later PyPI skill should emit the same JSON shape, documented in [references/report-schema.md](references/report-schema.md).

## Run

From any working directory, run the script that sits next to this file. The argument is the project root:

```bash
node /absolute/path/to/osv-npm-scan/scripts/osv-scan.mjs /absolute/path/to/project
```

The script writes one JSON document to stdout and progress lines to stderr. It does not modify the project.

If stdout contains an `error` field, say what it says and stop. A missing lockfile is not a clean scan. If `warnings` is present, say each one. A warning is a lockfile or directory that could not be read, or an install that was not queried because it is not a registry tarball.

## What the script covers

- Every `package-lock.json` under the project root, except paths inside `node_modules` or `.git`, and except files reached only through a symlink
- npm `lockfileVersion` 2 and 3
- Production and development installs, direct dependencies and transitive ones
- Optional dependencies declared by a workspace or the root
- Peer dependency edges, so `introducedBy` names the requiring package

It does not query git, file, link, or other non-registry installs. It does not read `package.json` ranges, `yarn.lock`, `pnpm-lock.yaml`, or OS packages inside Docker images. Do not guess versions for those. Say they were not scanned.

## How to report

Read [references/report-schema.md](references/report-schema.md) before summarizing.

Lead with the answer: whether any locked version is in an OSV advisory, how many package versions were queried, and how many of those versions have at least one advisory.

Then a table of production findings at CRITICAL and HIGH, one row per package version:

- Package and locked version
- Lockfile, and whether it is a direct production dependency
- `introducedBy` when it is transitive
- Worst advisory id, a short summary, and `upgradeTo`

`severity` on a finding is already the worst advisory. `MEDIUM` means GitHub's MODERATE. Do not rescore advisories from the CVSS vector. `score` is informational.

When advisories on the same version disagree by major (one fixed in 4.x, another only in 5.x), name the advisory that forces `upgradeTo`. When `upgradeTo` is null, an advisory has no fixed version. Report the highest `fixed` among the advisories that have one, and name the advisory that has none.

Mention dev-only CRITICAL and HIGH findings in a short paragraph after the production table. Count the remaining MEDIUM and LOW production findings instead of listing every advisory. Call out a direct production dependency in that remainder when there is one.

This is a lockfile match against known advisories. It does not show whether the vulnerable code runs. Say that once.

Do not upgrade packages unless the user asks.
