# Report schema

`scripts/osv-scan.mjs` prints this document to stdout. Later NuGet and PyPI skills should use the same fields so a report can be read without knowing the ecosystem. Only `ecosystem` and the lockfile label change.

## Success

```json
{
  "ecosystem": "npm",
  "scannedAt": "2026-10-23T08:00:00.000Z",
  "root": "/absolute/project",
  "lockfiles": ["backend/package-lock.json"],
  "packageVersions": 1193,
  "vulnerablePackageVersions": 54,
  "findings": []
}
```

`packageVersions` is the number of distinct name@version pairs sent to OSV. `vulnerablePackageVersions` counts those that have at least one current advisory. Withdrawn advisories are omitted.

Findings are sorted with production installs first, then by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), then by name.

### Finding

| Field | Meaning |
| --- | --- |
| `name`, `version` | Installed package, as locked |
| `severity` | Worst advisory label on this version |
| `upgradeTo` | Highest per-advisory fix. Null when any advisory has no fixed version |
| `locations` | One entry per lockfile that installs this version |
| `advisories` | One entry per advisory, aliases already collapsed |

### Location

| Field | Meaning |
| --- | --- |
| `lockfile` | Path relative to `root` |
| `production` | True when at least one install of this version in that lockfile is not marked `dev` |
| `direct` | True when a workspace or the root declares this name in `dependencies`, `devDependencies`, or `optionalDependencies` |
| `directProduction` | True when a workspace or the root declares this name in `dependencies`, or in `optionalDependencies` without also listing it in `devDependencies` on that same package |
| `introducedBy` | Direct dependency names that pull this package in. Empty when `direct` is true |

Trust `production` for what `npm ci` installs at runtime. A name can be listed in `dependencies` while every install is still `dev`.

### Advisory

| Field | Meaning |
| --- | --- |
| `id` | Preferred id. A GHSA id when one exists, otherwise the first id |
| `aliases` | Other ids for the same advisory, including CVEs |
| `summary` | OSV summary |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`. `MEDIUM` is GitHub MODERATE. A publisher label wins over a score computed from an alias that has no label |
| `score` | Highest CVSS v3 base score on the merged advisory. Null when the advisory has no numeric score and no usable v3 base vector. Scope must be `U` or `C`. Does not change `severity` |
| `fixed` | Lowest fixed version above the installed version for this advisory. Null when OSV lists no fix |
| `url` | `https://osv.dev/vulnerability/<id>` |

`upgradeTo` is the highest `fixed` among advisories that have one, and only when every advisory has a fix. It assumes each advisory stays fixed after that version.

A skipped lockfile, an unreadable directory, or a non-registry install does not fail the scan. `warnings` is present only then. Each entry is the path and the reason. A git, file, link, or other non-registry install is named and was not queried. An `http` or `https` resolved URL is queried. A missing `resolved` URL is queried too.

## Error

Exit code 1. Stdout is still JSON:

```json
{
  "ecosystem": "npm",
  "error": "no package-lock.json found under /absolute/project"
}
```
