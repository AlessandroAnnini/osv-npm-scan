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
  "findings": [],
  "runtime": {}
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

## Runtime (npm only)

`runtime` is specific to this skill. The NuGet and PyPI skills do not emit it. It is one Node.js version matched against the [nodejs/security-wg core index](https://github.com/nodejs/security-wg/blob/main/vuln/core/index.json) the [nodejs/Release schedule](https://github.com/nodejs/Release/blob/main/schedule.json), and the [nodejs.org release list](https://nodejs.org/dist/index.json). It is separate from `findings` and does not change `vulnerablePackageVersions`.

| Field | Meaning |
| --- | --- |
| `name` | Always `node` |
| `version` | The version checked, without a leading `v` |
| `source` | `process` for the Node that ran the script, `flag` for `--node-version` |
| `platform` | `--node-platform`, or `process.platform` of the scan. Advisories are scoped to it |
| `releaseLine` | Major line, such as `v22` |
| `endOfLife` | True when the schedule's end date has passed. Null when the line is not in the schedule |
| `endOfLifeDate` | The schedule's end date, or null |
| `vulnerable` | True when at least one advisory applies to `platform`, or `missedSecurityReleases` is not empty |
| `severity` | Worst label among advisories that apply to `platform`, or null |
| `upgradeTo` | Highest per-advisory fix among those that apply, raised to the latest missed security release. Null when nothing applies, or when an advisory has no fix in this release line |
| `missedSecurityReleases` | Releases in the same major, newer than `version`, that nodejs.org marks `security`. Ascending. The advisory index can lag these, so they count even with no advisory |
| `advisories` | Every advisory whose `vulnerable` range matches and whose `patched` range does not. Ones that apply to `platform` sort first |
| `error` | Present instead of the result fields when the version is not exact or the sources could not be fetched. The package scan still completes |

Runtime advisory fields: `id` (first CVE, or `NODE-CORE-<index key>` when there is none), `aliases` (other CVEs), `summary`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`), `fixed` (the patched version on the installed major, or null), `environments` (`all`, or platforms such as `win32`), `appliesToPlatform`, and `url` (the Node.js security release post).

An index entry whose range cannot be parsed is named in `warnings`, not dropped silently.

## Error

Exit code 1. Stdout is still JSON:

```json
{
  "ecosystem": "npm",
  "error": "no package-lock.json found under /absolute/project"
}
```

The error document has no `runtime`. The runtime is checked only after the lockfiles are read.
