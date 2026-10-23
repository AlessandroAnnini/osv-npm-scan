# osv-npm-scan

Author: Alessandro Filippo Annini

[![skills.sh](https://skills.sh/b/AlessandroAnnini/osv-npm-scan)](https://skills.sh/AlessandroAnnini/osv-npm-scan)

Agent skill that matches registry versions in `package-lock.json` against the [OSV.dev](https://osv.dev) API. Git, file, link, and other non-registry installs are left out of the query and named in `warnings`. The format follows the [Agent Skills specification](https://agentskills.io/specification), which is what [skills.sh](https://skills.sh) publishes.

```
osv-npm-scan/
├── SKILL.md
├── LICENSE
├── scripts/osv-scan.mjs
├── scripts/osv-scan.test.mjs
└── references/report-schema.md
```

Requires Node.js 18 or newer and network access to `https://api.osv.dev`. No packages to install.

```bash
node scripts/osv-scan.mjs /path/to/project
```

Stdout is one JSON document. The fields are described in `references/report-schema.md`.

```bash
node --test scripts/osv-scan.test.mjs
```

Install:

```bash
npx skills add AlessandroAnnini/osv-npm-scan
```

## Other ecosystems

This skill only reads npm lockfiles. Companion skills use the same report shape:

| Skill | Ecosystem | Manifest |
| --- | --- | --- |
| `osv-nuget-scan` | NuGet | C# lockfiles |
| `osv-uv-scan` | PyPI | `uv.lock` |

`ecosystem` in the JSON is `npm` here. The finding, location, and advisory fields stay the same so a report from any of the three can be read the same way.
