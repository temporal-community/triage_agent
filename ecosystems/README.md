# Ecosystem Providers

**When do you need a new ecosystem?** When Dependabot or Renovate is opening PRs for a language or package manager that isn't in the coverage table below.

Each ecosystem provider translates a package registry's APIs into the seven checks that `PackageTriageWorkflow` uses to produce a triage verdict.

## Coverage

| Ecosystem | `ecosystem_name` | Language(s) | Registry | Build-origin verified? (attestation) | Implementation quirks |
|---|---|---|---|---|---|
| pip (PyPI) | `pip` | Python | [pypi.org](https://pypi.org) | Yes — via [Sigstore](https://www.sigstore.dev) | Registry can prove the package was built by a specific CI pipeline, not uploaded manually |
| npm | `npm` | JavaScript / TypeScript / Node.js | [npmjs.com](https://www.npmjs.com) | Yes — via [Sigstore](https://www.sigstore.dev) | Same build-origin verification as pip |
| Cargo | `cargo` | Rust | [crates.io](https://crates.io) | No | |
| RubyGems | `rubygems` | Ruby | [rubygems.org](https://rubygems.org) | No | Archive is nested `.gem` → `data.tar.gz` |
| Go modules | `go` | Go | [pkg.go.dev](https://pkg.go.dev) | No | GOPROXY URL encoding (`!` escaping for uppercase) |
| Maven | `maven` | Java / Kotlin / Scala / JVM | [search.maven.org](https://search.maven.org) | No | Coordinate format: `groupId:artifactId` |
| NuGet | `nuget` | C# / .NET / F# | [nuget.org](https://www.nuget.org) | No | Package IDs are case-insensitive — must be lowercased before API calls |
| Composer | `composer` | PHP | [packagist.org](https://packagist.org) | No | Packagist packages point to source repos (usually GitHub, sometimes self-hosted GitLab); archives are fetched from the source host's download CDN rather than Packagist itself |

All eight providers implement all seven signal methods. "No" in the attestation column means the registry simply doesn't support build-origin verification yet — it's not a red flag for packages on those registries.

## Required methods

Each provider must implement all seven of the following. Note that the workflow runs 11 checks total — the other four (OSV vulnerability lookup, Socket.dev score, deps.dev deprecation status, OpenSSF Scorecard) are ecosystem-agnostic and handled by shared activities that don't touch the provider.

`fetch_attestations` is required but can be a one-liner stub for registries that don't support build-origin verification yet — see the six "No" rows in the coverage table above.

| Method | What it returns | Primary data source |
|---|---|---|
| `fetch_metadata` | `MetadataChecks` — weekly downloads, major-bump flag, description | Registry API |
| `fetch_release_age` | `ReleaseAgeChecks` — hours since the version was published | Registry upload timestamp |
| `fetch_maintainer` | `MaintainerChecks` — whether a new maintainer was added for this version | Registry maintainer list |
| `get_archive_url` | `(url, filename, sha256)` or `None` | Registry file index |
| `extract_archive` | _(void)_ — extracts bytes to a dest dir | Archive bytes from `get_archive_url` |
| `fetch_attestations` | `AttestationChecks` — whether the registry can prove which CI pipeline built this version | Registry provenance endpoint |
| `fetch_release` | `ReleaseChecks` — GitHub release, tag signature, timing skew | GitHub/GitLab API |

---

To add a built-in ecosystem, see [docs/contributing.md](../docs/contributing.md). To add a plugin ecosystem (without modifying this repo), see [docs/extending.md](../docs/extending.md).
