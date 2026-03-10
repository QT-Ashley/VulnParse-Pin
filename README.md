## VulnParse-Pin

VulnParse-Pin is a vulnerability intelligence and triage engine that normalizes scanner output, enriches findings, applies configurable scoring, and prioritizes remediation.

### Current Scoring Profile (March 2026)

VulnParse-Pin now uses a **balanced, exploit-first** risk model (validated on 100k+ record samples):

- Strong prioritization of known-exploited vulnerabilities (CISA KEV, public exploits)
- Reduced over-classification in upper risk bands—focuses analyst effort on urgent, actionable items
- Preserves exploit-driven ordering for consistent triage workflow

See [Configs](docs/Configs.md) for current policy values and tuning guidance.

## Documentation

- [Docs Index](docs/README.md)
- [Overview](docs/Overview.md)
- [Getting Started In 5 Minutes](docs/Getting%20Started%20In%205%20Minutes.md)
- [Architecture](docs/Architecture.md)
- [Pipeline System](docs/Pipeline%20System.md)
- [Security](docs/Security.md)
- [Configs](docs/Configs.md)
- [Benchmarks](docs/Benchmarks.md)
- [Licensing](docs/Licensing.md)

## License

VulnParse-Pin is licensed under the **GNU Affero General Public License v3.0 or later (AGPLv3+)**.

This ensures that improvements to VulnParse-Pin — including those used in hosted or network-accessible services — remain open and benefit the community.

### What this means in practice
- ✅ Free to use, modify, and run internally
- ✅ Free for research, education, SOC pipelines, and consulting
- ✅ Free to sell services **using** VulnParse-Pin
- ⚠️ If you run a modified version as a hosted service, you must make the source available

Unmodified use does **not** require source disclosure.

### Commercial licensing
Commercial licensing or AGPL exceptions may be available for organizations that wish to embed VulnParse-Pin into proprietary products or managed services.
