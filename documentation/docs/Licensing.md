# Licensing

This document summarizes the licensing terms and license transition history for VulnParse-Pin (`vpp`).

## Current License (v2.0.0+: Apache License 2.0)

Starting with **v2.0.0**, VulnParse-Pin is licensed under the **Apache License, Version 2.0** (`Apache-2.0`).

Practical implications:

- Free to use, modify, and distribute in both open-source and proprietary environments
- Free for internal security operations, MSSP/consulting workflows, CI/CD pipelines, and hosted services without network source-disclosure obligations
- Includes an explicit patent license grant from contributors (Section 3)
- When redistributing or creating derivative works, you must retain copyright, patent, trademark, and attribution notices, include a copy of `LICENSE`, and preserve the attributions in `NOTICE` (Section 4)
- See the repository [`LICENSE`](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/LICENSE) and [`NOTICE`](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/NOTICE) files for authoritative terms

## Version License Cut (Historical Releases)

VulnParse-Pin underwent a clean forward relicense at **v2.0.0**:

| Release Range | License | Notes |
| --- | --- | --- |
| `v2.0.0` and later | **Apache-2.0** | Current active release line; zero copyleft runtime dependencies |
| `v1.0.0 – v1.2.2` | **AGPL-3.0-or-later** | Legacy releases; historical tags and artifacts remain under AGPLv3+ |

Users requiring permissive Apache-2.0 licensing must use **v2.0.0 or later**.

## Support and Contact Information

For general questions, support, or collaboration:

- **Issues & Community**: [GitHub Issues](https://github.com/QT-Ashley/VulnParse-Pin/issues)
- **General inquiries**: [info@vulnparse-pin.com](mailto:info@vulnparse-pin.com)
- **Support requests**: [support@vulnparse-pin.com](mailto:support@vulnparse-pin.com)
- **Security reports**: See [SECURITY.md](https://github.com/QT-Ashley/VulnParse-Pin/blob/main/SECURITY.md)

## Disclaimers

> 1. **VulnParse-Pin** is provided ***"as is"*** without any warranties or guarantees, as stated in Sections 7 and 8 of the Apache License, Version 2.0. The developers and contributors are ***not*** liable for any damages or losses resulting from the use of **VulnParse-Pin**. Users are responsible for ensuring that their use complies with all applicable laws and regulations.
>
> 2. **VulnParse-Pin** is a tool designed to assist in vulnerability management and prioritization. Always validate and verify findings through additional analysis and testing before taking remediation actions.
>
> 3. **VulnParse-Pin** does ***not*** guarantee the accuracy or completeness of external scanner reports or threat-intelligence feeds it processes.
>
> 4. **VulnParse-Pin** is intended for authorized, ethical security operations. Users must ensure they have proper authorization to scan and process assets in their environment.
>
> 5. **VulnParse-Pin** is ***not*** affiliated with any specific vulnerability scanner or feed provider. Users are responsible for complying with the terms of external data feeds they configure.
