# VulnParse-Pin – Vulnerability Intelligence and Decision Support Engine
# Copyright (C) 2026 QTShade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.

import random
from vulnparse_pin import __version__


def print_banner():
    subtitles = [
        "Pinnacle of Operational Security",
        "Pinnacle of Cyber Defense Intelligence",
        "Pinnacle of Threat-Aware Triage",
        "Pinnacle of Real-World Risk Insight",
        "Pinnacle of Defensive Strategy",
        "Pinnacle of Tactical Risk Management",
        "Pinnacle of Security Analytics Wizardry",
    ]

    selected_subtitle = random.choice(subtitles)

    banner = f"""
    ██████╗ ██╗███╗   ██╗███╗   ██╗ █████╗  ██████╗██╗     ███████╗
    ██╔══██╗██║████╗  ██║████╗  ██║██╔══██╗██╔════╝██║     ██╔════╝
    ██████╔╝██║██╔██╗ ██║██╔██╗ ██║███████║██║     ██║     █████╗
    ██╔═══╝ ██║██║╚██╗██║██║╚██╗██║██╔══██║██║     ██║     ██╔══╝
    ██║     ██║██║ ╚████║██║ ╚████║██║  ██║╚██████╗███████╗███████╗
    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝

                VulnParse-Pinnacle {__version__}
                Enrich ✦ Prioritize ✦ Defend
              {selected_subtitle}
                    Developer: QTShade
                Copyright (C) 2026 QTShade
    """


    print(banner)
    print("=" * 75)


def print_section_header(title: str, width: int = 60):
    """Display a simple console header for a section.

    ``width`` defines the total character width of the line; the title will be
    centered within equals signs.  This replaces the repeated ad-hoc calls in
    :mod:`main`.

    Examples::

        >>> print_section_header("Exploit-DB")
        ============ Exploit-DB ============
    """
    if width < len(title) + 2:
        # too narrow, just print the title
        print(title)
        return
    rem = width - len(title) - 2
    half = rem // 2
    print("=" * half + f" {title} " + "=" * (rem - half))
