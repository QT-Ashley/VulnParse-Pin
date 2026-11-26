# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

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
                Developer: Quashawn Ashley
              Copyright (C) 2026 Quashawn Ashley
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
