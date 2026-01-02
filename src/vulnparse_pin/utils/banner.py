# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
#  any later version.
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
                    Developer: Shade216
                Copyright (C) 2025 Shade216
    """
    
    
    print(banner)
    print("=" * 75)
