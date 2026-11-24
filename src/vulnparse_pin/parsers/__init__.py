# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Quashawn Ashley

from vulnparse_pin.core.schema_detector import ParserSpec
from .nessus_parser import NessusParser
from .openvas_parser import OpenVASParser
from .openvasXML_parser import OpenVASXMLParser
from .nessusXML_parser import NessusXMLParser
from .qualys_parser import QualysXMLParser
from .nmap_parser import NmapXMLParser
from .nessus_csv_parser import NessusCSVParser
from .qualys_csv_parser import QualysCSVParser
from .sarif_parser import SarifParser
from .nuclei_jsonl_parser import NucleiJSONLParser

PARSER_SPECS = [
    ParserSpec(name="openvas-xml", parser_cls=OpenVASXMLParser,
               formats=("xml",), scanner="openvas", priority=10),

    ParserSpec(name="nessus-xml", parser_cls=NessusXMLParser,
               formats=("xml", "nessus"), scanner="nessus", priority=20),

    ParserSpec(name="qualys-xml", parser_cls=QualysXMLParser,
               formats=("xml",), scanner="qualys", priority=15,
               stability="stable"),

    ParserSpec(name="nmap-xml", parser_cls=NmapXMLParser,
               formats=("xml",), scanner="nmap", priority=25,
               stability="stable"),

    ParserSpec(name="sarif-2.1.0", parser_cls=SarifParser,
               formats=("sarif", "json"), scanner="sarif", priority=12,
               stability="stable"),

    ParserSpec(name="nuclei-jsonl", parser_cls=NucleiJSONLParser,
               formats=("jsonl", "json"), scanner="nuclei", priority=14,
               stability="stable"),

    ParserSpec(name="openvas-json", parser_cls=OpenVASParser,
               formats=("json",), scanner="openvas", priority=10,
               stability="experimental", deprecated=True,
               deprecation_notice="JSON parser paths are experimental and may be removed in a future release."),

    ParserSpec(name="nessus-json", parser_cls=NessusParser,
               formats=("json", "nessus"), scanner="nessus", priority=20,
               stability="experimental", deprecated=True,
               deprecation_notice="JSON parser paths are experimental and may be removed in a future release."),

    ParserSpec(name="nessus-csv", parser_cls=NessusCSVParser,
               formats=("csv",), scanner="nessus", priority=18,
               stability="stable"),

    ParserSpec(name="qualys-csv", parser_cls=QualysCSVParser,
               formats=("csv",), scanner="qualys", priority=16,
               stability="stable"),
]
