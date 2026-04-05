from vulnparse_pin.core.schema_detector import ParserSpec
from .nessus_parser import NessusParser
from .openvas_parser import OpenVASParser
from .openvasXML_parser import OpenVASXMLParser
from .nessusXML_parser import NessusXMLParser

PARSER_SPECS = [
    ParserSpec(name="openvas-xml", parser_cls=OpenVASXMLParser,
               formats=("xml",), scanner="openvas", priority=10),

    ParserSpec(name="nessus-xml", parser_cls=NessusXMLParser,
               formats=("xml", "nessus"), scanner="nessus", priority=20),

    ParserSpec(name="openvas-json", parser_cls=OpenVASParser,
               formats=("json",), scanner="openvas", priority=10,
               stability="experimental", deprecated=True,
               deprecation_notice="JSON parser paths are experimental and may be removed in a future release."),

    ParserSpec(name="nessus-json", parser_cls=NessusParser,
               formats=("json", "nessus"), scanner="nessus", priority=20,
               stability="experimental", deprecated=True,
               deprecation_notice="JSON parser paths are experimental and may be removed in a future release."),
]
