from .nessus_parser import NessusParser
from .openvas_parser import OpenVASParser
from .openvasXML_parser import OpenVASXMLParser
from .nessusXML_parser import NessusXMLParser

parsers = [
    NessusParser,
    NessusXMLParser,
    OpenVASParser,
    OpenVASXMLParser, 
    #Rapid7Parser etc
]
