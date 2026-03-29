from pathlib import Path

import pytest

from vulnparse_pin.core.schema_detector import DetectionEvidence, DetectionResult, ParserSpec, SchemaDetector
from vulnparse_pin.parsers.nessusXML_parser import NessusXMLParser
from vulnparse_pin.parsers.openvasXML_parser import OpenVASXMLParser


# ---------------------------------------------------------------------------
# Minimal XML fixtures
# ---------------------------------------------------------------------------

_NESSUS_FULL_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="TestScan">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
      </HostProperties>
      <ReportItem pluginID="12345" pluginName="Test" severity="2" port="443" protocol="tcp" svc_name="https">
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

_NESSUS_ROOT_ONLY_XML = b"<NessusClientData_v2></NessusClientData_v2>"

_OPENVAS_FULL_XML = b"""<?xml version="1.0"?>
<report>
  <creation_time>2026-03-01T00:00:00Z</creation_time>
  <results>
    <result>
      <host>10.0.0.1</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.100000">
        <name>Test NVT</name>
      </nvt>
    </result>
  </results>
</report>"""

_OPENVAS_NO_OID_XML = b"""<?xml version="1.0"?>
<report>
  <results>
    <result>
      <host>10.0.0.2</host>
      <nvt>
        <name>No OID NVT</name>
      </nvt>
    </result>
  </results>
</report>"""

_UNRELATED_XML = b"<html><body>Not a scanner report</body></html>"


# ---------------------------------------------------------------------------
# Dummy parsers for schema_detector unit tests
# ---------------------------------------------------------------------------

class _DummyParserA:
    pass


class _DummyParserB:
    pass


def _det(name: str, parser_cls, matched: bool, confidence: float, scanner: str = "unknown") -> DetectionResult:
    return DetectionResult(
        parser_name=name,
        parser_cls=parser_cls,
        matched=matched,
        confidence=confidence,
        format="json",
        scanner=scanner,
        evidence=(),
        error=None,
    )


def test_pick_winner_prefers_higher_confidence():
    detector = SchemaDetector(
        [
            ParserSpec(name="A", parser_cls=_DummyParserA, formats=("json",), scanner="unknown", priority=100),
            ParserSpec(name="B", parser_cls=_DummyParserB, formats=("json",), scanner="unknown", priority=1),
        ]
    )

    results = [
        _det("A", _DummyParserA, matched=True, confidence=0.80),
        _det("B", _DummyParserB, matched=True, confidence=0.95),
    ]

    winner = detector._pick_winner(results)
    assert winner.parser_name == "B"


def test_pick_winner_uses_priority_when_confidence_ties():
    detector = SchemaDetector(
        [
            ParserSpec(name="A", parser_cls=_DummyParserA, formats=("json",), scanner="unknown", priority=100),
            ParserSpec(name="B", parser_cls=_DummyParserB, formats=("json",), scanner="unknown", priority=10),
        ]
    )

    results = [
        _det("A", _DummyParserA, matched=True, confidence=0.90),
        _det("B", _DummyParserB, matched=True, confidence=0.90),
    ]

    winner = detector._pick_winner(results)
    assert winner.parser_name == "B"


def test_pick_winner_returns_unmatched_when_none_match():
    detector = SchemaDetector(
        [
            ParserSpec(name="A", parser_cls=_DummyParserA, formats=("json",), scanner="unknown", priority=100),
            ParserSpec(name="B", parser_cls=_DummyParserB, formats=("json",), scanner="unknown", priority=10),
        ]
    )

    results = [
        _det("A", _DummyParserA, matched=False, confidence=0.10),
        _det("B", _DummyParserB, matched=False, confidence=0.20),
    ]

    winner = detector._pick_winner(results)
    assert not winner.matched
    assert winner.parser_name == "B"


# ---------------------------------------------------------------------------
# Graduated detection: Nessus parser
# ---------------------------------------------------------------------------

def test_nessus_detect_returns_tuple(tmp_path):
    """detect_file should return (float, list) not a bool."""
    f = tmp_path / "scan.nessus"
    f.write_bytes(_NESSUS_FULL_XML)
    result = NessusXMLParser.detect_file(f)
    assert isinstance(result, tuple) and len(result) == 2
    confidence, evidence = result
    assert isinstance(confidence, float)
    assert isinstance(evidence, list)


def test_nessus_full_xml_high_confidence(tmp_path):
    """Full Nessus XML with .nessus extension should reach >= 0.90 confidence."""
    f = tmp_path / "scan.nessus"
    f.write_bytes(_NESSUS_FULL_XML)
    confidence, evidence = NessusXMLParser.detect_file(f)
    assert confidence >= 0.90
    assert any(k == "root_tag" for k, v in evidence)
    assert any(k == "extension" for k, v in evidence)


def test_nessus_extension_boosts_confidence(tmp_path):
    """.nessus extension adds +0.10 to the score; .xml does not receive the bonus.

    Use root-only content so the score does not cap at 1.0 for both files,
    making the confidence gap clearly observable.
    """
    # root-only: .xml → 0.50, .nessus → 0.60
    nessus_file = tmp_path / "scan.nessus"
    xml_file = tmp_path / "scan.xml"
    nessus_file.write_bytes(_NESSUS_ROOT_ONLY_XML)
    xml_file.write_bytes(_NESSUS_ROOT_ONLY_XML)
    conf_nessus, ev_nessus = NessusXMLParser.detect_file(nessus_file)
    conf_xml, ev_xml = NessusXMLParser.detect_file(xml_file)
    assert conf_nessus > conf_xml
    assert any(k == "extension" for k, v in ev_nessus)
    assert not any(k == "extension" for k, v in ev_xml)


def test_nessus_root_tag_only_partial_match(tmp_path):
    """Root tag only (no structure) returns confidence 0.50 — bare minimum match."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_NESSUS_ROOT_ONLY_XML)
    confidence, evidence = NessusXMLParser.detect_file(f)
    assert 0.45 <= confidence <= 0.60
    assert any(k == "root_tag" for k, v in evidence)


def test_nessus_absent_root_tag_returns_zero(tmp_path):
    """Non-Nessus XML hard-gates to 0.0 confidence."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_UNRELATED_XML)
    confidence, evidence = NessusXMLParser.detect_file(f)
    assert confidence == 0.0
    assert any(k == "root_tag" for k, v in evidence)


def test_nessus_wrong_extension_returns_zero(tmp_path):
    """Files with non-.nessus/.xml extension immediately return 0.0."""
    f = tmp_path / "scan.csv"
    f.write_bytes(_NESSUS_FULL_XML)
    confidence, _ = NessusXMLParser.detect_file(f)
    assert confidence == 0.0


# ---------------------------------------------------------------------------
# Graduated detection: OpenVAS parser
# ---------------------------------------------------------------------------

def test_openvas_detect_returns_tuple(tmp_path):
    """detect_file should return (float, list) not a bool."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_OPENVAS_FULL_XML)
    result = OpenVASXMLParser.detect_file(f)
    assert isinstance(result, tuple) and len(result) == 2
    confidence, evidence = result
    assert isinstance(confidence, float)
    assert isinstance(evidence, list)


def test_openvas_full_xml_high_confidence(tmp_path):
    """Full OpenVAS file with OID should score >= 0.80."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_OPENVAS_FULL_XML)
    confidence, evidence = OpenVASXMLParser.detect_file(f)
    assert confidence >= 0.80
    assert any(k == "nvt_oid" for k, v in evidence)


def test_openvas_no_oid_still_matches(tmp_path):
    """OpenVAS without OID still matches via result_node + nvt signals (>= 0.50)."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_OPENVAS_NO_OID_XML)
    confidence, evidence = OpenVASXMLParser.detect_file(f)
    assert confidence >= 0.50
    assert not any(k == "nvt_oid" for k, v in evidence)


def test_openvas_rejects_nessus_file(tmp_path):
    """OpenVAS hard-rejects files containing NessusClientData_v2."""
    f = tmp_path / "scan.xml"
    f.write_bytes(_NESSUS_FULL_XML)
    confidence, evidence = OpenVASXMLParser.detect_file(f)
    assert confidence == 0.0
    assert any(k == "rejected" for k, v in evidence)


def test_openvas_wrong_extension_returns_zero(tmp_path):
    """OpenVAS only accepts .xml extension."""
    f = tmp_path / "scan.nessus"
    f.write_bytes(_OPENVAS_FULL_XML)
    confidence, _ = OpenVASXMLParser.detect_file(f)
    assert confidence == 0.0


# ---------------------------------------------------------------------------
# SchemaDetector._call_parser_detect_file: tuple return handling
# ---------------------------------------------------------------------------

class _TupleDetectParser:
    @classmethod
    def detect_file(cls, filepath):
        return (0.75, [("signal_a", "passed"), ("signal_b", "value2")])


class _LowConfParser:
    @classmethod
    def detect_file(cls, filepath):
        return (0.30, [("signal_weak", "partial")])


class _LegacyBoolParser:
    @classmethod
    def detect_file(cls, filepath):
        return True


def test_call_parser_detect_file_handles_tuple_return(tmp_path):
    """SchemaDetector accepts (confidence, evidence) tuple from detect_file."""
    dummy_file = tmp_path / "test.xml"
    dummy_file.write_text("<root/>")
    spec = ParserSpec(name="test-xml", parser_cls=_TupleDetectParser, formats=("xml",), scanner="test")
    detector = SchemaDetector([spec])
    result = detector._call_parser_detect_file(None, spec, dummy_file, "xml")
    assert result.matched is True
    assert result.confidence == 0.75
    assert len(result.evidence) == 2
    assert result.evidence[0].key == "signal_a"
    assert result.evidence[0].value == "passed"


def test_call_parser_detect_file_low_confidence_not_matched(tmp_path):
    """Confidence < 0.50 from detect_file results in matched=False."""
    dummy_file = tmp_path / "test.xml"
    dummy_file.write_text("<root/>")
    spec = ParserSpec(name="test-xml", parser_cls=_LowConfParser, formats=("xml",), scanner="test")
    detector = SchemaDetector([spec])
    result = detector._call_parser_detect_file(None, spec, dummy_file, "xml")
    assert result.matched is False
    assert result.confidence == 0.30


def test_call_parser_detect_file_legacy_bool_still_works(tmp_path):
    """Legacy bool True return from detect_file is backward-compatible (confidence=0.9)."""
    dummy_file = tmp_path / "test.xml"
    dummy_file.write_text("<root/>")
    spec = ParserSpec(name="test-xml", parser_cls=_LegacyBoolParser, formats=("xml",), scanner="test")
    detector = SchemaDetector([spec])
    result = detector._call_parser_detect_file(None, spec, dummy_file, "xml")
    assert result.matched is True
    assert result.confidence == 0.9
