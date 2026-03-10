from pathlib import Path

from vulnparse_pin.core.schema_detector import DetectionResult, ParserSpec, SchemaDetector


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
