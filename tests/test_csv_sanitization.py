
from utils.csv_exporter import (_sanitize_csv_cell, _sanitize_csv_row)

def test_sanitize_csv_cell_dangerous_prefix():
    """
    Cells starting with =, +, -, @ MUST be prefixed with a single quote.
    """
    cases = {
        "=SUM(1,2)": "'=SUM(1,2)",
        "+1+2": "'+1+2",
        "-IMPERSONATION": "'-IMPERSONATION",
        r"@HYPERLINK(\"http://evil\")": r"'@HYPERLINK(\"http://evil\")",
    }
    
    for value, expected in cases.items():
        assert _sanitize_csv_cell(value) == expected

def test_sanitize_csv_cell_safe_values_unchanged():
    """
    Normal values, empty strings, and None should pass through unchanged.
    """
    assert _sanitize_csv_cell("normal text") == "normal text"
    assert _sanitize_csv_cell("12345") == "12345"
    assert _sanitize_csv_cell("") == ""
    assert _sanitize_csv_cell(None) is None

    # Non-strings should be returned as-is
    assert _sanitize_csv_cell(42) == 42
    assert _sanitize_csv_cell(3.14) == 3.14
    assert _sanitize_csv_cell(True) is True


def test_sanitize_csv_row_mixed_types():
    """
    Only string values in the row should be sanitized. Other types stay intact.
    """
    row = {
        "dangerous_eq": "=SUM(1,2)",
        "dangerous_plus": "+1+2",
        "safe_text": "hello",
        "int_value": 10,
        "float_value": 9.8,
        "none_value": None,
    }

    safe = _sanitize_csv_row(row)

    assert safe["dangerous_eq"] == "'=SUM(1,2)"
    assert safe["dangerous_plus"] == "'+1+2"
    assert safe["safe_text"] == "hello"
    assert safe["int_value"] == 10
    assert safe["float_value"] == 9.8
    assert safe["none_value"] is None