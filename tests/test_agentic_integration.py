import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")

from core.agentic_loop import AgenticLoop


def test_agentic_loop_deduplicates_findings_without_db_roundtrip():
    loop = AgenticLoop(session_id=1, target="example.com")
    first = {"vuln_name": "Duplicate Finding", "severity": "high", "confidence": 0.9, "description": "same", "cve_id": None}
    second = {"vuln_name": "Duplicate Finding", "severity": "high", "confidence": 0.4, "description": "same", "cve_id": None}

    assert loop._finding_key(first) == loop._finding_key(second)
    normalized = loop._normalize_finding(second)
    assert normalized["severity"] == "high"
    assert 0.0 <= normalized["confidence"] <= 1.0
