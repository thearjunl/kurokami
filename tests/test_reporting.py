from types import SimpleNamespace

from core.reporting import diff_findings, render_html_report, render_pdf_report


def test_diff_findings_detects_added_removed_and_severity_changes():
    left = [
        SimpleNamespace(vuln_name="Open port 80/tcp", cve_id=None, description="HTTP", severity="info", confidence=0.9),
        SimpleNamespace(vuln_name="Old TLS", cve_id="CVE-2020-0001", description="Weak TLS", severity="medium", confidence=0.8),
    ]
    right = [
        SimpleNamespace(vuln_name="Old TLS", cve_id="CVE-2020-0001", description="Weak TLS", severity="high", confidence=0.8),
        SimpleNamespace(vuln_name="Directory listing", cve_id=None, description="Enabled", severity="medium", confidence=0.7),
    ]

    result = diff_findings(left, right)

    assert len(result["added"]) == 1
    assert len(result["removed"]) == 1
    assert len(result["severity_changed"]) == 1


def test_render_html_report_contains_target_and_finding_content():
    payload = {
        "session": {"id": 1, "target": "example.com", "status": "completed", "risk_level": "medium", "start_time": "now"},
        "targets": [{"id": 1, "host": "example.com", "ip": "1.2.3.4", "open_ports": [80], "tech_stack": ["nginx"]}],
        "findings": [{"vuln_name": "Open port 80/tcp", "severity": "info", "confidence": 0.9, "cve_id": None, "description": "HTTP exposed"}],
        "reasoning_chains": [{"stage": "RECON", "model_used": "test", "timestamp": "now", "output": "Scanned target"}],
    }

    html = render_html_report(payload)

    assert "example.com" in html
    assert "Open port 80/tcp" in html


def test_render_pdf_report_returns_pdf_bytes():
    payload = {
        "session": {"id": 1, "target": "example.com", "status": "completed", "risk_level": "medium"},
        "targets": [],
        "findings": [],
        "reasoning_chains": [],
    }

    pdf_bytes = render_pdf_report(payload)

    assert pdf_bytes.startswith(b"%PDF-1.4")
