import html
import json
from datetime import datetime
from pathlib import Path


def serialize_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def build_session_payload(session_record, targets, findings, reasoning):
    return {
        "session": {
            "id": session_record.id,
            "target": session_record.target,
            "start_time": serialize_datetime(session_record.start_time),
            "end_time": serialize_datetime(session_record.end_time),
            "status": session_record.status,
            "risk_level": session_record.risk_level,
        },
        "targets": [
            {
                "id": target.id,
                "host": target.host,
                "ip": target.ip,
                "open_ports": target.open_ports,
                "tech_stack": target.tech_stack,
            }
            for target in targets
        ],
        "findings": [
            {
                "id": finding.id,
                "target_id": finding.target_id,
                "vuln_name": finding.vuln_name,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "cve_id": finding.cve_id,
            }
            for finding in findings
        ],
        "reasoning_chains": [
            {
                "id": chain.id,
                "stage": chain.stage.value,
                "input_context": chain.input_context,
                "output": chain.output,
                "model_used": chain.model_used,
                "timestamp": serialize_datetime(chain.timestamp),
            }
            for chain in reasoning
        ],
    }


def diff_findings(findings_left, findings_right):
    left_map = {_finding_key(finding): finding for finding in findings_left}
    right_map = {_finding_key(finding): finding for finding in findings_right}

    added_keys = sorted(set(right_map) - set(left_map))
    removed_keys = sorted(set(left_map) - set(right_map))
    common_keys = sorted(set(left_map) & set(right_map))

    severity_changed = []
    confidence_changed = []
    for key in common_keys:
        left = left_map[key]
        right = right_map[key]
        if (left.severity or "").lower() != (right.severity or "").lower():
            severity_changed.append({"from": left, "to": right})
        elif (left.confidence or 0.0) != (right.confidence or 0.0):
            confidence_changed.append({"from": left, "to": right})

    return {
        "added": [right_map[key] for key in added_keys],
        "removed": [left_map[key] for key in removed_keys],
        "severity_changed": severity_changed,
        "confidence_changed": confidence_changed,
    }


def render_html_report(payload):
    session = payload["session"]
    targets = payload["targets"]
    findings = payload["findings"]
    reasoning = payload["reasoning_chains"]

    target_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(target['id']))}</td>"
        f"<td>{html.escape(target['host'] or '')}</td>"
        f"<td>{html.escape(target['ip'] or '')}</td>"
        f"<td><pre>{html.escape(json.dumps(target['open_ports'], indent=2))}</pre></td>"
        f"<td><pre>{html.escape(json.dumps(target['tech_stack'], indent=2))}</pre></td>"
        "</tr>"
        for target in targets
    )
    finding_cards = "".join(
        "<article class='finding'>"
        f"<h3>{html.escape(finding['vuln_name'])}</h3>"
        f"<p><strong>Severity:</strong> {html.escape(str(finding['severity']))}</p>"
        f"<p><strong>Confidence:</strong> {html.escape(str(finding['confidence']))}</p>"
        f"<p><strong>CVE:</strong> {html.escape(str(finding['cve_id'] or 'N/A'))}</p>"
        f"<p>{html.escape(str(finding['description'] or ''))}</p>"
        "</article>"
        for finding in findings
    )
    reasoning_rows = "".join(
        "<tr>"
        f"<td>{html.escape(chain['stage'])}</td>"
        f"<td>{html.escape(str(chain['model_used'] or ''))}</td>"
        f"<td>{html.escape(str(chain['timestamp'] or ''))}</td>"
        f"<td><pre>{html.escape(str(chain['output'] or ''))}</pre></td>"
        "</tr>"
        for chain in reasoning
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>KUROKAMI Session {session['id']}</title>
  <style>
    :root {{
      --bg: #f5f0e8;
      --paper: #fffdf8;
      --ink: #1f1c18;
      --accent: #8d3b2f;
      --muted: #6b6259;
      --line: #d8c9b8;
    }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: radial-gradient(circle at top, #fffaf1, var(--bg)); color: var(--ink); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px 80px; }}
    header {{ border-bottom: 2px solid var(--accent); padding-bottom: 18px; margin-bottom: 28px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 18px 0 28px; }}
    .panel, .finding {{ background: var(--paper); border: 1px solid var(--line); border-radius: 14px; padding: 16px; box-shadow: 0 8px 30px rgba(64, 33, 16, 0.06); }}
    .finding-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: var(--paper); }}
    th, td {{ border: 1px solid var(--line); padding: 10px; vertical-align: top; text-align: left; }}
    pre {{ white-space: pre-wrap; margin: 0; color: var(--muted); }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>KUROKAMI Session Report</h1>
      <p>Target: <strong>{html.escape(str(session['target']))}</strong></p>
    </header>
    <section class="meta">
      <div class="panel"><strong>Session ID</strong><br>{html.escape(str(session['id']))}</div>
      <div class="panel"><strong>Status</strong><br>{html.escape(str(session['status']))}</div>
      <div class="panel"><strong>Risk Level</strong><br>{html.escape(str(session['risk_level'] or 'unknown'))}</div>
      <div class="panel"><strong>Started</strong><br>{html.escape(str(session['start_time']))}</div>
    </section>
    <section>
      <h2>Targets</h2>
      <table>
        <thead><tr><th>ID</th><th>Host</th><th>IP</th><th>Open Ports</th><th>Tech Stack</th></tr></thead>
        <tbody>{target_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Findings</h2>
      <div class="finding-grid">{finding_cards or '<p>No findings recorded.</p>'}</div>
    </section>
    <section>
      <h2>Reasoning Chain</h2>
      <table>
        <thead><tr><th>Stage</th><th>Model</th><th>Timestamp</th><th>Output</th></tr></thead>
        <tbody>{reasoning_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


def render_pdf_report(payload):
    lines = [
        f"KUROKAMI Session Report #{payload['session']['id']}",
        f"Target: {payload['session']['target']}",
        f"Status: {payload['session']['status']}",
        f"Risk Level: {payload['session']['risk_level']}",
        "",
        "Targets:",
    ]
    for target in payload["targets"]:
        lines.append(f"- {target['host']} ({target['ip'] or 'unknown'}) ports={json.dumps(target['open_ports'])}")
    lines.append("")
    lines.append("Findings:")
    for finding in payload["findings"]:
        lines.append(f"- [{finding['severity']}] {finding['vuln_name']} | confidence={finding['confidence']} | cve={finding['cve_id'] or 'N/A'}")
        if finding["description"]:
            lines.append(f"  {finding['description']}")
    lines.append("")
    lines.append("Reasoning:")
    for chain in payload["reasoning_chains"]:
        lines.append(f"- {chain['stage']}: {chain['output']}")
    return _minimal_pdf("\n".join(lines))


def write_export(format_name, payload, export_path: Path):
    format_name = format_name.lower()
    if format_name == "json":
        export_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif format_name == "html":
        export_path.write_text(render_html_report(payload), encoding="utf-8")
    elif format_name == "pdf":
        export_path.write_bytes(render_pdf_report(payload))
    else:
        raise ValueError(f"Unsupported export format: {format_name}")


def _finding_key(finding):
    return (
        (finding.vuln_name or "").strip().lower(),
        (finding.cve_id or "").strip().upper(),
        (finding.description or "").strip().lower(),
    )


def _minimal_pdf(text):
    safe_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\r", "")
    lines = safe_text.split("\n")
    content_lines = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
    for index, line in enumerate(lines):
        if index > 0:
            content_lines.append("T*")
        content_lines.append(f"({line[:110]}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj")
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj")
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj")
    objects.append(b"5 0 obj << /Length " + str(len(stream)).encode("ascii") + b" >> stream\n" + stream + b"\nendstream endobj")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
        pdf.extend(b"\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend((f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF").encode("ascii"))
    return bytes(pdf)
