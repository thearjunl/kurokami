import html
import json
from datetime import datetime
from pathlib import Path

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def serialize_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def build_session_payload(session_record, targets, findings, reasoning, checkpoints=None, exploits=None):
    checkpoints = checkpoints or []
    exploits = exploits or []
    normalized_findings = [
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
    ]
    summary = _build_summary(session_record, targets, normalized_findings, reasoning, checkpoints, exploits)
    return {
        "summary": summary,
        "session": {
            "id": session_record.id,
            "target": session_record.target,
            "start_time": serialize_datetime(session_record.start_time),
            "end_time": serialize_datetime(session_record.end_time),
            "status": session_record.status,
            "risk_level": session_record.risk_level,
            "current_stage": getattr(session_record, "current_stage", None),
            "last_checkpoint": serialize_datetime(getattr(session_record, "last_checkpoint", None)),
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
        "findings": normalized_findings,
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
        "checkpoints": [
            {
                "id": checkpoint.id,
                "stage": checkpoint.stage,
                "module_name": checkpoint.module_name,
                "state": checkpoint.state,
                "payload": checkpoint.payload,
                "created_at": serialize_datetime(checkpoint.created_at),
            }
            for checkpoint in checkpoints
        ],
        "exploits": [
            {
                "id": exploit.id,
                "finding_id": exploit.finding_id,
                "payload": exploit.payload,
                "result": exploit.result,
                "attempted_at": serialize_datetime(exploit.attempted_at),
            }
            for exploit in exploits
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
    summary = payload["summary"]
    targets = payload["targets"]
    findings = payload["findings"]
    reasoning = payload["reasoning_chains"]
    checkpoints = payload.get("checkpoints", [])
    exploits = payload.get("exploits", [])
    exploit_attempt_count = summary.get("exploit_attempt_count", 0)
    checkpoint_count = summary.get("checkpoint_count", 0)

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
        (
            f"<article class='finding severity-{html.escape(str(finding['severity']).lower())}'>"
            f"<span class='severity-pill'>{html.escape(str(finding['severity']).upper())}</span>"
            f"<h3>{html.escape(finding['vuln_name'])}</h3>"
            f"<p><strong>Confidence:</strong> {html.escape(str(finding['confidence']))}</p>"
            f"<p><strong>CVE:</strong> {html.escape(str(finding['cve_id'] or 'N/A'))}</p>"
            f"<p>{html.escape(str(finding['description'] or ''))}</p>"
            "</article>"
        )
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
    checkpoint_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(checkpoint['created_at']))}</td>"
        f"<td>{html.escape(str(checkpoint['stage']))}</td>"
        f"<td>{html.escape(str(checkpoint['module_name'] or '-'))}</td>"
        f"<td>{html.escape(str(checkpoint['state']))}</td>"
        "</tr>"
        for checkpoint in checkpoints
    )
    exploit_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(exploit['finding_id']))}</td>"
        f"<td><pre>{html.escape(str(exploit['payload'] or ''))}</pre></td>"
        f"<td><pre>{html.escape(str(exploit['result'] or ''))}</pre></td>"
        f"<td>{html.escape(str(exploit['attempted_at']))}</td>"
        "</tr>"
        for exploit in exploits
    )
    top_findings = "".join(
        f"<li><strong>{html.escape(finding['severity'].upper())}</strong> - {html.escape(finding['vuln_name'])}</li>"
        for finding in findings[:5]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KUROKAMI Session {session['id']}</title>
  <style>
    :root {{
      --bg: #f4efe6; --panel: rgba(255,251,245,0.92); --ink: #201a15; --muted: #655b52; --line: #d5c4b5;
      --accent: #973d22; --accent-2: #264653; --high: #8f1d21; --medium: #b26a00; --low: #2f6f49; --info: #355c7d;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Segoe UI", Tahoma, sans-serif; background: radial-gradient(circle at top left, rgba(151,61,34,.15), transparent 35%), radial-gradient(circle at bottom right, rgba(38,70,83,.15), transparent 35%), linear-gradient(180deg, #fcf7f0 0%, var(--bg) 100%); color: var(--ink); }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 64px; }}
    header {{ background: linear-gradient(135deg, rgba(151,61,34,.95), rgba(38,70,83,.9)); color: #fff8f0; border-radius: 24px; padding: 28px; box-shadow: 0 18px 50px rgba(33,20,12,.18); }}
    h1, h2, h3 {{ margin-top: 0; }} section {{ margin-top: 24px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-top: 20px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 18px; box-shadow: 0 8px 28px rgba(44,30,20,.08); backdrop-filter: blur(8px); }}
    .findings-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    .finding {{ position: relative; overflow: hidden; min-height: 220px; background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 18px; }}
    .finding::before {{ content: ""; position: absolute; inset: 0 auto 0 0; width: 6px; background: var(--info); }}
    .finding.severity-critical::before, .finding.severity-high::before {{ background: var(--high); }}
    .finding.severity-medium::before {{ background: var(--medium); }}
    .finding.severity-low::before {{ background: var(--low); }}
    .severity-pill {{ display: inline-block; font-size: 12px; letter-spacing: 0.08em; margin-bottom: 10px; padding: 5px 9px; border-radius: 999px; background: rgba(32,26,21,.08); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 16px; overflow: hidden; }}
    th, td {{ border: 1px solid var(--line); padding: 12px; text-align: left; vertical-align: top; }}
    th {{ background: rgba(151,61,34,.08); }}
    pre {{ white-space: pre-wrap; margin: 0; color: var(--muted); font-family: Consolas, monospace; }}
    ul {{ margin: 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>KUROKAMI Session Report</h1>
      <p>Target: <strong>{html.escape(str(session['target']))}</strong></p>
      <p>Status: {html.escape(str(session['status']))} | Risk Level: {html.escape(str(session['risk_level'] or 'unknown'))} | Current Stage: {html.escape(str(session.get('current_stage') or 'completed'))}</p>
    </header>
    <section class="summary-grid">
      <div class="panel"><strong>Session ID</strong><br>{html.escape(str(session['id']))}</div>
      <div class="panel"><strong>Started</strong><br>{html.escape(str(session['start_time']))}</div>
      <div class="panel"><strong>Ended</strong><br>{html.escape(str(session['end_time'] or 'in progress'))}</div>
      <div class="panel"><strong>Findings</strong><br>{summary['finding_count']}</div>
      <div class="panel"><strong>Critical / High</strong><br>{summary['critical_count']} / {summary['high_count']}</div>
      <div class="panel"><strong>Exploit Attempts</strong><br>{exploit_attempt_count}</div>
      <div class="panel"><strong>Checkpoints</strong><br>{checkpoint_count}</div>
      <div class="panel"><strong>Targets</strong><br>{summary['target_count']}</div>
    </section>
    <section class="panel">
      <h2>Executive Summary</h2>
      <p>{html.escape(summary['executive_summary'])}</p>
      <h3>Top Findings</h3>
      <ul>{top_findings or '<li>No findings recorded.</li>'}</ul>
    </section>
    <section><h2>Targets</h2><table><thead><tr><th>ID</th><th>Host</th><th>IP</th><th>Open Ports</th><th>Tech Stack</th></tr></thead><tbody>{target_rows}</tbody></table></section>
    <section><h2>Findings</h2><div class="findings-grid">{finding_cards or '<p>No findings recorded.</p>'}</div></section>
    <section><h2>Exploit Attempts</h2><table><thead><tr><th>Finding ID</th><th>Payload</th><th>Result</th><th>Attempted At</th></tr></thead><tbody>{exploit_rows or '<tr><td colspan="4">No exploit attempts recorded.</td></tr>'}</tbody></table></section>
    <section><h2>Checkpoint History</h2><table><thead><tr><th>Time</th><th>Stage</th><th>Module</th><th>State</th></tr></thead><tbody>{checkpoint_rows or '<tr><td colspan="4">No checkpoints recorded.</td></tr>'}</tbody></table></section>
    <section><h2>Reasoning Chain</h2><table><thead><tr><th>Stage</th><th>Model</th><th>Timestamp</th><th>Output</th></tr></thead><tbody>{reasoning_rows}</tbody></table></section>
  </main>
</body>
</html>
"""


def render_pdf_report(payload):
    summary = payload["summary"]
    exploit_attempt_count = summary.get("exploit_attempt_count", 0)
    checkpoint_count = summary.get("checkpoint_count", 0)
    lines = [
        f"KUROKAMI Session Report #{payload['session']['id']}",
        f"Target: {payload['session']['target']}",
        f"Status: {payload['session']['status']}",
        f"Risk Level: {payload['session']['risk_level']}",
        f"Current Stage: {payload['session'].get('current_stage')}",
        f"Findings: {summary['finding_count']} | Critical: {summary['critical_count']} | High: {summary['high_count']}",
        f"Exploit Attempts: {exploit_attempt_count} | Checkpoints: {checkpoint_count}",
        "",
        "Executive Summary:",
        summary["executive_summary"],
        "",
        "Targets:",
    ]
    for target in payload["targets"]:
        lines.append(f"- {target['host']} ({target['ip'] or 'unknown'})")
        lines.append(f"  ports={json.dumps(target['open_ports'])}")
        lines.append(f"  tech_stack={json.dumps(target['tech_stack'])}")
    lines.append("")
    lines.append("Findings:")
    for finding in payload["findings"]:
        lines.append(f"- [{finding['severity'].upper()}] {finding['vuln_name']} | confidence={finding['confidence']} | cve={finding['cve_id'] or 'N/A'}")
        if finding["description"]:
            lines.append(f"  {finding['description']}")
    lines.append("")
    lines.append("Exploit Attempts:")
    for exploit in payload.get("exploits", []):
        lines.append(f"- finding={exploit['finding_id']} payload={exploit['payload']} result={exploit['result']}")
    lines.append("")
    lines.append("Checkpoints:")
    for checkpoint in payload.get("checkpoints", []):
        lines.append(f"- {checkpoint['created_at']} {checkpoint['stage']} {checkpoint['module_name']} {checkpoint['state']}")
    lines.append("")
    lines.append("Reasoning:")
    for chain in payload["reasoning_chains"]:
        lines.append(f"- {chain['stage']} ({chain['model_used']}): {chain['output']}")
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


def _build_summary(session_record, targets, findings, reasoning, checkpoints, exploits):
    severities = [(finding.get("severity") or "info").lower() for finding in findings]
    finding_count = len(findings)
    critical_count = sum(1 for severity in severities if severity == "critical")
    high_count = sum(1 for severity in severities if severity == "high")
    top_severity = max(severities or ["info"], key=lambda severity: SEVERITY_ORDER.get(severity, 0))
    planner_modes = [chain.model_used for chain in reasoning if chain.stage.value == "ATTACK_SURFACE" and chain.model_used]
    planner_used = planner_modes[0] if planner_modes else "unknown"
    return {
        "target_count": len(targets),
        "finding_count": finding_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "top_severity": top_severity,
        "planner_used": planner_used,
        "checkpoint_count": len(checkpoints),
        "exploit_attempt_count": len(exploits),
        "executive_summary": (
            f"Session {session_record.id} assessed {len(targets)} target(s), recorded {finding_count} finding(s), "
            f"and logged {len(exploits)} exploit attempt(s). The highest observed severity was {top_severity}. "
            f"Planner context was produced by {planner_used}."
        ),
    }


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
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >> endobj")
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
    exploit_attempt_count = summary.get("exploit_attempt_count", 0)
    checkpoint_count = summary.get("checkpoint_count", 0)
