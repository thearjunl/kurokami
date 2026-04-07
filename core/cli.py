import asyncio
import configparser
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import click
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.style import Style
from rich.table import Table
from rich.text import Text

# The CLI core setup
console = Console()

PRIMARY_STYLE = "bold bright_red"
ACCENT_STYLE = "dark_orange3"
DIM_STYLE = "dim red"
SEVERITY_STYLES = {
    "critical": "bold bright_red",
    "high": "yellow",
    "medium": "cyan",
    "low": "green",
    "info": "dim",
    "informational": "dim",
}


def load_config():
    """
    Lookup order:
    1. ./kurokami.conf
    2. ~/.config/kurokami/kurokami.conf
    3. /etc/kurokami/kurokami.conf
    """
    config = configparser.ConfigParser()

    paths_to_check = [
        os.path.join(os.getcwd(), "kurokami.conf"),
        os.path.expanduser("~/.config/kurokami/kurokami.conf"),
        "/etc/kurokami/kurokami.conf",
    ]

    for path in paths_to_check:
        if os.path.exists(path):
            config.read(path)
            return config, path

    return None, None


def bootstrap_database():
    """Initialize the database layer and return the active DB path."""
    try:
        from .database import init_db, resolve_db_path
    except ModuleNotFoundError as exc:
        missing_module = exc.name or "database dependency"
        console.print(
            f"[bold red]Database initialization failed:[/] Missing Python package [cyan]{missing_module}[/cyan]."
        )
        console.print("Install the project dependencies, then retry the scan command.")
        sys.exit(1)

    db_path = resolve_db_path()
    init_db()
    return db_path


def create_scan_session(target: str):
    """Create a persisted scan session before the agentic loop begins."""
    from .database import get_session
    from .db import Session

    with get_session() as db:
        scan_session = Session(
            target=target,
            status="initialized",
            risk_level="unknown",
        )
        db.add(scan_session)
        db.flush()
        return scan_session


def _require_database_models():
    try:
        from .database import get_session, resolve_config_path
        from .db import AIReasoningChain, Checkpoint, Exploit, Export, Finding, Session, Target
    except ModuleNotFoundError as exc:
        missing_module = exc.name or "database dependency"
        console.print(
            f"[bold red]Database access failed:[/] Missing Python package [cyan]{missing_module}[/cyan]."
        )
        console.print("Install the project dependencies, then retry this command.")
        sys.exit(1)

    return get_session, resolve_config_path, AIReasoningChain, Checkpoint, Exploit, Export, Finding, Session, Target


def run_scan_pipeline(scan_session_id: int, scan_target: str, scope_path: str | None = None):
    """Execute the initial agentic loop for a persisted session."""
    from .agentic_loop import run_agentic_loop

    return asyncio.run(
        run_agentic_loop(
            session_id=scan_session_id,
            target=scan_target,
            scope_path=scope_path,
        )
    )


def run_resume_pipeline(scan_session_id: int, scan_target: str):
    from .agentic_loop import run_agentic_loop

    return asyncio.run(
        run_agentic_loop(
            session_id=scan_session_id,
            target=scan_target,
            resume_mode=True,
        )
    )


def _load_session_bundle(db, session_model, target_model, finding_model, reasoning_model, checkpoint_model, exploit_model, session_id: int):
    session_record = db.get(session_model, int(session_id))
    if not session_record:
        return None

    targets = db.query(target_model).filter(target_model.session_id == session_record.id).order_by(target_model.id.asc()).all()
    findings = db.query(finding_model).filter(finding_model.session_id == session_record.id).order_by(finding_model.id.asc()).all()
    reasoning = (
        db.query(reasoning_model)
        .filter(reasoning_model.session_id == session_record.id)
        .order_by(reasoning_model.id.asc())
        .all()
    )
    checkpoints = (
        db.query(checkpoint_model)
        .filter(checkpoint_model.session_id == session_record.id)
        .order_by(checkpoint_model.id.asc())
        .all()
    )
    finding_ids = [finding.id for finding in findings]
    exploits = []
    if finding_ids:
        exploits = db.query(exploit_model).filter(exploit_model.finding_id.in_(finding_ids)).order_by(exploit_model.id.asc()).all()
    return session_record, targets, findings, reasoning, checkpoints, exploits


def _load_session_findings(session_id: int):
    bootstrap_database()
    get_session, _, _, _, _, _, Finding, Session, _ = _require_database_models()
    with get_session() as db:
        session_record = db.get(Session, int(session_id))
        if not session_record:
            return []
        return db.query(Finding).filter(Finding.session_id == session_record.id).order_by(Finding.id.asc()).all()


def _load_sessions():
    bootstrap_database()
    get_session, _, _, _, _, _, _, Session, _ = _require_database_models()
    with get_session() as db:
        return db.query(Session).order_by(Session.start_time.desc()).all()


def _get_model_name() -> str:
    cfg, _ = load_config()
    if not cfg:
        return "unknown"
    return cfg.get("ai", "default_model", fallback="unknown")


def _render_banner():
    banner_text = _build_ascii_banner()
    subtitle = Text.assemble(
        ("AI Penetration Testing Framework", Style(color="bright_red", bold=True)),
        ("  |  ", Style(color="red", dim=True)),
        ("Model: ", Style(color="dark_orange3")),
        (_get_model_name(), Style(color="bright_red", bold=True)),
        ("  |  ", Style(color="red", dim=True)),
        ("Parrot OS", Style(color="dark_orange3", bold=True)),
    )
    console.print(Text(banner_text, style=PRIMARY_STYLE))
    console.print(subtitle)
    console.print(Rule(style=DIM_STYLE))


def _build_ascii_banner() -> str:
    try:
        import pyfiglet

        for font_name in ("doom", "banner3"):
            try:
                return pyfiglet.figlet_format("KUROKAMI", font=font_name)
            except Exception:
                continue
    except ModuleNotFoundError:
        pass
    return "KUROKAMI"


def _render_main_menu():
    menu = Table.grid(padding=(0, 1))
    menu.add_row(Text("[1]", style=PRIMARY_STYLE), Text("New Scan", style="bold"))
    menu.add_row(Text("[2]", style=PRIMARY_STYLE), Text("View History", style="bold"))
    menu.add_row(Text("[3]", style=PRIMARY_STYLE), Text("Export Report", style="bold"))
    menu.add_row(Text("[4]", style=PRIMARY_STYLE), Text("Exit", style="bold"))
    console.print(menu)


def _render_history_table(sessions):
    table = Table(title="KUROKAMI History", header_style=PRIMARY_STYLE)
    table.add_column("Session ID", style="bright_red")
    table.add_column("Target", style="bold")
    table.add_column("Date", style="dim")
    table.add_column("Risk Level", style=ACCENT_STYLE)
    table.add_column("Status", style="dim")

    for session in sessions:
        risk_style = SEVERITY_STYLES.get((session.risk_level or "informational").lower(), "dim")
        table.add_row(
            str(session.id),
            session.target,
            str(session.start_time),
            Text(session.risk_level or "unknown", style=risk_style),
            session.status,
        )
    return table


def _render_findings_table(findings):
    table = Table(title="Findings", header_style=PRIMARY_STYLE)
    table.add_column("Vulnerability", style="bold")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("CVE ID")

    for finding in findings:
        severity = (finding.severity or "info").lower()
        row_style = SEVERITY_STYLES.get(severity, "dim")
        table.add_row(
            finding.vuln_name,
            Text(finding.severity or "info", style=row_style),
            str(finding.confidence),
            finding.cve_id or "-",
            style=row_style,
        )
    return table


def _status_symbol(status: str) -> str:
    status = (status or "").lower()
    if status == "completed":
        return "[bold green][ ✓ ][/]"
    if status == "skipped":
        return "[dim][ - ][/]"
    if status == "error":
        return "[bold red][ ! ][/]"
    return "[bright_red][ > ][/]"


def _render_progress_panel(tool_labels, statuses):
    rows = []
    for tool in tool_labels:
        state = statuses.get(tool, {"status": "pending", "message": f"Waiting to run {tool}..."})
        symbol = _status_symbol(state["status"])
        message = state.get("message", "")
        rows.append(Text.from_markup(f"{symbol} {message}"))
    return Panel(Group(*rows), title="SCAN INITIATED", border_style="bright_red")


def _interactive_scan_flow():
    target_input = Prompt.ask("Enter target IP, domain, or scope file path", console=console)
    is_scope = os.path.exists(target_input)
    scope_path = target_input if is_scope else None
    scan_target = target_input if not is_scope else f"scope:{target_input}"
    db_path = bootstrap_database()
    scan_session = create_scan_session(scan_target)

    panel_body = Text()
    panel_body.append("Target: ", style="dim")
    panel_body.append(target_input, style="bold bright_red")
    panel_body.append("\nSession ID: ", style="dim")
    panel_body.append(str(scan_session.id), style="bold")
    panel_body.append("\nDatabase: ", style="dim")
    panel_body.append(str(db_path), style="dark_orange3")
    console.print(Panel(panel_body, title="SCAN INITIATED", border_style="bright_red"))

    tool_labels = ["nmap", "nikto", "whatweb", "whois", "dnsenum", "gobuster", "curl", "smbclient", "sslscan"]
    statuses = {tool: {"status": "pending", "message": f"{tool} queued"} for tool in tool_labels}
    result_holder = {}

    def _worker():
        result_holder["result"] = run_scan_pipeline(
            scan_session_id=scan_session.id,
            scan_target=scan_target,
            scope_path=scope_path,
        )

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    spinner_map = {tool: Spinner("dots", text=f"Running {tool}...", style="bright_red") for tool in tool_labels}
    with Live(_render_progress_panel(tool_labels, statuses), console=console, refresh_per_second=8) as live:
        current_index = 0
        while thread.is_alive():
            active_tool = tool_labels[current_index % len(tool_labels)]
            for tool in tool_labels:
                if statuses[tool]["status"] == "pending":
                    statuses[tool] = {"status": "pending", "message": f"{tool} queued"}
            statuses[active_tool] = {"status": "running", "message": f"Running {active_tool}..."}
            live.update(_render_progress_panel(tool_labels, statuses))
            time.sleep(0.25)
            current_index += 1

        thread.join()
        result = result_holder.get("result", {})
        module_results = result.get("module_results", [])
        module_lookup = {
            "k_nmap": "nmap",
            "k_nikto": "nikto",
            "k_whatweb": "whatweb",
            "k_whois": "whois",
            "k_dnsenum": "dnsenum",
            "k_gobuster": "gobuster",
            "k_curl": "curl",
            "k_smbclient": "smbclient",
            "k_sslscan": "sslscan",
        }
        for module_result in module_results:
            tool = module_lookup.get(module_result.get("module"))
            if not tool:
                continue
            status = module_result.get("status", "unknown")
            statuses[tool] = {"status": status, "message": f"{tool} {status}"}
        live.update(_render_progress_panel(tool_labels, statuses))

    findings = _load_session_findings(scan_session.id)
    console.print(
        Text.from_markup(
            f"[bold bright_red]Pipeline complete[/]  |  Risk: [bold]{result.get('risk_level', 'unknown')}[/]  |  "
            f"Planner: [bold]{result.get('planner_mode', 'unknown')}[/]"
        )
    )
    if findings:
        console.print(_render_findings_table(findings))
    else:
        console.print(Panel(Text("No findings recorded for this session.", style="dim"), border_style="dim red"))


def _interactive_history_flow():
    sessions = _load_sessions()
    if not sessions:
        console.print(Panel(Text("No sessions found.", style="dim"), border_style="dim red"))
        return
    console.print(_render_history_table(sessions))


def _interactive_export_flow():
    session_id = Prompt.ask("Enter session ID to export", console=console)
    format_name = Prompt.ask("Enter export format", choices=["json", "html", "pdf"], default="json", console=console)
    ctx = click.Context(export)
    export.callback(session=session_id, format=format_name)


def _interactive_shell():
    _render_banner()
    while True:
        _render_main_menu()
        choice = console.input("[bold bright_red]kurokami> [/]").strip()
        if choice == "1":
            _interactive_scan_flow()
        elif choice == "2":
            _interactive_history_flow()
        elif choice == "3":
            _interactive_export_flow()
        elif choice == "4":
            console.print(Text("Exiting KUROKAMI.", style=DIM_STYLE))
            break
        else:
            console.print(Text("Invalid selection. Choose 1, 2, 3, or 4.", style="bold red"))
        console.print(Rule(style=DIM_STYLE))


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """KUROKAMI - AI-driven Penetration Testing Framework"""
    if ctx.invoked_subcommand is None:
        _interactive_shell()


@cli.command()
@click.option("--target", "-t", help="Single target (IP, Domain, CIDR)")
@click.option("--scope", "-s", type=click.Path(exists=True), help="File containing target scope")
def scan(target, scope):
    """Initiate a full AI-driven scan cycle against the given scope."""
    if not target and not scope:
        console.print("[bold red]Error:[/] Must specify either --target or --scope.")
        sys.exit(1)

    db_path = bootstrap_database()
    scan_target = target if target else f"scope:{scope}"
    scan_session = create_scan_session(scan_target)

    console.print(f"[bold bright_red]Starting KUROKAMI Scan Pipeline...[/]")
    console.print(f"Session ID: [bright_red]{scan_session.id}[/bright_red]")
    console.print(f"Database: [dark_orange3]{db_path}[/dark_orange3]")
    if target:
        console.print(f"Target: [bright_red]{target}[/bright_red]")
    if scope:
        console.print(f"Scope File: [bright_red]{scope}[/bright_red]")

    result = run_scan_pipeline(
        scan_session_id=scan_session.id,
        scan_target=scan_target,
        scope_path=scope,
    )
    console.print(
        f"Pipeline status: [green]completed[/green] | Modules executed: [bright_red]{result['modules_executed']}[/bright_red] | "
        f"Findings recorded: [bright_red]{result['findings_recorded']}[/bright_red] | "
        f"Risk: [bright_red]{result['risk_level']}[/bright_red] | "
        f"Planner: [bright_red]{result['planner_mode']}[/bright_red] | "
        f"RAG: [bright_red]{result['rag_status']}[/bright_red] ({result['documents_indexed']} docs)"
    )


@cli.group()
def history():
    """Manage and review scan session history."""
    pass


@history.command(name="list")
def list_history():
    """List all previous sessions."""
    sessions = _load_sessions()
    if not sessions:
        console.print("No sessions found.")
        return
    console.print(_render_history_table(sessions))


@history.command()
@click.argument("session_id")
def resume(session_id):
    """Resume an incomplete or past session."""
    bootstrap_database()
    get_session, _, _, _, _, _, _, Session, _ = _require_database_models()

    with get_session() as db:
        session_record = db.get(Session, int(session_id))
        if not session_record:
            console.print(f"[bold red]Session {session_id} not found.[/]")
            sys.exit(1)

        session_record.status = "resumed"
        scan_target = session_record.target

    console.print(f"Resuming session: [bright_red]{session_id}[/bright_red]")
    result = run_resume_pipeline(scan_session_id=int(session_id), scan_target=scan_target)
    console.print(
        f"Resumed pipeline completed | Modules executed: [bright_red]{result['modules_executed']}[/bright_red] | "
        f"Findings recorded: [bright_red]{result['findings_recorded']}[/bright_red] | Risk: [bright_red]{result['risk_level']}[/bright_red] | "
        f"RAG: [bright_red]{result['rag_status']}[/bright_red] ({result['documents_indexed']} docs)"
    )


@history.command()
@click.argument("id1")
@click.argument("id2")
def diff(id1, id2):
    """Diff the findings between two specific sessions."""
    bootstrap_database()
    get_session, _, _, _, _, _, Finding, Session, _ = _require_database_models()
    from .reporting import diff_findings

    with get_session() as db:
        left = db.get(Session, int(id1))
        right = db.get(Session, int(id2))
        if not left or not right:
            console.print("[bold red]One or both sessions were not found.[/]")
            sys.exit(1)

        left_findings = db.query(Finding).filter(Finding.session_id == left.id).order_by(Finding.id.asc()).all()
        right_findings = db.query(Finding).filter(Finding.session_id == right.id).order_by(Finding.id.asc()).all()

    result = diff_findings(left_findings, right_findings)
    console.print(f"Diffing session [bright_red]{id1}[/bright_red] vs [bright_red]{id2}[/bright_red]")

    table = Table(title="Findings Diff Summary", header_style=PRIMARY_STYLE)
    table.add_column("Category", style="bright_red")
    table.add_column("Count", style=ACCENT_STYLE)
    table.add_row("Added", str(len(result["added"])))
    table.add_row("Removed", str(len(result["removed"])))
    table.add_row("Severity Changed", str(len(result["severity_changed"])))
    table.add_row("Confidence Changed", str(len(result["confidence_changed"])))
    console.print(table)

    if result["added"]:
        console.print("[bold green]Added Findings[/bold green]")
        for finding in result["added"]:
            console.print(f"- {finding.vuln_name} [{finding.severity}]")
    if result["removed"]:
        console.print("[bold red]Removed Findings[/bold red]")
        for finding in result["removed"]:
            console.print(f"- {finding.vuln_name} [{finding.severity}]")
    if result["severity_changed"]:
        console.print("[bold yellow]Severity Changes[/bold yellow]")
        for change in result["severity_changed"]:
            console.print(f"- {change['from'].vuln_name}: {change['from'].severity} -> {change['to'].severity}")


@cli.command()
@click.option("--session", required=True, help="Session ID to export")
@click.option("--format", type=click.Choice(["pdf", "html", "json"], case_sensitive=False), required=True, help="Export output format")
def export(session, format):
    """Export a session report to the specified format."""
    bootstrap_database()
    get_session, resolve_config_path, AIReasoningChain, Checkpoint, Exploit, Export, Finding, Session, Target = _require_database_models()
    from .reporting import build_session_payload, write_export

    exports_dir = resolve_config_path("paths", "exports_dir", "data/exports")
    exports_dir.mkdir(parents=True, exist_ok=True)

    with get_session() as db:
        bundle = _load_session_bundle(db, Session, Target, Finding, AIReasoningChain, Checkpoint, Exploit, int(session))
        if not bundle:
            console.print(f"[bold red]Session {session} not found.[/]")
            sys.exit(1)
        session_record, targets, findings, reasoning, checkpoints, exploits = bundle
        payload = build_session_payload(session_record, targets, findings, reasoning, checkpoints, exploits)
        export_path = exports_dir / f"session_{session_record.id}.{format.lower()}"
        write_export(format.lower(), payload, export_path)

        export_record = Export(
            session_id=session_record.id,
            format=format.lower(),
            filepath=str(export_path),
        )
        db.add(export_record)

    console.print(
        f"Exported session [bright_red]{session}[/bright_red] to [bold]{format.upper()}[/bold]: [dark_orange3]{export_path}[/dark_orange3]"
    )


@cli.command()
def config():
    """Show the currently loaded configuration settings."""
    cfg, path = load_config()
    if not cfg:
        console.print("[bold red]No kurokami.conf found![/]")
        sys.exit(1)

    console.print(f"[bold bright_red]Loaded configuration from:[/] {path}")

    table = Table(title="KUROKAMI Configuration", header_style=PRIMARY_STYLE)
    table.add_column("Section", style="bright_red")
    table.add_column("Key", style=ACCENT_STYLE)
    table.add_column("Value", style="dim")

    for section in cfg.sections():
        for key, val in cfg.items(section):
            table.add_row(section, key, val)

    console.print(table)


if __name__ == "__main__":
    cli()
