import os
import sys
import asyncio
import click
from rich.console import Console
from rich.table import Table
import configparser

# The CLI core setup
console = Console()

def load_config():
    """
    Lookup order:
    1. ./kurokami.conf
    2. ~/.config/kurokami/kurokami.conf
    3. /etc/kurokami/kurokami.conf
    """
    config = configparser.ConfigParser()
    
    paths_to_check = [
        os.path.join(os.getcwd(), 'kurokami.conf'),
        os.path.expanduser('~/.config/kurokami/kurokami.conf'),
        '/etc/kurokami/kurokami.conf'
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

@click.group()
def cli():
    """KUROKAMI - AI-driven Penetration Testing Framework"""
    pass

@cli.command()
@click.option('--target', '-t', help='Single target (IP, Domain, CIDR)')
@click.option('--scope', '-s', type=click.Path(exists=True), help='File containing target scope')
def scan(target, scope):
    """Initiate a full AI-driven scan cycle against the given scope."""
    if not target and not scope:
        console.print("[bold red]Error:[/] Must specify either --target or --scope.")
        sys.exit(1)

    db_path = bootstrap_database()
    scan_target = target if target else f"scope:{scope}"
    scan_session = create_scan_session(scan_target)
        
    console.print(f"[bold green]Starting KUROKAMI Scan Pipeline...[/]")
    console.print(f"Session ID: [cyan]{scan_session.id}[/cyan]")
    console.print(f"Database: [cyan]{db_path}[/cyan]")
    if target:
        console.print(f"Target: [cyan]{target}[/cyan]")
    if scope:
        console.print(f"Scope File: [cyan]{scope}[/cyan]")

    result = run_scan_pipeline(
        scan_session_id=scan_session.id,
        scan_target=scan_target,
        scope_path=scope,
    )
    console.print(
        f"Pipeline status: [green]completed[/green] | Modules executed: [cyan]{result['modules_executed']}[/cyan] | "
        f"Findings recorded: [cyan]{result['findings_recorded']}[/cyan] | "
        f"Risk: [cyan]{result['risk_level']}[/cyan] | "
        f"Planner: [cyan]{result['planner_mode']}[/cyan] | "
        f"RAG: [cyan]{result['rag_status']}[/cyan] ({result['documents_indexed']} docs)"
    )

@cli.group()
def history():
    """Manage and review scan session history."""
    pass

@history.command()
def list():
    """List all previous sessions."""
    bootstrap_database()
    get_session, _, _, _, _, _, _, Session, _ = _require_database_models()

    console.print("[bold blue]Session History:[/bold blue]")
    table = Table(title="KUROKAMI Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Risk", style="yellow")
    table.add_column("Started", style="white")
    table.add_column("Ended", style="white")

    with get_session() as db:
        sessions = db.query(Session).order_by(Session.start_time.desc()).all()

    if not sessions:
        console.print("No sessions found.")
        return

    for session in sessions:
        table.add_row(
            str(session.id),
            session.target,
            session.status,
            session.risk_level or "unknown",
            str(session.start_time),
            str(session.end_time) if session.end_time else "-",
        )

    console.print(table)

@history.command()
@click.argument('session_id')
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

    console.print(f"Resuming session: [cyan]{session_id}[/cyan]")
    result = run_resume_pipeline(scan_session_id=int(session_id), scan_target=scan_target)
    console.print(
        f"Resumed pipeline completed | Modules executed: [cyan]{result['modules_executed']}[/cyan] | "
        f"Findings recorded: [cyan]{result['findings_recorded']}[/cyan] | Risk: [cyan]{result['risk_level']}[/cyan] | "
        f"RAG: [cyan]{result['rag_status']}[/cyan] ({result['documents_indexed']} docs)"
    )

@history.command()
@click.argument('id1')
@click.argument('id2')
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
    console.print(f"Diffing session [cyan]{id1}[/cyan] vs [cyan]{id2}[/cyan]")

    table = Table(title="Findings Diff Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="magenta")
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
@click.option('--session', required=True, help='Session ID to export')
@click.option('--format', type=click.Choice(['pdf', 'html', 'json'], case_sensitive=False), required=True, help='Export output format')
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
        f"Exported session [cyan]{session}[/cyan] to [bold]{format.upper()}[/bold]: [cyan]{export_path}[/cyan]"
    )

@cli.command()
def config():
    """Show the currently loaded configuration settings."""
    cfg, path = load_config()
    if not cfg:
        console.print("[bold red]No kurokami.conf found![/]")
        sys.exit(1)
        
    console.print(f"[bold green]Loaded configuration from:[/] {path}")
    
    table = Table(title="KUROKAMI Configuration")
    table.add_column("Section", style="cyan")
    table.add_column("Key", style="magenta")
    table.add_column("Value", style="green")
    
    for section in cfg.sections():
        for key, val in cfg.items(section):
            table.add_row(section, key, val)
            
    console.print(table)

if __name__ == '__main__':
    cli()
