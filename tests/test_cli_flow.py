from click.testing import CliRunner

from core import cli as cli_module


def test_scan_command_prints_pipeline_summary(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr(cli_module, "bootstrap_database", lambda: "data/kurokami.db")
    monkeypatch.setattr(cli_module, "create_scan_session", lambda target: type("SessionStub", (), {"id": 7})())
    monkeypatch.setattr(
        cli_module,
        "run_scan_pipeline",
        lambda scan_session_id, scan_target, scope_path=None: {
            "modules_executed": 5,
            "findings_recorded": 3,
            "risk_level": "high",
            "planner_mode": "heuristic",
            "rag_status": "completed",
            "documents_indexed": 12,
        },
    )

    result = runner.invoke(cli_module.cli, ["scan", "--target", "example.com"])

    assert result.exit_code == 0
    assert "Pipeline status" in result.output
    assert "high" in result.output


def test_resume_command_prints_resume_summary(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr(cli_module, "bootstrap_database", lambda: "data/kurokami.db")

    class SessionStub:
        target = "example.com"
        status = "resumed"

    class DBStub:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, model, session_id):
            return SessionStub()

    monkeypatch.setattr(
        cli_module,
        "_require_database_models",
        lambda: (lambda: DBStub(), None, None, None, None, None, None, type("SessionModel", (), {}), None),
    )
    monkeypatch.setattr(
        cli_module,
        "run_resume_pipeline",
        lambda scan_session_id, scan_target: {
            "modules_executed": 2,
            "findings_recorded": 1,
            "risk_level": "medium",
            "rag_status": "completed",
            "documents_indexed": 4,
        },
    )

    result = runner.invoke(cli_module.cli, ["history", "resume", "1"])

    assert result.exit_code == 0
    assert "Resumed pipeline completed" in result.output
