from core.planner import Planner


def test_planner_prioritizes_web_modules_for_web_targets():
    planner = Planner(session_id=1, target="https://example.com")
    plan = planner.build_plan(
        {
            "k_nmap": object(),
            "k_nikto": object(),
            "k_whatweb": object(),
            "k_gobuster": object(),
            "k_smbclient": object(),
            "k_curl": object(),
            "k_sslscan": object(),
        }
    )

    assert plan["selected_modules"][:6] == [
        "k_nmap",
        "k_nikto",
        "k_whatweb",
        "k_gobuster",
        "k_curl",
        "k_sslscan",
    ]


def test_planner_includes_smb_module_when_target_looks_smb():
    planner = Planner(session_id=1, target="smb://fileserver")
    plan = planner.build_plan({"k_nmap": object(), "k_smbclient": object()})

    assert "k_smbclient" in plan["selected_modules"]


def test_planner_falls_back_to_heuristics_when_ollama_is_unavailable(monkeypatch):
    monkeypatch.setattr("core.planner.OllamaClient.is_available", lambda self: False)
    planner = Planner(session_id=1, target="https://example.com")
    plan = planner.build_plan({"k_nmap": object(), "k_nikto": object()})

    assert plan["planner_mode"] == "heuristic"


def test_planner_uses_ollama_output_when_available(monkeypatch):
    monkeypatch.setattr("core.planner.OllamaClient.is_available", lambda self: True)
    monkeypatch.setattr(
        "core.planner.OllamaClient.chat",
        lambda self, model, messages, format_schema=None: {
            "message": {"content": '{"selected_modules":["k_nmap","k_sslscan"],"summary":"LLM selected network and TLS checks."}'}
        },
    )
    planner = Planner(session_id=1, target="https://secure.example.com")
    plan = planner.build_plan({"k_nmap": object(), "k_sslscan": object(), "k_nikto": object()})

    assert plan["planner_mode"] == "ollama"
    assert plan["selected_modules"][0:2] == ["k_nmap", "k_sslscan"]
