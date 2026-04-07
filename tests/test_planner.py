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
        }
    )

    assert plan["selected_modules"][:4] == ["k_nmap", "k_nikto", "k_whatweb", "k_gobuster"]


def test_planner_includes_smb_module_when_target_looks_smb():
    planner = Planner(session_id=1, target="smb://fileserver")
    plan = planner.build_plan({"k_nmap": object(), "k_smbclient": object()})

    assert "k_smbclient" in plan["selected_modules"]
