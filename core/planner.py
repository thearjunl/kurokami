import configparser
from pathlib import Path


class Planner:
    """Simple planner that selects modules from target shape and prior context."""

    def __init__(self, session_id: int, target: str, scope_path: str | None = None):
        self.session_id = session_id
        self.target = target
        self.scope_path = scope_path
        self.model_name = self._resolve_model_name()

    def build_plan(self, available_modules: dict) -> dict:
        context_hits = self._retrieve_context_hits()
        profile = self._infer_profile()
        selected = []
        rationale = []

        if "k_nmap" in available_modules:
            selected.append("k_nmap")
            rationale.append("Run port and service discovery first to map exposed surface.")
        if profile["is_web"] and "k_nikto" in available_modules:
            selected.append("k_nikto")
            rationale.append("Target looks web-facing, so run Nikto for HTTP checks.")
        if profile["is_web"] and "k_whatweb" in available_modules:
            selected.append("k_whatweb")
            rationale.append("Fingerprint web technologies to enrich the tech stack.")
        if profile["is_domain_like"] and "k_gobuster" in available_modules:
            selected.append("k_gobuster")
            rationale.append("Enumerate likely web paths because the target appears to be a host/domain.")
        if profile["looks_smb"] and "k_smbclient" in available_modules:
            selected.append("k_smbclient")
            rationale.append("Inspect SMB exposure because the target suggests file sharing.")

        for module_name in available_modules:
            if module_name not in selected:
                selected.append(module_name)
                rationale.append(f"Keep {module_name} available as a fallback step.")

        return {
            "model_used": self.model_name,
            "selected_modules": selected,
            "context_hits": context_hits,
            "profile": profile,
            "summary": " ".join(rationale),
        }

    def _infer_profile(self):
        lower_target = self.target.lower()
        return {
            "is_web": lower_target.startswith(("http://", "https://")) or "." in lower_target,
            "is_domain_like": any(char.isalpha() for char in lower_target) or "/" in lower_target,
            "looks_smb": any(token in lower_target for token in ("smb", "445", "\\\\")),
            "has_scope_file": bool(self.scope_path),
        }

    def _resolve_model_name(self):
        candidate_paths = [
            Path.cwd() / "kurokami.conf",
            Path.home() / ".config" / "kurokami" / "kurokami.conf",
            Path("/etc/kurokami/kurokami.conf"),
        ]
        config = configparser.ConfigParser()
        for path in candidate_paths:
            if path.exists():
                config.read(path)
                break
        return config.get("ai", "default_model", fallback="heuristic-planner")

    def _retrieve_context_hits(self):
        try:
            from .rag import SessionRAGStore
        except ModuleNotFoundError:
            return []
        return SessionRAGStore(self.session_id).retrieve(self.target, limit=3)
