import configparser
import json
from pathlib import Path

from .ollama import DEFAULT_OLLAMA_HOST, OllamaClient


class Planner:
    """Target-aware planner that can use Ollama and falls back to local heuristics."""

    def __init__(self, session_id: int, target: str, scope_path: str | None = None):
        self.session_id = session_id
        self.target = target
        self.scope_path = scope_path
        self.config = self._load_config()
        self.model_name = self.config.get("ai", "default_model", fallback="heuristic-planner")
        self.ollama_host = self.config.get("ai", "ollama_host", fallback=DEFAULT_OLLAMA_HOST)

    def build_plan(self, available_modules: dict) -> dict:
        context_hits = self._retrieve_context_hits()
        profile = self._infer_profile()
        heuristic_plan = self._build_heuristic_plan(available_modules, profile, context_hits)
        llm_plan = self._build_llm_plan(available_modules, profile, context_hits)
        if llm_plan:
            return llm_plan
        return heuristic_plan

    def _build_llm_plan(self, available_modules: dict, profile: dict, context_hits: list[dict]) -> dict | None:
        client = OllamaClient(host=self.ollama_host)
        if not client.is_available():
            return None

        module_summaries = {
            name: {
                "description": getattr(module, "description", ""),
                "tool_schema": getattr(module, "tool_schema", {}),
            }
            for name, module in available_modules.items()
        }

        schema = {
            "type": "object",
            "properties": {
                "selected_modules": {"type": "array", "items": {"type": "string"}},
                "summary": {"type": "string"},
            },
            "required": ["selected_modules", "summary"],
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "You are planning a local penetration testing workflow. "
                    "Select only module names that exist in the provided module list. "
                    "Prefer broad recon first, then protocol-specific enumeration."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "target": self.target,
                        "scope_path": self.scope_path,
                        "profile": profile,
                        "context_hits": context_hits,
                        "available_modules": module_summaries,
                    }
                ),
            },
        ]

        try:
            response = client.chat(model=self.model_name, messages=messages, format_schema=schema)
            content = response.get("message", {}).get("content", "{}")
            payload = json.loads(content)
            selected = [name for name in payload.get("selected_modules", []) if name in available_modules]
            if not selected:
                return None
            return {
                "model_used": self.model_name,
                "selected_modules": self._append_unselected_fallbacks(selected, available_modules),
                "context_hits": context_hits,
                "profile": profile,
                "summary": payload.get("summary", "LLM planner selected modules."),
                "planner_mode": "ollama",
            }
        except Exception:
            return None

    def _build_heuristic_plan(self, available_modules: dict, profile: dict, context_hits: list[dict]) -> dict:
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
        if profile["is_domain_like"] and "k_whois" in available_modules:
            selected.append("k_whois")
            rationale.append("Gather registration and ASN context for domain-like targets.")
        if profile["is_domain_like"] and "k_dnsenum" in available_modules:
            selected.append("k_dnsenum")
            rationale.append("Enumerate DNS records and subdomain-related context.")
        if profile["is_web"] and "k_gobuster" in available_modules:
            selected.append("k_gobuster")
            rationale.append("Enumerate likely web paths because the target appears web-facing.")
        if profile["is_web"] and "k_curl" in available_modules:
            selected.append("k_curl")
            rationale.append("Capture HTTP headers and protocol details for the target.")
        if profile["looks_tls"] and "k_sslscan" in available_modules:
            selected.append("k_sslscan")
            rationale.append("Assess exposed TLS configuration for HTTPS or TLS-capable services.")
        if profile["looks_smb"] and "k_smbclient" in available_modules:
            selected.append("k_smbclient")
            rationale.append("Inspect SMB exposure because the target suggests file sharing.")

        selected = self._append_unselected_fallbacks(selected, available_modules)
        return {
            "model_used": self.model_name,
            "selected_modules": selected,
            "context_hits": context_hits,
            "profile": profile,
            "summary": " ".join(rationale) or "Fallback heuristic planner selected all available modules.",
            "planner_mode": "heuristic",
        }

    def _append_unselected_fallbacks(self, selected: list[str], available_modules: dict) -> list[str]:
        ordered = list(dict.fromkeys(selected))
        for module_name in available_modules:
            if module_name not in ordered:
                ordered.append(module_name)
        return ordered

    def _infer_profile(self):
        lower_target = self.target.lower()
        return {
            "is_web": lower_target.startswith(("http://", "https://")) or "." in lower_target,
            "is_domain_like": any(char.isalpha() for char in lower_target) or "/" in lower_target,
            "looks_smb": any(token in lower_target for token in ("smb", "445", "\\\\")),
            "looks_tls": lower_target.startswith("https://") or ":443" in lower_target,
            "has_scope_file": bool(self.scope_path),
        }

    def _load_config(self):
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
        return config

    def _retrieve_context_hits(self):
        try:
            from .rag import SessionRAGStore
        except ModuleNotFoundError:
            return []
        return SessionRAGStore(self.session_id).retrieve(self.target, limit=3)
