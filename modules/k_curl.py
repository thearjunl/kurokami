import json
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KCurlModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_curl"

    @property
    def description(self) -> str:
        return "Capture HTTP headers and response metadata using curl."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_curl",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        curl_path = shutil.which("curl")
        if not curl_path:
            return {"status": "skipped", "output": "curl binary was not found in PATH.", "findings": [], "target_updates": {}}

        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        process = await create_subprocess_exec(
            curl_path,
            "-kI",
            "--max-time",
            "15",
            url,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "curl execution failed.", "findings": [], "target_updates": {}}

        findings = []
        tech_stack = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            header_name, header_value = stripped.split(":", 1)
            normalized_name = header_name.strip().lower()
            tech_stack.append({"type": "http-header", "name": normalized_name, "value": header_value.strip()})
            if normalized_name in {"server", "x-powered-by", "strict-transport-security", "content-security-policy"}:
                findings.append(
                    {
                        "vuln_name": f"HTTP header {header_name.strip()}",
                        "severity": "info",
                        "confidence": 0.8,
                        "description": stripped,
                        "cve_id": None,
                    }
                )

        return {
            "status": "completed",
            "output": f"curl captured {len(tech_stack)} HTTP header(s) from {url}.",
            "findings": findings,
            "target_updates": {"tech_stack": tech_stack},
        }
