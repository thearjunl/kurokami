import re
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KSslscanModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_sslscan"

    @property
    def description(self) -> str:
        return "Assess TLS protocols and ciphers using sslscan."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_sslscan",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        sslscan_path = shutil.which("sslscan")
        if not sslscan_path:
            return {"status": "skipped", "output": "sslscan binary was not found in PATH.", "findings": [], "target_updates": {}}

        normalized_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = normalized_target if ":" in normalized_target else f"{normalized_target}:443"
        process = await create_subprocess_exec(sslscan_path, host, stdout=PIPE, stderr=PIPE)
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "sslscan execution failed.", "findings": [], "target_updates": {}}

        findings = []
        tech_stack = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("SSLv") or stripped.startswith("TLSv"):
                tech_stack.append({"type": "tls", "value": stripped})
                lowered = stripped.lower()
                severity = "info"
                if "sslv2" in lowered or "sslv3" in lowered or "rc4" in lowered:
                    severity = "high"
                elif "tlsv1.0" in lowered or "tlsv1.1" in lowered:
                    severity = "medium"
                findings.append(
                    {
                        "vuln_name": "TLS configuration observation",
                        "severity": severity,
                        "confidence": 0.85,
                        "description": stripped,
                        "cve_id": None,
                    }
                )
            elif re.search(r"certificate|issuer|subject", stripped, re.IGNORECASE):
                tech_stack.append({"type": "certificate", "value": stripped})

        return {
            "status": "completed",
            "output": f"sslscan completed for {host} with {len(findings)} TLS observation(s).",
            "findings": findings,
            "target_updates": {"tech_stack": tech_stack},
        }
