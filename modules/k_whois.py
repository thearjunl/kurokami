import re
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KWhoisModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_whois"

    @property
    def description(self) -> str:
        return "Collect domain registration and registrar context using whois."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_whois",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        whois_path = shutil.which("whois")
        if not whois_path:
            return {"status": "skipped", "output": "whois binary was not found in PATH.", "findings": [], "target_updates": {}}

        normalized_target = re.sub(r"^https?://", "", target).split("/")[0]
        process = await create_subprocess_exec(whois_path, normalized_target, stdout=PIPE, stderr=PIPE)
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "whois execution failed.", "findings": [], "target_updates": {}}

        findings = []
        for label in ("Registrar", "Name Server", "Creation Date", "Expiry Date"):
            for line in raw_output.splitlines():
                if line.lower().startswith(label.lower()):
                    findings.append(
                        {
                            "vuln_name": f"WHOIS {label}",
                            "severity": "info",
                            "confidence": 0.7,
                            "description": line.strip(),
                            "cve_id": None,
                        }
                    )
                    break

        tech_stack = [{"type": "whois", "value": line.strip()} for line in raw_output.splitlines()[:10] if ":" in line]
        return {
            "status": "completed",
            "output": f"whois completed for {normalized_target} with {len(findings)} structured details extracted.",
            "findings": findings,
            "target_updates": {"tech_stack": tech_stack},
        }
