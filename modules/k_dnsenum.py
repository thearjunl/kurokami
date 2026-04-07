import json
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KDnsenumModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_dnsenum"

    @property
    def description(self) -> str:
        return "Enumerate DNS records and related exposure using dnsenum."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_dnsenum",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        dnsenum_path = shutil.which("dnsenum")
        if not dnsenum_path:
            return {"status": "skipped", "output": "dnsenum binary was not found in PATH.", "findings": [], "target_updates": {}}

        normalized_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        process = await create_subprocess_exec(dnsenum_path, normalized_target, stdout=PIPE, stderr=PIPE)
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "dnsenum execution failed.", "findings": [], "target_updates": {}}

        findings = []
        records = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if any(token in stripped for token in ("NS record", "MX record", "host address", "TXT record")):
                findings.append(
                    {
                        "vuln_name": "DNS record enumeration",
                        "severity": "info",
                        "confidence": 0.75,
                        "description": stripped,
                        "cve_id": None,
                    }
                )
                records.append({"type": "dns", "value": stripped})

        return {
            "status": "completed",
            "output": f"dnsenum completed for {normalized_target} with {len(records)} notable DNS record(s).",
            "findings": findings,
            "target_updates": {"tech_stack": records},
        }
