import json
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KWhatwebModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_whatweb"

    @property
    def description(self) -> str:
        return "Fingerprint web technologies using WhatWeb."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_whatweb",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        whatweb_path = shutil.which("whatweb")
        if not whatweb_path:
            return {"status": "skipped", "output": "WhatWeb binary was not found in PATH.", "findings": [], "target_updates": {}}

        process = await create_subprocess_exec(
            whatweb_path,
            "--log-json=-",
            target,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode(errors="replace").strip()
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not output:
            return {"status": "error", "output": error_output or "WhatWeb execution failed.", "findings": [], "target_updates": {}}

        tech_stack = []
        findings = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugins = item.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                tech_stack.append({"type": "fingerprint", "value": plugin_name, "details": plugin_data})
                findings.append(
                    {
                        "vuln_name": f"Technology fingerprint: {plugin_name}",
                        "severity": "info",
                        "confidence": 0.75,
                        "description": f"WhatWeb detected {plugin_name} with metadata {plugin_data}",
                        "cve_id": None,
                    }
                )

        return {
            "status": "completed",
            "output": f"WhatWeb completed against {target} with {len(tech_stack)} technology fingerprints.",
            "findings": findings,
            "target_updates": {"tech_stack": tech_stack},
        }
