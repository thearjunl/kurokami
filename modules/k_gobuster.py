import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KGobusterModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_gobuster"

    @property
    def description(self) -> str:
        return "Enumerate common web paths with Gobuster."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_gobuster",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        gobuster_path = shutil.which("gobuster")
        if not gobuster_path:
            return {"status": "skipped", "output": "Gobuster binary was not found in PATH.", "findings": [], "target_updates": {}}

        wordlist = kwargs.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"
        process = await create_subprocess_exec(
            gobuster_path,
            "dir",
            "-q",
            "-u",
            target if target.startswith(("http://", "https://")) else f"http://{target}",
            "-w",
            wordlist,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and "no such file" in error_output.lower():
            return {"status": "skipped", "output": f"Gobuster wordlist unavailable: {wordlist}", "findings": [], "target_updates": {}}
        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "Gobuster execution failed.", "findings": [], "target_updates": {}}

        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or "/" not in line:
                continue
            findings.append(
                {
                    "vuln_name": f"Discovered path {line.split()[0]}",
                    "severity": "low",
                    "confidence": 0.7,
                    "description": f"Gobuster discovered content path: {line}",
                    "cve_id": None,
                }
            )

        return {
            "status": "completed",
            "output": f"Gobuster completed against {target} with {len(findings)} discovered path(s).",
            "findings": findings,
            "target_updates": {},
        }
