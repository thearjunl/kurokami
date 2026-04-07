import re
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KSmbclientModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_smbclient"

    @property
    def description(self) -> str:
        return "Enumerate SMB shares with smbclient."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_smbclient",
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        }

    async def execute(self, target: str, **kwargs) -> dict:
        smbclient_path = shutil.which("smbclient")
        if not smbclient_path:
            return {"status": "skipped", "output": "smbclient binary was not found in PATH.", "findings": [], "target_updates": {}}

        normalized_target = target.replace("smb://", "").replace("\\\\", "").strip("/")
        process = await create_subprocess_exec(
            smbclient_path,
            "-N",
            "-L",
            f"//{normalized_target}",
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()
        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode != 0 and not raw_output:
            return {"status": "error", "output": error_output or "smbclient execution failed.", "findings": [], "target_updates": {}}

        findings = []
        shares = []
        for line in raw_output.splitlines():
            match = re.match(r"\s*([A-Za-z0-9$_-]+)\s+(Disk|IPC|Printer)\s+(.*)", line)
            if not match:
                continue
            share_name, share_type, comment = match.groups()
            shares.append({"type": "smb-share", "value": share_name, "share_type": share_type, "comment": comment.strip()})
            findings.append(
                {
                    "vuln_name": f"Enumerated SMB share {share_name}",
                    "severity": "medium" if share_type == "Disk" else "info",
                    "confidence": 0.85,
                    "description": f"smbclient listed share {share_name} ({share_type}) {comment.strip()}",
                    "cve_id": None,
                }
            )

        return {
            "status": "completed",
            "output": f"smbclient completed against {target} with {len(shares)} share(s) listed.",
            "findings": findings,
            "target_updates": {"tech_stack": shares},
        }
