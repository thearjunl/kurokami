import re
import shutil
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KNiktoModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_nikto"

    @property
    def description(self) -> str:
        return "Run Nikto web reconnaissance and normalize web findings."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_nikto",
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host or URL target to scan with Nikto.",
                    }
                },
                "required": ["target"],
            },
        }

    async def execute(self, target: str, **kwargs) -> dict:
        nikto_path = shutil.which("nikto")
        if not nikto_path:
            return {
                "status": "skipped",
                "output": "Nikto binary was not found in PATH.",
                "findings": [],
                "target_updates": {},
            }

        process = await create_subprocess_exec(
            nikto_path,
            "-host",
            target,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()

        raw_output = stdout.decode(errors="replace")
        error_output = stderr.decode(errors="replace").strip()

        if process.returncode not in (0, 1):
            return {
                "status": "error",
                "output": error_output or raw_output or "Nikto execution failed.",
                "findings": [],
                "target_updates": {},
            }

        findings, tech_stack = self._parse_nikto_output(raw_output)
        status = "completed" if findings or tech_stack else "completed"
        summary = f"Nikto completed against {target} with {len(findings)} finding(s)."
        if error_output:
            summary = f"{summary} STDERR: {error_output}"

        return {
            "status": status,
            "output": summary,
            "findings": findings,
            "target_updates": {
                "tech_stack": tech_stack,
            },
        }

    def _parse_nikto_output(self, output: str) -> tuple[list[dict], list[dict]]:
        findings = []
        tech_stack = []
        seen_stack = set()

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if "Server:" in line:
                server_value = line.split("Server:", 1)[1].strip()
                if server_value and server_value not in seen_stack:
                    tech_stack.append({"type": "server", "value": server_value})
                    seen_stack.add(server_value)
                continue

            if "Retrieved x-powered-by header:" in line.lower():
                header_value = line.split(":", 1)[1].strip()
                if header_value and header_value not in seen_stack:
                    tech_stack.append({"type": "x-powered-by", "value": header_value})
                    seen_stack.add(header_value)
                continue

            if not line.startswith("+"):
                continue

            severity = "medium"
            lowered = line.lower()
            if any(token in lowered for token in ("osvdb", "cve-", "vulnerable", "default", "exposed")):
                severity = "high"
            elif any(token in lowered for token in ("header", "cookie", "allowed", "uncommon")):
                severity = "low"

            cve_match = re.search(r"(CVE-\d{4}-\d+)", line, re.IGNORECASE)
            findings.append(
                {
                    "vuln_name": self._build_finding_name(line),
                    "severity": severity,
                    "confidence": 0.8,
                    "description": line.lstrip("+ ").strip(),
                    "cve_id": cve_match.group(1).upper() if cve_match else None,
                }
            )

        return findings, tech_stack

    def _build_finding_name(self, line: str) -> str:
        cleaned = line.lstrip("+ ").strip()
        if ": " in cleaned:
            cleaned = cleaned.split(": ", 1)[1]
        if len(cleaned) > 120:
            cleaned = f"{cleaned[:117]}..."
        return cleaned or "Nikto Finding"
