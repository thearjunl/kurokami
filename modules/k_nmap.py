import shutil
import xml.etree.ElementTree as ET
from asyncio.subprocess import PIPE, create_subprocess_exec

from core.module_base import KurokamiModule


class KNmapModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_nmap"

    @property
    def description(self) -> str:
        return "Run Nmap service discovery and return normalized recon data."

    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_nmap",
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host, IP, or CIDR target to scan with Nmap.",
                    }
                },
                "required": ["target"],
            },
        }

    async def execute(self, target: str, **kwargs) -> dict:
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            return {
                "status": "skipped",
                "output": "Nmap binary was not found in PATH.",
                "findings": [],
                "target_updates": {},
            }

        process = await create_subprocess_exec(
            nmap_path,
            "-Pn",
            "-sV",
            "-T4",
            "-oX",
            "-",
            target,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_text = stderr.decode(errors="replace").strip() or "Unknown nmap failure"
            return {
                "status": "error",
                "output": error_text,
                "findings": [],
                "target_updates": {},
            }

        try:
            parsed = self._parse_nmap_xml(stdout.decode(errors="replace"), fallback_host=target)
        except ET.ParseError as exc:
            return {
                "status": "error",
                "output": f"Failed to parse Nmap XML output: {exc}",
                "findings": [],
                "target_updates": {},
            }

        open_ports = parsed["open_ports"]
        findings = []
        for port in open_ports:
            findings.append(
                {
                    "vuln_name": f"Open port {port['port']}/{port['protocol']}",
                    "severity": "info",
                    "confidence": 0.95,
                    "description": (
                        f"Service {port.get('service') or 'unknown'} exposed on "
                        f"{parsed['host']}:{port['port']}/{port['protocol']}"
                    ),
                    "cve_id": None,
                }
            )

        return {
            "status": "completed",
            "output": (
                f"Nmap discovered {len(open_ports)} open port(s) on {parsed['host']}"
                + (f" ({parsed['ip']})" if parsed["ip"] else "")
            ),
            "findings": findings,
            "target_updates": {
                "host": parsed["host"],
                "ip": parsed["ip"],
                "open_ports": open_ports,
            },
        }

    def _parse_nmap_xml(self, xml_text: str, fallback_host: str) -> dict:
        root = ET.fromstring(xml_text)
        host_node = root.find("host")

        if host_node is None:
            return {"host": fallback_host, "ip": None, "open_ports": []}

        ip_address = None
        for address in host_node.findall("address"):
            addr_type = address.attrib.get("addrtype", "")
            if addr_type in {"ipv4", "ipv6"}:
                ip_address = address.attrib.get("addr")
                break

        hostname = fallback_host
        hostname_node = host_node.find("./hostnames/hostname")
        if hostname_node is not None and hostname_node.attrib.get("name"):
            hostname = hostname_node.attrib["name"]
        elif ip_address:
            hostname = ip_address

        open_ports = []
        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            service_node = port_node.find("service")
            open_ports.append(
                {
                    "port": int(port_node.attrib.get("portid", "0")),
                    "protocol": port_node.attrib.get("protocol", "tcp"),
                    "service": service_node.attrib.get("name") if service_node is not None else None,
                    "product": service_node.attrib.get("product") if service_node is not None else None,
                    "version": service_node.attrib.get("version") if service_node is not None else None,
                }
            )

        return {"host": hostname, "ip": ip_address, "open_ports": open_ports}
