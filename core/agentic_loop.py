import asyncio
from datetime import datetime
from pathlib import Path

from .database import get_session
from .db import AIReasoningChain, Finding, ReasoningStage, Session, Target
from .discovery import discover_modules
from .planner import Planner
from .rag import SessionRAGStore


class AgenticLoop:
    """Initial orchestration layer for scan execution and DB persistence."""

    def __init__(self, session_id: int, target: str, scope_path: str | None = None):
        self.session_id = session_id
        self.target = target
        self.scope_path = scope_path

    async def run(self) -> dict:
        target_record = self._ensure_target_record()
        available_modules = discover_modules(str(Path(__file__).resolve().parent.parent / "modules"))
        plan = self._build_execution_plan(available_modules)
        modules = {name: available_modules[name] for name in plan["selected_modules"] if name in available_modules}

        self._update_session(status="running")
        self._record_reasoning_stage(
            stage=ReasoningStage.RECON,
            input_context=self._build_input_context(module_names=available_modules.keys()),
            output=(
                f"Initialized session for target '{self.target}' with {len(available_modules)} discovered modules. "
                f"Planner selected {plan['selected_modules']}."
            ),
        )
        self._record_reasoning_stage(
            stage=ReasoningStage.ATTACK_SURFACE,
            input_context=f"Planner profile: {plan['profile']} | context_hits={plan['context_hits']}",
            output=plan["summary"],
        )

        module_results = await self._run_modules(target_record.id, modules)
        self._record_reasoning_stage(
            stage=ReasoningStage.ATTACK_SURFACE,
            input_context=f"Module execution summary for {self.target}",
            output=self._summarize_module_results(module_results),
        )

        prioritized_findings = self._load_findings_snapshot(target_record.id)
        self._record_reasoning_stage(
            stage=ReasoningStage.EXPLOIT_PRIORITY,
            input_context=f"Findings snapshot generated from {len(module_results)} module runs.",
            output=self._summarize_findings(prioritized_findings),
        )

        self._record_reasoning_stage(
            stage=ReasoningStage.REMEDIATION,
            input_context=f"Post-processing for target {self.target}",
            output=self._generate_remediation_summary(prioritized_findings),
        )
        rag_result = self._index_session_knowledge()
        self._update_session(status="completed", end_time=datetime.utcnow())

        return {
            "target_id": target_record.id,
            "modules_executed": len(module_results),
            "findings_recorded": len(prioritized_findings),
            "module_results": module_results,
            "rag_status": rag_result["status"],
            "documents_indexed": rag_result["documents_indexed"],
            "plan_summary": plan["summary"],
        }

    def _ensure_target_record(self) -> Target:
        with get_session() as db:
            target_record = Target(
                session_id=self.session_id,
                host=self.target,
                ip=None,
                open_ports=[],
                tech_stack=[],
            )
            db.add(target_record)
            db.flush()
            return target_record

    def _update_session(self, status: str, end_time: datetime | None = None) -> None:
        with get_session() as db:
            session_record = db.get(Session, self.session_id)
            if not session_record:
                raise ValueError(f"Session {self.session_id} does not exist.")

            session_record.status = status
            if end_time is not None:
                session_record.end_time = end_time

    def _record_reasoning_stage(self, stage: ReasoningStage, input_context: str, output: str) -> None:
        with get_session() as db:
            db.add(
                AIReasoningChain(
                    session_id=self.session_id,
                    stage=stage,
                    input_context=input_context,
                    output=output,
                    model_used="bootstrap-agent-loop",
                )
            )

    async def _run_modules(self, target_id: int, modules: dict) -> list[dict]:
        results = []

        if not modules:
            results.append(
                {
                    "module": "discovery",
                    "status": "skipped",
                    "output": "No tool modules discovered under modules/.",
                    "findings": [],
                }
            )
            return results

        for module_name, module in modules.items():
            try:
                result = await module.execute(self.target, session_id=self.session_id, target_id=target_id)
            except Exception as exc:
                result = {
                    "status": "error",
                    "output": f"Module execution failed: {exc}",
                    "findings": [],
                    "target_updates": {},
                }

            normalized_result = self._normalize_module_result(module_name, result)
            self._apply_target_updates(target_id, normalized_result["target_updates"])
            self._persist_findings(target_id, normalized_result["findings"])
            results.append(normalized_result)

        return results

    def _apply_target_updates(self, target_id: int, target_updates: dict) -> None:
        if not target_updates:
            return

        with get_session() as db:
            target_record = db.get(Target, target_id)
            if not target_record:
                raise ValueError(f"Target {target_id} does not exist.")

            if "host" in target_updates and target_updates["host"]:
                target_record.host = target_updates["host"]
            if "ip" in target_updates:
                target_record.ip = target_updates["ip"]
            if "open_ports" in target_updates:
                target_record.open_ports = self._merge_list_data(
                    target_record.open_ports,
                    target_updates["open_ports"],
                )
            if "tech_stack" in target_updates:
                target_record.tech_stack = self._merge_list_data(
                    target_record.tech_stack,
                    target_updates["tech_stack"],
                )

    def _persist_findings(self, target_id: int, findings: list[dict]) -> None:
        if not findings:
            return

        with get_session() as db:
            for finding in findings:
                db.add(
                    Finding(
                        session_id=self.session_id,
                        target_id=target_id,
                        vuln_name=finding.get("vuln_name", "Unnamed Finding"),
                        severity=finding.get("severity", "info"),
                        confidence=finding.get("confidence"),
                        description=finding.get("description"),
                        cve_id=finding.get("cve_id"),
                    )
                )

    def _load_findings_snapshot(self, target_id: int) -> list[Finding]:
        with get_session() as db:
            return (
                db.query(Finding)
                .filter(Finding.session_id == self.session_id, Finding.target_id == target_id)
                .order_by(Finding.severity.desc(), Finding.id.asc())
                .all()
            )

    def _build_input_context(self, module_names) -> str:
        context_lines = [f"target={self.target}", f"session_id={self.session_id}"]
        if self.scope_path:
            context_lines.append(f"scope_path={self.scope_path}")
        context_lines.append(f"discovered_modules={list(module_names)}")
        return "\n".join(context_lines)

    def _normalize_module_result(self, module_name: str, result: dict | None) -> dict:
        result = result or {}
        return {
            "module": module_name,
            "status": result.get("status", "unknown"),
            "output": result.get("output", ""),
            "findings": result.get("findings", []) or [],
            "target_updates": result.get("target_updates", {}) or {},
        }

    def _summarize_module_results(self, module_results: list[dict]) -> str:
        lines = []
        for result in module_results:
            lines.append(
                f"{result['module']}: status={result['status']}, findings={len(result['findings'])}"
            )
        return "\n".join(lines) if lines else "No modules executed."

    def _summarize_findings(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings were recorded during this session."

        return "\n".join(
            f"{finding.severity.upper()}: {finding.vuln_name} (confidence={finding.confidence})"
            for finding in findings
        )

    def _generate_remediation_summary(self, findings: list[Finding]) -> str:
        if not findings:
            return "No remediation actions required yet because no findings were recorded."

        high_priority = [finding for finding in findings if finding.severity.lower() in {"critical", "high"}]
        if not high_priority:
            return "Review recorded findings and validate impact before remediation planning."

        return (
            f"Prioritize remediation for {len(high_priority)} high-severity findings, "
            "starting with externally reachable services and known-CVE exposure."
        )

    def _index_session_knowledge(self) -> dict:
        store = SessionRAGStore(session_id=self.session_id)
        result = store.index_session()
        self._record_reasoning_stage(
            stage=ReasoningStage.REMEDIATION,
            input_context=f"RAG indexing result for session {self.session_id}",
            output=(
                f"RAG status={result['status']} documents_indexed={result['documents_indexed']} "
                f"index_path={result['index_path']}"
            ),
        )
        return result

    def _build_execution_plan(self, available_modules: dict) -> dict:
        planner = Planner(session_id=self.session_id, target=self.target, scope_path=self.scope_path)
        return planner.build_plan(available_modules)

    def _merge_list_data(self, existing, incoming):
        existing = existing or []
        incoming = incoming or []

        merged = []
        seen = set()
        for item in [*existing, *incoming]:
            key = repr(item)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged


async def run_agentic_loop(session_id: int, target: str, scope_path: str | None = None) -> dict:
    loop = AgenticLoop(session_id=session_id, target=target, scope_path=scope_path)
    return await loop.run()


def run_agentic_loop_sync(session_id: int, target: str, scope_path: str | None = None) -> dict:
    return asyncio.run(run_agentic_loop(session_id=session_id, target=target, scope_path=scope_path))
