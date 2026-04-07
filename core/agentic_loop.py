import asyncio
from datetime import datetime
from pathlib import Path

from .checkpoints import CheckpointManager
from .database import get_session, _load_config
from .db import AIReasoningChain, Finding, ReasoningStage, Session, Target
from .discovery import discover_modules
from .exploitation import ExploitationPipeline
from .planner import Planner
from .rag import SessionRAGStore

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class AgenticLoop:
    """Session-aware orchestration layer for scan execution, checkpoints, and exploitation."""

    def __init__(self, session_id: int, target: str, scope_path: str | None = None, resume_mode: bool = False):
        self.session_id = session_id
        self.target = target
        self.scope_path = scope_path
        self.resume_mode = resume_mode
        self.checkpoints = CheckpointManager(session_id)
        self.allow_exploits = self._allow_exploits()

    async def run(self) -> dict:
        self.checkpoints.record(stage="BOOTSTRAP", state="started", payload={"resume_mode": self.resume_mode})
        target_record = self._ensure_target_record()
        available_modules = discover_modules(str(Path(__file__).resolve().parent.parent / "modules"))
        plan = self._build_execution_plan(available_modules)
        recon_modules = self._filter_modules_by_phase(available_modules, plan["selected_modules"], "recon")
        exploit_modules = self._filter_modules_by_phase(available_modules, plan["selected_modules"], "exploit")

        self._update_session(status="running", current_stage="RECON")
        self._record_reasoning_stage(
            stage=ReasoningStage.RECON,
            input_context=self._build_input_context(module_names=available_modules.keys()),
            output=(
                f"Initialized session for target '{self.target}' with {len(available_modules)} discovered modules. "
                f"Planner mode={plan['planner_mode']} selected {plan['selected_modules']}."
            ),
            model_used=plan["model_used"],
        )
        self._record_reasoning_stage(
            stage=ReasoningStage.ATTACK_SURFACE,
            input_context=f"Planner profile: {plan['profile']} | context_hits={plan['context_hits']}",
            output=plan["summary"],
            model_used=plan["model_used"],
        )

        module_results = await self._run_modules(target_record.id, recon_modules, stage_name="RECON")
        self._record_reasoning_stage(
            stage=ReasoningStage.ATTACK_SURFACE,
            input_context=f"Module execution summary for {self.target}",
            output=self._summarize_module_results(module_results),
            model_used=plan["model_used"],
        )

        prioritized_findings = self._load_findings_snapshot(target_record.id)
        computed_risk = self._compute_risk_level(prioritized_findings)
        self._update_session(current_stage="EXPLOIT_PRIORITY", risk_level=computed_risk)
        self._record_reasoning_stage(
            stage=ReasoningStage.EXPLOIT_PRIORITY,
            input_context=f"Findings snapshot generated from {len(module_results)} module runs.",
            output=self._summarize_findings(prioritized_findings, computed_risk),
            model_used=plan["model_used"],
        )

        exploit_results = await self._run_exploit_modules(target_record.id, exploit_modules)
        self._update_session(current_stage="REMEDIATION")
        self._record_reasoning_stage(
            stage=ReasoningStage.REMEDIATION,
            input_context=f"Post-processing for target {self.target}",
            output=self._generate_remediation_summary(prioritized_findings, exploit_results),
            model_used=plan["model_used"],
        )

        rag_result = self._index_session_knowledge()
        self._update_session(status="completed", end_time=datetime.utcnow(), risk_level=computed_risk, current_stage="COMPLETED")
        self.checkpoints.record(stage="COMPLETED", state="completed", payload={"risk_level": computed_risk})

        return {
            "target_id": target_record.id,
            "modules_executed": len(module_results),
            "exploit_modules_executed": len(exploit_results),
            "findings_recorded": len(prioritized_findings),
            "module_results": module_results,
            "exploit_results": exploit_results,
            "rag_status": rag_result["status"],
            "documents_indexed": rag_result["documents_indexed"],
            "plan_summary": plan["summary"],
            "risk_level": computed_risk,
            "planner_mode": plan["planner_mode"],
        }

    def _ensure_target_record(self) -> Target:
        with get_session() as db:
            if self.resume_mode:
                existing_target = (
                    db.query(Target)
                    .filter(Target.session_id == self.session_id)
                    .order_by(Target.id.asc())
                    .first()
                )
                if existing_target:
                    return existing_target

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

    def _update_session(
        self,
        status: str | None = None,
        end_time: datetime | None = None,
        risk_level: str | None = None,
        current_stage: str | None = None,
    ) -> None:
        with get_session() as db:
            session_record = db.get(Session, self.session_id)
            if not session_record:
                raise ValueError(f"Session {self.session_id} does not exist.")

            if status is not None:
                session_record.status = status
            if end_time is not None:
                session_record.end_time = end_time
            if risk_level is not None:
                session_record.risk_level = risk_level
            if current_stage is not None:
                session_record.current_stage = current_stage
                session_record.last_checkpoint = datetime.utcnow()

    def _record_reasoning_stage(
        self,
        stage: ReasoningStage,
        input_context: str,
        output: str,
        model_used: str = "bootstrap-agent-loop",
    ) -> None:
        with get_session() as db:
            db.add(
                AIReasoningChain(
                    session_id=self.session_id,
                    stage=stage,
                    input_context=input_context,
                    output=output,
                    model_used=model_used,
                )
            )

    async def _run_modules(self, target_id: int, modules: dict, stage_name: str) -> list[dict]:
        results = []

        if not modules:
            results.append(
                {
                    "module": "discovery",
                    "status": "skipped",
                    "output": f"No {stage_name.lower()} modules scheduled.",
                    "findings": [],
                    "target_updates": {},
                }
            )
            return results

        completed_modules = self.checkpoints.completed_modules(stage_name) if self.resume_mode else set()
        for module_name, module in modules.items():
            if module_name in completed_modules:
                results.append(
                    {
                        "module": module_name,
                        "status": "skipped",
                        "output": f"Skipped because checkpoint shows {module_name} already completed in {stage_name}.",
                        "findings": [],
                        "target_updates": {},
                        "persisted_findings": 0,
                    }
                )
                continue

            self.checkpoints.record(stage=stage_name, state="started", module_name=module_name)
            try:
                result = await module.execute(
                    self.target,
                    session_id=self.session_id,
                    target_id=target_id,
                    resume_mode=self.resume_mode,
                )
            except Exception as exc:
                result = {
                    "status": "error",
                    "output": f"Module execution failed: {exc}",
                    "findings": [],
                    "target_updates": {},
                }

            normalized_result = self._normalize_module_result(module_name, result)
            self._apply_target_updates(target_id, normalized_result["target_updates"])
            persisted_count = self._persist_findings(target_id, normalized_result["findings"])
            normalized_result["persisted_findings"] = persisted_count
            results.append(normalized_result)
            self.checkpoints.record(
                stage=stage_name,
                state=normalized_result["status"],
                module_name=module_name,
                payload={"persisted_findings": persisted_count, "output": normalized_result["output"]},
            )

        return results

    async def _run_exploit_modules(self, target_id: int, exploit_modules: dict) -> list[dict]:
        pipeline = ExploitationPipeline(
            session_id=self.session_id,
            target_id=target_id,
            allow_exploits=self.allow_exploits,
        )
        candidates = pipeline.candidate_findings()
        if not candidates or not exploit_modules:
            return []

        results = []
        completed_modules = self.checkpoints.completed_modules("EXPLOIT") if self.resume_mode else set()
        for module_name, module in exploit_modules.items():
            if module_name in completed_modules:
                results.append({"module": module_name, "status": "skipped", "output": "Skipped via checkpoint.", "attempts": 0})
                continue

            self.checkpoints.record(stage="EXPLOIT", state="started", module_name=module_name)
            attempts = 0
            outputs = []
            for finding in candidates:
                exploit_context = pipeline.build_context(finding)
                result = await module.execute(
                    self.target,
                    session_id=self.session_id,
                    target_id=target_id,
                    exploit_context=exploit_context,
                    allow_exploits=self.allow_exploits,
                )
                exploit_attempt = result.get("exploit_attempt")
                if exploit_attempt:
                    pipeline.record_attempt(
                        finding_id=finding.id,
                        payload=exploit_attempt.get("payload", ""),
                        result=exploit_attempt.get("result", ""),
                    )
                    attempts += 1
                outputs.append(result.get("output", ""))

            status = "completed" if attempts or self.allow_exploits else "skipped"
            combined = {"module": module_name, "status": status, "output": "\n".join(outputs), "attempts": attempts}
            results.append(combined)
            self.checkpoints.record(stage="EXPLOIT", state=status, module_name=module_name, payload={"attempts": attempts})

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
                target_record.open_ports = self._merge_list_data(target_record.open_ports, target_updates["open_ports"])
            if "tech_stack" in target_updates:
                target_record.tech_stack = self._merge_list_data(target_record.tech_stack, target_updates["tech_stack"])

    def _persist_findings(self, target_id: int, findings: list[dict]) -> int:
        if not findings:
            return 0

        inserted = 0
        with get_session() as db:
            existing = {
                self._finding_key(finding)
                for finding in db.query(Finding)
                .filter(Finding.session_id == self.session_id, Finding.target_id == target_id)
                .all()
            }

            for finding in findings:
                normalized = self._normalize_finding(finding)
                key = self._finding_key(normalized)
                if key in existing:
                    continue
                existing.add(key)
                db.add(
                    Finding(
                        session_id=self.session_id,
                        target_id=target_id,
                        vuln_name=normalized["vuln_name"],
                        severity=normalized["severity"],
                        confidence=normalized["confidence"],
                        description=normalized["description"],
                        cve_id=normalized["cve_id"],
                    )
                )
                inserted += 1
        return inserted

    def _load_findings_snapshot(self, target_id: int) -> list[Finding]:
        with get_session() as db:
            findings = (
                db.query(Finding)
                .filter(Finding.session_id == self.session_id, Finding.target_id == target_id)
                .all()
            )
        return sorted(
            findings,
            key=lambda finding: (-SEVERITY_ORDER.get((finding.severity or "info").lower(), 0), -(finding.confidence or 0.0), finding.id),
        )

    def _build_input_context(self, module_names) -> str:
        context_lines = [f"target={self.target}", f"session_id={self.session_id}", f"resume_mode={self.resume_mode}"]
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

    def _normalize_finding(self, finding: dict) -> dict:
        severity = (finding.get("severity") or "info").lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        confidence = finding.get("confidence")
        return {
            "vuln_name": finding.get("vuln_name", "Unnamed Finding"),
            "severity": severity,
            "confidence": max(0.0, min(float(confidence), 1.0)) if confidence is not None else 0.5,
            "description": finding.get("description"),
            "cve_id": finding.get("cve_id"),
        }

    def _finding_key(self, finding) -> tuple[str, str, str]:
        if isinstance(finding, dict):
            return (
                (finding.get("vuln_name") or "").strip().lower(),
                (finding.get("cve_id") or "").strip().upper(),
                (finding.get("description") or "").strip().lower(),
            )
        return (
            (finding.vuln_name or "").strip().lower(),
            (finding.cve_id or "").strip().upper(),
            (finding.description or "").strip().lower(),
        )

    def _compute_risk_level(self, findings: list[Finding]) -> str:
        if not findings:
            return "informational"

        weighted_score = 0.0
        for finding in findings:
            severity_score = SEVERITY_ORDER.get((finding.severity or "info").lower(), 0)
            weighted_score += severity_score * max(finding.confidence or 0.5, 0.1)

        if any((finding.severity or "").lower() == "critical" for finding in findings):
            return "critical"
        if weighted_score >= 8:
            return "high"
        if weighted_score >= 4:
            return "medium"
        if weighted_score >= 1:
            return "low"
        return "informational"

    def _summarize_module_results(self, module_results: list[dict]) -> str:
        lines = []
        for result in module_results:
            lines.append(
                f"{result['module']}: status={result['status']}, findings={len(result.get('findings', []))}, persisted={result.get('persisted_findings', 0)}"
            )
        return "\n".join(lines) if lines else "No modules executed."

    def _summarize_findings(self, findings: list[Finding], risk_level: str) -> str:
        if not findings:
            return "No findings were recorded during this session."

        lines = [f"Computed session risk level: {risk_level}"]
        lines.extend(
            f"{finding.severity.upper()}: {finding.vuln_name} (confidence={finding.confidence})"
            for finding in findings[:15]
        )
        return "\n".join(lines)

    def _generate_remediation_summary(self, findings: list[Finding], exploit_results: list[dict]) -> str:
        if not findings:
            return "No remediation actions required yet because no findings were recorded."

        high_priority = [finding for finding in findings if (finding.severity or "").lower() in {"critical", "high"}]
        exploit_attempts = sum(result.get("attempts", 0) for result in exploit_results)
        if not high_priority:
            return "Review recorded findings and validate impact before remediation planning."

        return (
            f"Prioritize remediation for {len(high_priority)} high-severity findings. "
            f"Controlled exploit attempts recorded: {exploit_attempts}. "
            "Start with externally reachable services, weak TLS posture, exposed admin surfaces, and known-CVE exposure."
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

    def _filter_modules_by_phase(self, available_modules: dict, selected_order: list[str], phase: str) -> dict:
        return {
            name: available_modules[name]
            for name in selected_order
            if name in available_modules and getattr(available_modules[name], "phase", "recon") == phase
        }

    def _allow_exploits(self) -> bool:
        config, _ = _load_config()
        return config.getboolean("security", "allow_exploits", fallback=False)

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


async def run_agentic_loop(session_id: int, target: str, scope_path: str | None = None, resume_mode: bool = False) -> dict:
    loop = AgenticLoop(session_id=session_id, target=target, scope_path=scope_path, resume_mode=resume_mode)
    return await loop.run()


def run_agentic_loop_sync(session_id: int, target: str, scope_path: str | None = None, resume_mode: bool = False) -> dict:
    return asyncio.run(run_agentic_loop(session_id=session_id, target=target, scope_path=scope_path, resume_mode=resume_mode))
