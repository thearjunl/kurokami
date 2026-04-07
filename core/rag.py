import hashlib
import json
import math
import re
from pathlib import Path

from .database import get_session, resolve_vector_store_dir
from .db import AIReasoningChain, Finding, Session, Target


class SessionRAGStore:
    """Persist and query session knowledge with a FAISS index plus JSON metadata."""

    def __init__(self, session_id: int, embedding_dim: int = 128):
        self.session_id = session_id
        self.embedding_dim = embedding_dim
        self.base_dir = resolve_vector_store_dir() / f"session_{session_id}"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.base_dir / "index.faiss"
        self.metadata_path = self.base_dir / "metadata.json"

    def index_session(self) -> dict:
        documents = self._collect_documents()
        if not documents:
            self._write_metadata([])
            return {
                "status": "skipped",
                "documents_indexed": 0,
                "index_path": str(self.index_path),
                "reason": "No session documents available for indexing.",
            }

        try:
            import faiss
            import numpy as np
        except ModuleNotFoundError as exc:
            self._write_metadata(documents)
            return {
                "status": "skipped",
                "documents_indexed": len(documents),
                "index_path": str(self.index_path),
                "reason": f"Missing dependency: {exc.name}",
            }

        vectors = np.array(
            [self._embed_text(doc["text"]) for doc in documents],
            dtype="float32",
        )
        index = faiss.IndexFlatL2(self.embedding_dim)
        index.add(vectors)
        faiss.write_index(index, str(self.index_path))
        self._write_metadata(documents)

        return {
            "status": "completed",
            "documents_indexed": len(documents),
            "index_path": str(self.index_path),
            "metadata_path": str(self.metadata_path),
        }

    def retrieve(self, query: str, limit: int = 5) -> list[dict]:
        documents = self._read_metadata()
        if not documents:
            return []

        try:
            import faiss
            import numpy as np
        except ModuleNotFoundError:
            ranked = sorted(
                documents,
                key=lambda doc: self._text_overlap_score(query, doc["text"]),
                reverse=True,
            )
            return ranked[:limit]

        if not self.index_path.exists():
            ranked = sorted(
                documents,
                key=lambda doc: self._text_overlap_score(query, doc["text"]),
                reverse=True,
            )
            return ranked[:limit]

        index = faiss.read_index(str(self.index_path))
        query_vector = np.array([self._embed_text(query)], dtype="float32")
        _, indices = index.search(query_vector, min(limit, len(documents)))
        return [documents[idx] for idx in indices[0] if 0 <= idx < len(documents)]

    def _collect_documents(self) -> list[dict]:
        with get_session() as db:
            session_record = db.get(Session, self.session_id)
            targets = (
                db.query(Target)
                .filter(Target.session_id == self.session_id)
                .order_by(Target.id.asc())
                .all()
            )
            findings = (
                db.query(Finding)
                .filter(Finding.session_id == self.session_id)
                .order_by(Finding.id.asc())
                .all()
            )
            reasoning = (
                db.query(AIReasoningChain)
                .filter(AIReasoningChain.session_id == self.session_id)
                .order_by(AIReasoningChain.id.asc())
                .all()
            )

        documents = []
        if session_record:
            documents.append(
                {
                    "kind": "session",
                    "id": session_record.id,
                    "text": (
                        f"Session {session_record.id} target {session_record.target} "
                        f"status {session_record.status} risk {session_record.risk_level or 'unknown'}"
                    ),
                }
            )

        for target in targets:
            documents.append(
                {
                    "kind": "target",
                    "id": target.id,
                    "text": (
                        f"Target host {target.host} ip {target.ip or 'unknown'} "
                        f"open_ports {json.dumps(target.open_ports or [])} "
                        f"tech_stack {json.dumps(target.tech_stack or [])}"
                    ),
                }
            )

        for finding in findings:
            documents.append(
                {
                    "kind": "finding",
                    "id": finding.id,
                    "text": (
                        f"Finding {finding.vuln_name} severity {finding.severity} "
                        f"confidence {finding.confidence} cve {finding.cve_id or 'none'} "
                        f"description {finding.description or ''}"
                    ),
                }
            )

        for chain in reasoning:
            documents.append(
                {
                    "kind": "reasoning",
                    "id": chain.id,
                    "text": (
                        f"Reasoning stage {chain.stage.value} input {chain.input_context or ''} "
                        f"output {chain.output or ''}"
                    ),
                }
            )

        return documents

    def _embed_text(self, text: str) -> list[float]:
        vector = [0.0] * self.embedding_dim
        tokens = re.findall(r"[a-zA-Z0-9_./:-]+", text.lower())
        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.embedding_dim
            weight = 1.0 + (digest[4] / 255.0)
            vector[bucket] += weight

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0:
            return vector
        return [value / norm for value in vector]

    def _text_overlap_score(self, query: str, text: str) -> int:
        query_tokens = set(re.findall(r"[a-zA-Z0-9_./:-]+", query.lower()))
        text_tokens = set(re.findall(r"[a-zA-Z0-9_./:-]+", text.lower()))
        return len(query_tokens & text_tokens)

    def _write_metadata(self, documents: list[dict]) -> None:
        payload = {
            "session_id": self.session_id,
            "embedding_dim": self.embedding_dim,
            "documents": documents,
        }
        self.metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _read_metadata(self) -> list[dict]:
        if not self.metadata_path.exists():
            return []
        payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        return payload.get("documents", [])
