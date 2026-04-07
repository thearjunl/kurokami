from datetime import datetime

from .database import get_session
from .db import Checkpoint, Session


class CheckpointManager:
    """Persist and query session checkpoints for resumable execution."""

    def __init__(self, session_id: int):
        self.session_id = session_id

    def record(self, stage: str, state: str, module_name: str | None = None, payload: dict | list | None = None) -> None:
        with get_session() as db:
            db.add(
                Checkpoint(
                    session_id=self.session_id,
                    stage=stage,
                    module_name=module_name,
                    state=state,
                    payload=payload,
                )
            )
            session_record = db.get(Session, self.session_id)
            if session_record:
                session_record.current_stage = stage
                session_record.last_checkpoint = datetime.utcnow()

    def completed_modules(self, stage: str) -> set[str]:
        with get_session() as db:
            rows = (
                db.query(Checkpoint)
                .filter(
                    Checkpoint.session_id == self.session_id,
                    Checkpoint.stage == stage,
                    Checkpoint.state == "completed",
                    Checkpoint.module_name.isnot(None),
                )
                .all()
            )
        return {row.module_name for row in rows if row.module_name}

    def latest(self) -> Checkpoint | None:
        with get_session() as db:
            return (
                db.query(Checkpoint)
                .filter(Checkpoint.session_id == self.session_id)
                .order_by(Checkpoint.id.desc())
                .first()
            )
