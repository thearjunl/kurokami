import enum
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base declarative class for KUROKAMI ORM models."""


class ReasoningStage(enum.Enum):
    RECON = "RECON"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    EXPLOIT_PRIORITY = "EXPLOIT_PRIORITY"
    REMEDIATION = "REMEDIATION"


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    end_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    risk_level: Mapped[str | None] = mapped_column(String(50), nullable=True)

    targets: Mapped[list["Target"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
    )
    ai_reasoning_chains: Mapped[list["AIReasoningChain"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
    )
    exports: Mapped[list["Export"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    open_ports: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    tech_stack: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)

    session: Mapped["Session"] = relationship(back_populates="targets")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False, index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True, index=True)
    vuln_name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    session: Mapped["Session"] = relationship(back_populates="findings")
    target: Mapped["Target | None"] = relationship(back_populates="findings")
    exploits: Mapped[list["Exploit"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


class Exploit(Base):
    __tablename__ = "exploits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="exploits")


class AIReasoningChain(Base):
    __tablename__ = "ai_reasoning_chains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False, index=True)
    stage: Mapped[ReasoningStage] = mapped_column(Enum(ReasoningStage), nullable=False)
    input_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_used: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    session: Mapped["Session"] = relationship(back_populates="ai_reasoning_chains")


class Export(Base):
    __tablename__ = "exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    filepath: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    session: Mapped["Session"] = relationship(back_populates="exports")
