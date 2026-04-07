import configparser
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .db import Base


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "kurokami.db"
DEFAULT_VECTOR_STORE_DIR = PROJECT_ROOT / "data" / "vector_store"

_engine = None
_SessionLocal = None


def _load_config() -> tuple[configparser.ConfigParser, Path | None]:
    config = configparser.ConfigParser()
    candidate_paths = [
        PROJECT_ROOT / "kurokami.conf",
        Path.home() / ".config" / "kurokami" / "kurokami.conf",
        Path("/etc/kurokami/kurokami.conf"),
    ]

    for path in candidate_paths:
        if path.exists():
            config.read(path)
            return config, path

    return config, None


def resolve_config_path(section: str, option: str, fallback: str | Path) -> Path:
    config, config_path = _load_config()
    configured_path = config.get(section, option, fallback=str(fallback))
    db_path = Path(configured_path).expanduser()

    if db_path.is_absolute():
        return db_path

    base_dir = config_path.parent if config_path else PROJECT_ROOT
    return (base_dir / db_path).resolve()


def resolve_db_path() -> Path:
    return resolve_config_path("database", "db_path", DEFAULT_DB_PATH)


def resolve_vector_store_dir() -> Path:
    return resolve_config_path("paths", "vector_store_dir", DEFAULT_VECTOR_STORE_DIR)


def get_engine():
    global _engine

    if _engine is None:
        db_path = resolve_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{db_path}", future=True)

    return _engine


def _get_session_factory():
    global _SessionLocal

    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            class_=Session,
        )

    return _SessionLocal


def init_db() -> None:
    """Create all database tables configured for KUROKAMI."""
    Base.metadata.create_all(bind=get_engine())


@contextmanager
def get_session() -> Iterator[Session]:
    """Yield a SQLAlchemy session with automatic commit/rollback handling."""
    db = _get_session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
