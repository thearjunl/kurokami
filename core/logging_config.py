"""Structured logging configuration for production environments."""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "session_id"):
            log_data["session_id"] = record.session_id
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if hasattr(record, "module_name"):
            log_data["module_name"] = record.module_name
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id

        return json.dumps(log_data)


class AuditLogger:
    """Specialized logger for audit trail of security-relevant events."""

    def __init__(self, log_dir: Path):
        """Initialize audit logger."""
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger("kurokami.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        
        # Audit logs go to a separate file
        audit_file = self.log_dir / "audit.log"
        file_handler = logging.FileHandler(audit_file)
        file_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(file_handler)

    def log_scan_started(self, session_id: int, target: str, user_id: str = "system"):
        """Log scan initiation."""
        self.logger.info(
            "Scan started",
            extra={
                "event_type": "scan_started",
                "session_id": session_id,
                "target": target,
                "user_id": user_id,
            },
        )

    def log_scan_completed(self, session_id: int, target: str, risk_level: str, user_id: str = "system"):
        """Log scan completion."""
        self.logger.info(
            "Scan completed",
            extra={
                "event_type": "scan_completed",
                "session_id": session_id,
                "target": target,
                "risk_level": risk_level,
                "user_id": user_id,
            },
        )

    def log_exploit_attempted(self, session_id: int, finding_id: int, module_name: str, allowed: bool, user_id: str = "system"):
        """Log exploit attempt."""
        self.logger.warning(
            "Exploit attempted",
            extra={
                "event_type": "exploit_attempted",
                "session_id": session_id,
                "finding_id": finding_id,
                "module_name": module_name,
                "allowed": allowed,
                "user_id": user_id,
            },
        )

    def log_export_generated(self, session_id: int, format_name: str, file_path: str, user_id: str = "system"):
        """Log report export."""
        self.logger.info(
            "Export generated",
            extra={
                "event_type": "export_generated",
                "session_id": session_id,
                "format": format_name,
                "file_path": file_path,
                "user_id": user_id,
            },
        )

    def log_validation_failure(self, input_type: str, input_value: str, reason: str, user_id: str = "system"):
        """Log input validation failure (potential attack)."""
        self.logger.warning(
            "Input validation failed",
            extra={
                "event_type": "validation_failure",
                "input_type": input_type,
                "input_value": input_value[:100],  # Truncate for safety
                "reason": reason,
                "user_id": user_id,
            },
        )

    def log_authentication_failure(self, user_id: str, reason: str):
        """Log authentication failure."""
        self.logger.warning(
            "Authentication failed",
            extra={
                "event_type": "authentication_failure",
                "user_id": user_id,
                "reason": reason,
            },
        )

    def log_configuration_change(self, setting: str, old_value: Any, new_value: Any, user_id: str = "system"):
        """Log configuration changes."""
        self.logger.info(
            "Configuration changed",
            extra={
                "event_type": "configuration_change",
                "setting": setting,
                "old_value": str(old_value),
                "new_value": str(new_value),
                "user_id": user_id,
            },
        )


def setup_logging(log_dir: Path, log_level: str = "INFO", enable_json: bool = True) -> tuple[logging.Logger, AuditLogger]:
    """
    Configure application-wide logging.
    
    Args:
        log_dir: Directory for log files
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        enable_json: Whether to use JSON formatting
        
    Returns:
        Tuple of (main logger, audit logger)
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger("kurokami")
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root_logger.propagate = False
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    if enable_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    
    root_logger.addHandler(console_handler)
    
    # File handler for all logs
    app_log_file = log_dir / "kurokami.log"
    file_handler = logging.FileHandler(app_log_file)
    file_handler.setLevel(logging.DEBUG)
    
    if enable_json:
        file_handler.setFormatter(JSONFormatter())
    else:
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    
    root_logger.addHandler(file_handler)
    
    # Error log file
    error_log_file = log_dir / "error.log"
    error_handler = logging.FileHandler(error_log_file)
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter() if enable_json else logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s\n%(exc_info)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    
    root_logger.addHandler(error_handler)
    
    # Create audit logger
    audit_logger = AuditLogger(log_dir)
    
    root_logger.info("Logging system initialized", extra={"log_dir": str(log_dir), "log_level": log_level})
    
    return root_logger, audit_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module."""
    return logging.getLogger(f"kurokami.{name}")
