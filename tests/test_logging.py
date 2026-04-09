"""Tests for logging configuration."""
import json
import logging
from pathlib import Path

import pytest

from core.logging_config import JSONFormatter, AuditLogger, setup_logging, get_logger


class TestJSONFormatter:
    """Test JSON formatter."""

    def test_basic_formatting(self):
        """Test basic log formatting."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["message"] == "Test message"
        assert data["line"] == 10
        assert "timestamp" in data

    def test_extra_fields(self):
        """Test extra fields in log record."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.session_id = 123
        record.target = "example.com"
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert data["session_id"] == 123
        assert data["target"] == "example.com"


class TestAuditLogger:
    """Test audit logger."""

    def test_log_scan_started(self, tmp_path):
        """Test logging scan start."""
        audit = AuditLogger(tmp_path)
        audit.log_scan_started(session_id=1, target="example.com", user_id="test_user")
        
        audit_file = tmp_path / "audit.log"
        assert audit_file.exists()
        
        content = audit_file.read_text()
        data = json.loads(content)
        
        assert data["event_type"] == "scan_started"
        assert data["session_id"] == 1
        assert data["target"] == "example.com"
        assert data["user_id"] == "test_user"

    def test_log_exploit_attempted(self, tmp_path):
        """Test logging exploit attempt."""
        audit = AuditLogger(tmp_path)
        audit.log_exploit_attempted(
            session_id=1,
            finding_id=5,
            module_name="k_http_trace",
            allowed=False,
            user_id="test_user"
        )
        
        audit_file = tmp_path / "audit.log"
        content = audit_file.read_text()
        data = json.loads(content)
        
        assert data["event_type"] == "exploit_attempted"
        assert data["finding_id"] == 5
        assert data["allowed"] is False

    def test_log_validation_failure(self, tmp_path):
        """Test logging validation failure."""
        audit = AuditLogger(tmp_path)
        audit.log_validation_failure(
            input_type="target",
            input_value="malicious; rm -rf /",
            reason="Contains forbidden characters",
            user_id="attacker"
        )
        
        audit_file = tmp_path / "audit.log"
        content = audit_file.read_text()
        data = json.loads(content)
        
        assert data["event_type"] == "validation_failure"
        assert data["input_type"] == "target"
        assert "malicious" in data["input_value"]


class TestSetupLogging:
    """Test logging setup."""

    def test_setup_with_json(self, tmp_path):
        """Test setup with JSON formatting."""
        logger, audit = setup_logging(tmp_path, log_level="INFO", enable_json=True)
        
        assert logger.name == "kurokami"
        assert logger.level == logging.INFO
        assert (tmp_path / "kurokami.log").exists()
        assert (tmp_path / "error.log").exists()
        assert (tmp_path / "audit.log").exists()

    def test_setup_without_json(self, tmp_path):
        """Test setup without JSON formatting."""
        logger, audit = setup_logging(tmp_path, log_level="DEBUG", enable_json=False)
        
        assert logger.level == logging.DEBUG

    def test_get_logger(self, tmp_path):
        """Test getting module logger."""
        setup_logging(tmp_path)
        logger = get_logger("test_module")
        
        assert logger.name == "kurokami.test_module"
