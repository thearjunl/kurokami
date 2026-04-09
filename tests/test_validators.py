"""Tests for input validation and sanitization."""
import pytest
from pathlib import Path

from core.validators import InputValidator, ValidationError


class TestTargetValidation:
    """Test target validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 address."""
        result = InputValidator.validate_target("192.168.1.1")
        assert result == "192.168.1.1"

    def test_valid_ipv6(self):
        """Test valid IPv6 address."""
        result = InputValidator.validate_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        result = InputValidator.validate_target("192.168.1.0/24")
        assert result == "192.168.1.0/24"

    def test_valid_hostname(self):
        """Test valid hostname."""
        result = InputValidator.validate_target("example.com")
        assert result == "example.com"

    def test_valid_subdomain(self):
        """Test valid subdomain."""
        result = InputValidator.validate_target("api.example.com")
        assert result == "api.example.com"

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        result = InputValidator.validate_target("http://example.com")
        assert result == "http://example.com"

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        result = InputValidator.validate_target("https://example.com/path")
        assert result == "https://example.com/path"

    def test_empty_target(self):
        """Test empty target."""
        with pytest.raises(ValidationError, match="non-empty string"):
            InputValidator.validate_target("")

    def test_none_target(self):
        """Test None target."""
        with pytest.raises(ValidationError, match="non-empty string"):
            InputValidator.validate_target(None)

    def test_command_injection_semicolon(self):
        """Test command injection with semicolon."""
        with pytest.raises(ValidationError, match="forbidden characters"):
            InputValidator.validate_target("example.com; rm -rf /")

    def test_command_injection_pipe(self):
        """Test command injection with pipe."""
        with pytest.raises(ValidationError, match="forbidden characters"):
            InputValidator.validate_target("example.com | cat /etc/passwd")

    def test_command_injection_backtick(self):
        """Test command injection with backtick."""
        with pytest.raises(ValidationError, match="forbidden characters"):
            InputValidator.validate_target("example.com`whoami`")

    def test_command_injection_dollar(self):
        """Test command injection with dollar sign."""
        with pytest.raises(ValidationError, match="forbidden characters"):
            InputValidator.validate_target("example.com$(whoami)")

    def test_too_long_target(self):
        """Test target exceeding maximum length."""
        long_target = "a" * 3000
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            InputValidator.validate_target(long_target)

    def test_invalid_url_scheme(self):
        """Test invalid URL scheme."""
        with pytest.raises(ValidationError, match="scheme must be http or https"):
            InputValidator.validate_target("ftp://example.com")


class TestFilePathValidation:
    """Test file path validation."""

    def test_valid_relative_path(self, tmp_path):
        """Test valid relative path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        
        result = InputValidator.validate_file_path(str(test_file))
        assert result.exists()

    def test_nonexistent_file_must_exist(self):
        """Test nonexistent file when must_exist=True."""
        with pytest.raises(ValidationError, match="does not exist"):
            InputValidator.validate_file_path("/nonexistent/file.txt", must_exist=True)

    def test_nonexistent_file_optional(self):
        """Test nonexistent file when must_exist=False."""
        result = InputValidator.validate_file_path("/tmp/newfile.txt", must_exist=False)
        assert isinstance(result, Path)

    def test_null_byte_in_path(self):
        """Test null byte in path."""
        with pytest.raises(ValidationError, match="null bytes"):
            InputValidator.validate_file_path("/tmp/file\x00.txt", must_exist=False)

    def test_too_long_path(self):
        """Test path exceeding maximum length."""
        long_path = "a" * 5000
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            InputValidator.validate_file_path(long_path, must_exist=False)

    def test_empty_path(self):
        """Test empty path."""
        with pytest.raises(ValidationError, match="non-empty string"):
            InputValidator.validate_file_path("")


class TestSessionIdValidation:
    """Test session ID validation."""

    def test_valid_positive_int(self):
        """Test valid positive integer."""
        result = InputValidator.validate_session_id(42)
        assert result == 42

    def test_valid_string_number(self):
        """Test valid string number."""
        result = InputValidator.validate_session_id("123")
        assert result == 123

    def test_zero_session_id(self):
        """Test zero session ID."""
        with pytest.raises(ValidationError, match="must be positive"):
            InputValidator.validate_session_id(0)

    def test_negative_session_id(self):
        """Test negative session ID."""
        with pytest.raises(ValidationError, match="must be positive"):
            InputValidator.validate_session_id(-1)

    def test_too_large_session_id(self):
        """Test session ID exceeding max int."""
        with pytest.raises(ValidationError, match="too large"):
            InputValidator.validate_session_id(2147483648)

    def test_invalid_string(self):
        """Test invalid string."""
        with pytest.raises(ValidationError, match="Invalid session ID"):
            InputValidator.validate_session_id("abc")


class TestExportFormatValidation:
    """Test export format validation."""

    def test_valid_json(self):
        """Test valid JSON format."""
        result = InputValidator.validate_export_format("json")
        assert result == "json"

    def test_valid_html(self):
        """Test valid HTML format."""
        result = InputValidator.validate_export_format("html")
        assert result == "html"

    def test_valid_pdf(self):
        """Test valid PDF format."""
        result = InputValidator.validate_export_format("pdf")
        assert result == "pdf"

    def test_uppercase_format(self):
        """Test uppercase format."""
        result = InputValidator.validate_export_format("JSON")
        assert result == "json"

    def test_invalid_format(self):
        """Test invalid format."""
        with pytest.raises(ValidationError, match="Unsupported export format"):
            InputValidator.validate_export_format("xml")

    def test_empty_format(self):
        """Test empty format."""
        with pytest.raises(ValidationError, match="non-empty string"):
            InputValidator.validate_export_format("")


class TestStringSanitization:
    """Test string sanitization."""

    def test_normal_string(self):
        """Test normal string."""
        result = InputValidator.sanitize_string("  hello world  ")
        assert result == "hello world"

    def test_null_byte_removal(self):
        """Test null byte removal."""
        result = InputValidator.sanitize_string("hello\x00world")
        assert result == "helloworld"

    def test_too_long_string(self):
        """Test string exceeding max length."""
        long_string = "a" * 2000
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            InputValidator.sanitize_string(long_string, max_length=1000)

    def test_non_string_input(self):
        """Test non-string input."""
        with pytest.raises(ValidationError, match="must be a string"):
            InputValidator.sanitize_string(123)
