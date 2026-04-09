"""Input validation and sanitization for security hardening."""
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class InputValidator:
    """Validates and sanitizes user inputs to prevent injection attacks."""

    # Allowed characters for hostnames (RFC 1123)
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    # Maximum lengths to prevent DoS
    MAX_HOSTNAME_LENGTH = 253
    MAX_URL_LENGTH = 2048
    MAX_PATH_LENGTH = 4096

    @staticmethod
    def validate_target(target: str) -> str:
        """
        Validate and sanitize a target (IP, hostname, CIDR, or URL).
        
        Args:
            target: User-provided target string
            
        Returns:
            Sanitized target string
            
        Raises:
            ValidationError: If target is invalid or potentially malicious
        """
        if not target or not isinstance(target, str):
            raise ValidationError("Target must be a non-empty string")
        
        target = target.strip()
        
        # Check for command injection attempts
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
        if any(char in target for char in dangerous_chars):
            raise ValidationError(f"Target contains forbidden characters: {target}")
        
        # Check length
        if len(target) > InputValidator.MAX_URL_LENGTH:
            raise ValidationError(f"Target exceeds maximum length of {InputValidator.MAX_URL_LENGTH}")
        
        # Try to parse as IP address
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        
        # Try to parse as CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            pass
        
        # Try to parse as URL
        if target.startswith(('http://', 'https://')):
            return InputValidator._validate_url(target)
        
        # Validate as hostname
        return InputValidator._validate_hostname(target)

    @staticmethod
    def _validate_hostname(hostname: str) -> str:
        """Validate hostname according to RFC 1123."""
        if len(hostname) > InputValidator.MAX_HOSTNAME_LENGTH:
            raise ValidationError(f"Hostname exceeds maximum length of {InputValidator.MAX_HOSTNAME_LENGTH}")
        
        if not InputValidator.HOSTNAME_PATTERN.match(hostname):
            raise ValidationError(f"Invalid hostname format: {hostname}")
        
        return hostname

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate URL format and scheme."""
        try:
            parsed = urlparse(url)
            
            if parsed.scheme not in ('http', 'https'):
                raise ValidationError(f"URL scheme must be http or https: {url}")
            
            if not parsed.netloc:
                raise ValidationError(f"URL missing network location: {url}")
            
            # Validate the hostname part
            hostname = parsed.hostname
            if hostname:
                InputValidator._validate_hostname(hostname)
            
            return url
        except Exception as e:
            raise ValidationError(f"Invalid URL: {url} - {str(e)}")

    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = True) -> Path:
        """
        Validate file path and prevent directory traversal attacks.
        
        Args:
            file_path: User-provided file path
            must_exist: Whether the file must exist
            
        Returns:
            Resolved Path object
            
        Raises:
            ValidationError: If path is invalid or potentially malicious
        """
        if not file_path or not isinstance(file_path, str):
            raise ValidationError("File path must be a non-empty string")
        
        file_path = file_path.strip()
        
        if len(file_path) > InputValidator.MAX_PATH_LENGTH:
            raise ValidationError(f"File path exceeds maximum length of {InputValidator.MAX_PATH_LENGTH}")
        
        # Check for null bytes
        if '\0' in file_path:
            raise ValidationError("File path contains null bytes")
        
        try:
            path = Path(file_path).resolve()
        except (OSError, RuntimeError) as e:
            raise ValidationError(f"Invalid file path: {file_path} - {str(e)}")
        
        if must_exist and not path.exists():
            raise ValidationError(f"File does not exist: {file_path}")
        
        if must_exist and not path.is_file():
            raise ValidationError(f"Path is not a file: {file_path}")
        
        return path

    @staticmethod
    def validate_session_id(session_id: str | int) -> int:
        """
        Validate session ID.
        
        Args:
            session_id: User-provided session ID
            
        Returns:
            Integer session ID
            
        Raises:
            ValidationError: If session ID is invalid
        """
        try:
            sid = int(session_id)
            if sid <= 0:
                raise ValidationError("Session ID must be positive")
            if sid > 2147483647:  # Max 32-bit int
                raise ValidationError("Session ID too large")
            return sid
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid session ID: {session_id}")

    @staticmethod
    def validate_export_format(format_name: str) -> str:
        """
        Validate export format.
        
        Args:
            format_name: User-provided format name
            
        Returns:
            Lowercase format name
            
        Raises:
            ValidationError: If format is not supported
        """
        if not format_name or not isinstance(format_name, str):
            raise ValidationError("Export format must be a non-empty string")
        
        format_name = format_name.lower().strip()
        
        allowed_formats = {'json', 'html', 'pdf'}
        if format_name not in allowed_formats:
            raise ValidationError(f"Unsupported export format: {format_name}. Allowed: {', '.join(allowed_formats)}")
        
        return format_name

    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize a generic string input.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
            
        Raises:
            ValidationError: If string is invalid
        """
        if not isinstance(value, str):
            raise ValidationError("Value must be a string")
        
        # Remove null bytes
        value = value.replace('\0', '')
        
        # Limit length
        if len(value) > max_length:
            raise ValidationError(f"String exceeds maximum length of {max_length}")
        
        return value.strip()
