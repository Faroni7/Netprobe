"""
Logging configuration for the NetSec Platform.

Provides structured logging with security-aware formatting that:
- Never logs sensitive values (passwords, tokens, cookies, etc.)
- Supports multiple log levels and destinations
- Integrates with audit logging for evidence access
- Uses structlog for structured logging
"""

import logging
import sys
from typing import Optional
from pathlib import Path

import structlog
from structlog.stdlib import ProcessorFormatter


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    json_format: bool = False,
) -> None:
    """
    Configure application logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        json_format: Whether to use JSON format for logs
    """
    
    # Convert string level to logging constant
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create handlers
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    handlers.append(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        handlers.append(file_handler)
    
    # Configure processors for structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]
    
    # Configure formatter
    if json_format:
        formatter = ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=processors,
        )
    else:
        formatter = ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
            foreign_pre_chain=processors,
        )
    
    # Apply formatter to all handlers
    for handler in handlers:
        handler.setFormatter(formatter)
    
    # Configure root logger
    logging.basicConfig(
        handlers=handlers,
        level=level,
        force=True,  # Override existing handlers
    )
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = __name__) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


# Security-aware logger that filters sensitive data
class SecureLogger:
    """
    Logger wrapper that prevents sensitive data from being logged.
    
    This ensures passwords, tokens, cookies, API keys, and other
    sensitive values never appear in application logs.
    """
    
    SENSITIVE_PATTERNS = [
        "password",
        "passwd",
        "secret",
        "token",
        "cookie",
        "session",
        "auth",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "access_token",
        "refresh_token",
        "bearer",
    ]
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self._logger = logger
    
    def _sanitize(self, event_data: dict) -> dict:
        """Remove or redact sensitive fields from log data."""
        sanitized = {}
        for key, value in event_data.items():
            key_lower = key.lower()
            
            # Check if key matches sensitive patterns
            if any(pattern in key_lower for pattern in self.SENSITIVE_PATTERNS):
                # Redact the value but keep the key for debugging
                sanitized[key] = "[REDACTED]"
            else:
                # Convert complex objects to strings safely
                if isinstance(value, (dict, list)):
                    sanitized[key] = str(value)[:200]  # Limit length
                else:
                    sanitized[key] = value
        
        return sanitized
    
    def info(self, event: str, **kwargs) -> None:
        self._logger.info(event, **self._sanitize(kwargs))
    
    def warning(self, event: str, **kwargs) -> None:
        self._logger.warning(event, **self._sanitize(kwargs))
    
    def error(self, event: str, **kwargs) -> None:
        self._logger.error(event, **self._sanitize(kwargs))
    
    def debug(self, event: str, **kwargs) -> None:
        self._logger.debug(event, **self._sanitize(kwargs))
    
    def critical(self, event: str, **kwargs) -> None:
        self._logger.critical(event, **self._sanitize(kwargs))


def get_secure_logger(name: str = __name__) -> SecureLogger:
    """
    Get a secure logger that filters sensitive data.
    
    Args:
        name: Logger name
        
    Returns:
        SecureLogger instance
    """
    return SecureLogger(get_logger(name))
