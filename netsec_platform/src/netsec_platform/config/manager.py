"""
Configuration Manager for NetSec Platform

Handles:
- Loading configuration from multiple sources
- Atomic updates with validation
- Runtime reload capabilities
- Audit logging integration
- Secret management
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import hashlib

from .schema import ConfigurationSchema, get_config_metadata


class ConfigurationError(Exception):
    """Configuration-related errors"""
    pass


class ConfigurationSecurityError(ConfigurationError):
    """Security-related configuration errors"""
    pass


class ConfigurationManager:
    """
    Manages application configuration with atomic updates and audit trails.
    
    Configuration precedence (highest to lowest):
    1. Runtime updates (via API)
    2. Environment variables
    3. Configuration file
    4. Built-in defaults
    """
    
    def __init__(self, config_path: str = "config/netsec.config.yaml"):
        self.config_path = Path(config_path)
        self._config: Optional[ConfigurationSchema] = None
        self._runtime_overrides: Dict[str, Any] = {}
        self._last_modified: Optional[datetime] = None
        self._last_modified_by: Optional[str] = None
        self._audit_callback = None
        
    def set_audit_callback(self, callback):
        """Set callback for audit logging"""
        self._audit_callback = callback
        
    def load(self) -> ConfigurationSchema:
        """
        Load configuration from all sources according to precedence.
        
        Returns:
            Complete validated configuration schema
        """
        # Start with defaults from Pydantic models
        config_dict = {}
        
        # Load from file if exists
        if self.config_path.exists():
            file_config = self._load_file()
            config_dict.update(file_config)
            
        # Override with environment variables
        env_config = self._load_environment()
        config_dict.update(env_config)
        
        # Override with runtime updates
        config_dict.update(self._runtime_overrides)
        
        # Validate and create schema
        try:
            self._config = ConfigurationSchema(**config_dict)
            return self._config
        except Exception as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")
    
    def _load_file(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                content = yaml.safe_load(f)
                if content is None:
                    return {}
                return content
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except FileNotFoundError:
            return {}
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file: {e}")
    
    def _load_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_mapping = {
            'NETSEC_APP_ENV': ('app', 'environment'),
            'NETSEC_APP_HOST': ('app', 'host'),
            'NETSEC_APP_PORT': ('app', 'port'),
            'NETSEC_LOG_LEVEL': ('app', 'log_level'),
            'NETSEC_DEBUG': ('app', 'debug_mode'),
            'NETSEC_CAPTURE_ENABLED': ('capture', 'enabled'),
            'NETSEC_CAPTURE_PROFILE': ('capture', 'profile'),
            'NETSEC_EVIDENCE_ENCRYPT': ('evidence', 'encryption_enabled'),
            'NETSEC_EVIDENCE_KEY': ('evidence', 'encryption_key'),
            'NETSEC_AUTH_SESSION_TIMEOUT': ('auth', 'session_timeout_minutes'),
            'NETSEC_AUDIT_ENABLED': ('audit', 'enabled'),
            'NETSEC_TESTING_ENABLED': ('testing', 'enabled'),
            'NETSEC_ESS_ENABLED': ('ess', 'enabled'),
        }
        
        env_config = {}
        
        for env_var, (section, key) in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                if section not in env_config:
                    env_config[section] = {}
                
                # Type conversion for known types
                if key in ['enabled', 'debug_mode', 'encryption_enabled']:
                    env_config[section][key] = value.lower() in ['true', '1', 'yes']
                elif key in ['port', 'session_timeout_minutes']:
                    env_config[section][key] = int(value)
                else:
                    env_config[section][key] = value
                    
        return env_config
    
    def get_effective_config(self, redact_secrets: bool = True) -> Dict[str, Any]:
        """
        Get effective configuration with optional secret redaction.
        
        Args:
            redact_secrets: If True, replace sensitive values with metadata
            
        Returns:
            Dictionary of effective configuration values
        """
        if self._config is None:
            self.load()
            
        config_dict = self._config.dict()
        
        if redact_secrets:
            self._redact_secrets(config_dict)
            
        # Add source information
        return self._add_source_metadata(config_dict)
    
    def _redact_secrets(self, config_dict: Dict[str, Any]):
        """Redact sensitive configuration values"""
        sensitive_paths = [
            ('evidence', 'encryption_key'),
            ('auth', 'jwt_secret'),
        ]
        
        for section, key in sensitive_paths:
            if section in config_dict and key in config_dict[section]:
                if config_dict[section][key] is not None:
                    config_dict[section][key] = {
                        '_configured': True,
                        '_value': '<REDACTED>',
                        '_type': 'secret'
                    }
    
    def _add_source_metadata(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Add source information to each configuration value"""
        # This would track whether each value came from file, env, or runtime
        # For now, simplified implementation
        config_dict['_metadata'] = {
            'last_modified': self._last_modified.isoformat() if self._last_modified else None,
            'last_modified_by': self._last_modified_by,
            'config_file': str(self.config_path),
            'file_exists': self.config_path.exists()
        }
        return config_dict
    
    def update(self, path: str, value: Any, actor: str) -> Tuple[bool, str]:
        """
        Update a single configuration value atomically.
        
        Args:
            path: Dot-notation path (e.g., "app.log_level")
            value: New value
            actor: User performing the change
            
        Returns:
            Tuple of (success, message)
        """
        # Check if setting is locked
        metadata = get_config_metadata(path)
        if metadata.get('locked'):
            return False, f"Setting '{path}' is locked and cannot be modified"
        
        # Validate value against schema
        if not self._validate_update(path, value):
            return False, f"Invalid value for '{path}'"
        
        # Store runtime override
        self._runtime_overrides[path] = value
        self._last_modified = datetime.utcnow()
        self._last_modified_by = actor
        
        # Audit log
        if self._audit_callback:
            self._audit_callback(
                action="CONFIG_UPDATE",
                actor=actor,
                path=path,
                old_value=self._get_current_value(path),
                new_value=value,
                restart_required=metadata.get('restart_required', False)
            )
        
        return True, "Configuration updated successfully"
    
    def _validate_update(self, path: str, value: Any) -> bool:
        """Validate a configuration update"""
        # Simplified validation - in production would validate against schema
        parts = path.split('.')
        if len(parts) != 2:
            return False
            
        section, key = parts
        
        # Check for sensitive settings that require special handling
        if key in ['encryption_key', 'jwt_secret']:
            if not isinstance(value, str) or len(value) < 32:
                return False
                
        return True
    
    def _get_current_value(self, path: str) -> Any:
        """Get current value for a configuration path"""
        if self._config is None:
            return None
            
        parts = path.split('.')
        if len(parts) != 2:
            return None
            
        section, key = parts
        try:
            return getattr(getattr(self._config, section), key)
        except AttributeError:
            return None
    
    def save_to_file(self, actor: str) -> Tuple[bool, str]:
        """
        Persist current configuration to file.
        
        Args:
            actor: User performing the save
            
        Returns:
            Tuple of (success, message)
        """
        if self._config is None:
            return False, "No configuration loaded"
        
        try:
            # Create directory if needed
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Merge runtime overrides into config
            config_dict = self._config.dict()
            
            # Write atomically using temp file
            temp_path = self.config_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            
            # Atomic rename
            temp_path.rename(self.config_path)
            
            self._last_modified = datetime.utcnow()
            self._last_modified_by = actor
            
            # Audit log
            if self._audit_callback:
                self._audit_callback(
                    action="CONFIG_SAVE",
                    actor=actor,
                    path=str(self.config_path)
                )
            
            return True, "Configuration saved successfully"
            
        except Exception as e:
            return False, f"Failed to save configuration: {e}"
    
    def validate_config(self, config_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate configuration without applying it.
        
        Args:
            config_dict: Configuration dictionary to validate
            
        Returns:
            Tuple of (valid, error_message)
        """
        try:
            ConfigurationSchema(**config_dict)
            return True, "Configuration is valid"
        except Exception as e:
            return False, f"Validation error: {e}"
    
    def requires_restart(self, path: str) -> bool:
        """Check if a configuration change requires restart"""
        metadata = get_config_metadata(path)
        return metadata.get('restart_required', False)
    
    def can_reload_runtime(self, path: str) -> bool:
        """Check if a configuration change can be applied at runtime"""
        metadata = get_config_metadata(path)
        return metadata.get('runtime_reload', False)
    
    def get_configuration_hash(self) -> str:
        """Get hash of current configuration for version tracking"""
        if self._config is None:
            self.load()
            
        config_str = str(self._config.dict())
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]


# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None


def get_config_manager() -> ConfigurationManager:
    """Get or create global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    return _config_manager


def reload_config() -> ConfigurationSchema:
    """Reload configuration from all sources"""
    manager = get_config_manager()
    return manager.load()
