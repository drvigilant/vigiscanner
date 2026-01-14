# ============================================================
# FILE 2: config.py
# Configuration management module
# ============================================================

import os
from pathlib import Path
from typing import List, Set
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class ScannerConfig:
    """
    Centralized configuration management
    
    Features:
    - Environment-based configuration
    - Default values with overrides
    - Type validation
    - Configuration validation
    """
    
    # Scanner Settings
    MAX_FILES: int = int(os.getenv('SCAN_MAX_FILES', '1000'))
    MAX_FILE_SIZE_MB: int = int(os.getenv('SCAN_MAX_FILE_SIZE_MB', '10'))
    TIMEOUT_SECONDS: int = int(os.getenv('SCAN_TIMEOUT_SECONDS', '300'))
    
    # Exclusion Patterns
    EXCLUDED_DIRS: Set[str] = set(
        os.getenv('EXCLUDED_DIRS', '.git,node_modules,venv,__pycache__,.venv,env,dist,build').split(',')
    )
    
    EXCLUDED_EXTENSIONS: Set[str] = set(
        os.getenv('EXCLUDED_EXTENSIONS', '.pyc,.git,.png,.jpg,.jpeg,.gif,.pdf,.zip,.exe').split(',')
    )
    
    # Logging Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'scanner.log')
    
    # API Validation
    VALIDATE_ENDPOINTS: bool = os.getenv('VALIDATE_ENDPOINTS', 'false').lower() == 'true'
    API_TIMEOUT: int = int(os.getenv('API_TIMEOUT_SECONDS', '5'))
    
    # Export Settings
    EXPORT_FORMAT: str = os.getenv('EXPORT_FORMAT', 'json')
    EXPORT_DIR: Path = Path(os.getenv('EXPORT_DIR', './reports'))
    
    # Alerting
    SLACK_WEBHOOK_URL: str = os.getenv('SLACK_WEBHOOK_URL', '')
    ALERT_ON_CRITICAL: bool = os.getenv('ALERT_ON_CRITICAL', 'true').lower() == 'true'
    ALERT_ON_HIGH: bool = os.getenv('ALERT_ON_HIGH', 'false').lower() == 'true'
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate configuration settings
        
        Returns:
            bool: True if configuration is valid
        
        Raises:
            ValueError: If configuration is invalid
        """
        # Validate max files
        if cls.MAX_FILES < 1:
            raise ValueError("MAX_FILES must be at least 1")
        
        # Validate timeout
        if cls.TIMEOUT_SECONDS < 10:
            raise ValueError("TIMEOUT_SECONDS must be at least 10")
        
        # Create export directory if it doesn't exist
        cls.EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        
        return True
    
    @classmethod
    def get_safe_config(cls) -> dict:
        """
        Get configuration without sensitive values
        
        Returns:
            dict: Safe configuration for logging/display
        """
        return {
            'max_files': cls.MAX_FILES,
            'max_file_size_mb': cls.MAX_FILE_SIZE_MB,
            'timeout_seconds': cls.TIMEOUT_SECONDS,
            'excluded_dirs': list(cls.EXCLUDED_DIRS),
            'excluded_extensions': list(cls.EXCLUDED_EXTENSIONS),
            'log_level': cls.LOG_LEVEL,
            'export_format': cls.EXPORT_FORMAT,
            'validate_endpoints': cls.VALIDATE_ENDPOINTS,
            'alerting_enabled': bool(cls.SLACK_WEBHOOK_URL)
        }


class SecurityPatterns:
    """
    Additional security patterns that can be customized
    """
    
    # High-value file patterns to prioritize
    HIGH_VALUE_FILES = [
        '.env',
        'config.py',
        'settings.py',
        'secrets.json',
        'credentials.json',
        '.aws/credentials',
        '.gcp/credentials.json'
    ]
    
    # API endpoint patterns to validate
    API_ENDPOINTS = [
        'api.openai.com',
        'api.anthropic.com',
        'bedrock.amazonaws.com',
        'api.cohere.ai',
        'api.ai21.com',
        'generativelanguage.googleapis.com'
    ]
    
    # Safe file patterns (never scan these)
    SAFE_EXTENSIONS = {
        '.md', '.txt', '.rst',  # Documentation
        '.lock', '.sum',  # Lock files
        '.toml', '.yaml', '.yml'  # Config (but still scan for secrets)
    }


# Validate configuration on import
try:
    ScannerConfig.validate()
except ValueError as e:
    print(f"Configuration Error: {e}")
    print("Please check your .env file or environment variables")


# Usage example in scanner:
"""
from config import ScannerConfig

scanner = AISecurityScanner()
scanner.excluded_dirs = ScannerConfig.EXCLUDED_DIRS
scanner.excluded_extensions = ScannerConfig.EXCLUDED_EXTENSIONS
findings = scanner.scan_directory(".", max_files=ScannerConfig.MAX_FILES)
"""
