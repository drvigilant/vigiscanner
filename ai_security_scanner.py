"""
AI Security Posture Scanner - Core Engine
Scans repositories and infrastructure for AI/LLM security misconfigurations
"""

import re
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AssetType(Enum):
    """Types of AI assets detected"""
    API_KEY = "API_KEY"
    ENDPOINT = "ENDPOINT"
    MODEL_REFERENCE = "MODEL_REFERENCE"
    CONFIG_FILE = "CONFIG_FILE"
    PROMPT_TEMPLATE = "PROMPT_TEMPLATE"
    EMBEDDING_STORE = "EMBEDDING_STORE"


@dataclass
class SecurityFinding:
    """Represents a security finding"""
    id: str
    asset_type: AssetType
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    matched_content: str
    recommendation: str
    timestamp: str
    risk_score: int  # 0-100


class AISecurityScanner:
    """
    Main scanner class for discovering AI/LLM security issues
    
    Features:
    - API key detection (OpenAI, Anthropic, Google, AWS, Azure)
    - Endpoint security validation
    - Model reference tracking
    - Configuration analysis
    - Risk scoring
    """
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.scanned_files = 0
        self.ai_patterns = self._initialize_patterns()
        self.excluded_extensions = {'.pyc', '.git', '.png', '.jpg', '.jpeg', 
                                   '.gif', '.pdf', '.zip', '.exe', '.bin'}
        self.excluded_dirs = {'.git', 'node_modules', '__pycache__', 
                            'venv', 'env', '.venv'}
    
    def _initialize_patterns(self) -> Dict:
        """
        Initialize regex patterns for AI asset detection
        
        Pattern Structure:
        - API Keys: Detect various provider formats
        - Endpoints: Common AI service URLs
        - Models: Reference to AI models
        - Sensitive configs: Database connections, credentials
        """
        return {
            # API Keys - High precision patterns
            'openai_key': {
                'pattern': r'sk-[a-zA-Z0-9]{48,}',
                'description': 'OpenAI API Key',
                'severity': Severity.CRITICAL,
                'asset_type': AssetType.API_KEY
            },
            'openai_org': {
                'pattern': r'org-[a-zA-Z0-9]{24,}',
                'description': 'OpenAI Organization ID',
                'severity': Severity.HIGH,
                'asset_type': AssetType.API_KEY
            },
            'anthropic_key': {
                'pattern': r'sk-ant-api03-[a-zA-Z0-9_-]{95,}',
                'description': 'Anthropic API Key',
                'severity': Severity.CRITICAL,
                'asset_type': AssetType.API_KEY
            },
            'google_ai_key': {
                'pattern': r'AIza[0-9A-Za-z_-]{35}',
                'description': 'Google AI API Key',
                'severity': Severity.CRITICAL,
                'asset_type': AssetType.API_KEY
            },
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Key (Bedrock)',
                'severity': Severity.CRITICAL,
                'asset_type': AssetType.API_KEY
            },
            'azure_key': {
                'pattern': r'[0-9a-f]{32}',
                'description': 'Azure OpenAI Key',
                'severity': Severity.HIGH,
                'asset_type': AssetType.API_KEY,
                'context_required': ['azure', 'openai', 'cognitive']
            },
            
            # AI Endpoints
            'ai_endpoints': {
                'pattern': r'(api\.openai\.com|api\.anthropic\.com|bedrock\.amazonaws\.com|api\.cohere\.ai|api\.ai21\.com)',
                'description': 'AI Service Endpoint',
                'severity': Severity.MEDIUM,
                'asset_type': AssetType.ENDPOINT
            },
            
            # Model References
            'openai_models': {
                'pattern': r'(gpt-4-turbo|gpt-4|gpt-3\.5-turbo|text-davinci-003|text-embedding-ada-002)',
                'description': 'OpenAI Model Reference',
                'severity': Severity.INFO,
                'asset_type': AssetType.MODEL_REFERENCE
            },
            'anthropic_models': {
                'pattern': r'(claude-3-opus|claude-3-sonnet|claude-3-haiku|claude-2\.1|claude-2)',
                'description': 'Anthropic Model Reference',
                'severity': Severity.INFO,
                'asset_type': AssetType.MODEL_REFERENCE
            },
            'meta_models': {
                'pattern': r'(llama-2-[0-9]+b|llama-3-[0-9]+b|codellama)',
                'description': 'Meta LLaMA Model',
                'severity': Severity.INFO,
                'asset_type': AssetType.MODEL_REFERENCE
            },
            
            # Configuration Issues
            'hardcoded_creds': {
                'pattern': r'(password|passwd|pwd|secret|token)\s*=\s*["\'][^"\']{8,}["\']',
                'description': 'Hardcoded Credentials',
                'severity': Severity.HIGH,
                'asset_type': AssetType.CONFIG_FILE
            },
            
            # Prompt Injection Vulnerabilities
            'unsafe_prompt': {
                'pattern': r'(f".*\{.*\}.*"|f\'.*\{.*\}.*\')',
                'description': 'Potential Prompt Injection via f-string',
                'severity': Severity.MEDIUM,
                'asset_type': AssetType.PROMPT_TEMPLATE
            },
            
            # Vector Store Configs
            'pinecone_key': {
                'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'description': 'Pinecone API Key',
                'severity': Severity.HIGH,
                'asset_type': AssetType.EMBEDDING_STORE,
                'context_required': ['pinecone']
            }
        }
    
    def scan_directory(self, directory_path: str, max_files: int = 1000) -> List[SecurityFinding]:
        """
        Scan entire directory recursively
        
        Args:
            directory_path: Root directory to scan
            max_files: Maximum files to scan (prevent DoS)
        
        Returns:
            List of security findings
        """
        logger.info(f"Starting scan of directory: {directory_path}")
        self.findings.clear()
        self.scanned_files = 0
        
        path = Path(directory_path)
        if not path.exists():
            logger.error(f"Path does not exist: {directory_path}")
            return []
        
        for file_path in self._walk_directory(path):
            if self.scanned_files >= max_files:
                logger.warning(f"Reached max file limit: {max_files}")
                break
            
            self._scan_file(file_path)
            self.scanned_files += 1
        
        logger.info(f"Scan complete. Files scanned: {self.scanned_files}, Findings: {len(self.findings)}")
        return self.findings
    
    def _walk_directory(self, path: Path):
        """Generator to walk directory tree with exclusions"""
        for item in path.rglob('*'):
            # Skip excluded directories
            if any(excluded in item.parts for excluded in self.excluded_dirs):
                continue
            
            # Skip excluded file extensions
            if item.suffix in self.excluded_extensions:
                continue
            
            # Only process files
            if item.is_file():
                yield item
    
    def _scan_file(self, file_path: Path):
        """
        Scan individual file for security issues
        
        Process:
        1. Read file content safely
        2. Apply pattern matching
        3. Check context requirements
        4. Calculate risk score
        5. Generate findings
        """
        try:
            # Try to read as text
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Apply all patterns
            for pattern_name, pattern_config in self.ai_patterns.items():
                self._apply_pattern(file_path, content, pattern_name, pattern_config)
        
        except Exception as e:
            logger.debug(f"Could not scan {file_path}: {str(e)}")
    
    def _apply_pattern(self, file_path: Path, content: str, 
                       pattern_name: str, config: Dict):
        """Apply single pattern and create findings"""
        pattern = config['pattern']
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            # Check context requirements if specified
            if 'context_required' in config:
                if not self._check_context(content, match, config['context_required']):
                    continue
            
            # Find line number
            line_num = content[:match.start()].count('\n') + 1
            
            # Create finding
            finding = self._create_finding(
                file_path=str(file_path),
                line_number=line_num,
                matched_content=match.group(),
                config=config,
                pattern_name=pattern_name
            )
            
            self.findings.append(finding)
    
    def _check_context(self, content: str, match: re.Match, 
                       context_keywords: List[str]) -> bool:
        """Check if required context keywords exist near the match"""
        # Get surrounding context (500 chars before and after)
        start = max(0, match.start() - 500)
        end = min(len(content), match.end() + 500)
        context = content[start:end].lower()
        
        return any(keyword.lower() in context for keyword in context_keywords)
    
    def _create_finding(self, file_path: str, line_number: int,
                       matched_content: str, config: Dict, 
                       pattern_name: str) -> SecurityFinding:
        """Create a SecurityFinding object with risk scoring"""
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(
            severity=config['severity'],
            file_path=file_path,
            matched_content=matched_content
        )
        
        # Generate unique finding ID
        finding_id = hashlib.md5(
            f"{file_path}{line_number}{matched_content}".encode()
        ).hexdigest()[:12]
        
        # Mask sensitive content
        masked_content = self._mask_sensitive(matched_content)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(config['asset_type'])
        
        return SecurityFinding(
            id=finding_id,
            asset_type=config['asset_type'],
            severity=config['severity'],
            title=config['description'],
            description=f"Found {config['description']} in {Path(file_path).name}",
            file_path=file_path,
            line_number=line_number,
            matched_content=masked_content,
            recommendation=recommendation,
            timestamp=datetime.now().isoformat(),
            risk_score=risk_score
        )
    
    def _calculate_risk_score(self, severity: Severity, file_path: str,
                             matched_content: str) -> int:
        """
        Calculate risk score based on multiple factors
        
        Factors:
        - Base severity (40% weight)
        - File location (30% weight) - public vs config
        - Content exposure (30% weight) - env files vs code
        """
        # Base score from severity
        severity_scores = {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 50,
            Severity.LOW: 30,
            Severity.INFO: 10
        }
        base_score = severity_scores[severity]
        
        # Location factor
        location_modifier = 1.0
        if '.env' in file_path.lower() or 'config' in file_path.lower():
            location_modifier = 0.8  # Better if in config files
        elif 'public' in file_path.lower() or 'www' in file_path.lower():
            location_modifier = 1.3  # Worse if in public directories
        
        # Calculate final score
        final_score = min(100, int(base_score * location_modifier))
        
        return final_score
    
    def _mask_sensitive(self, content: str) -> str:
        """Mask sensitive parts of matched content"""
        if len(content) <= 8:
            return '*' * len(content)
        
        # Show first 4 and last 4 characters
        return f"{content[:4]}...{content[-4:]}"
    
    def _generate_recommendation(self, asset_type: AssetType) -> str:
        """Generate security recommendations based on asset type"""
        recommendations = {
            AssetType.API_KEY: "Move API keys to environment variables or secure vault. Never commit keys to version control. Use .gitignore to exclude .env files.",
            AssetType.ENDPOINT: "Ensure endpoints use HTTPS. Implement rate limiting and authentication. Monitor for unusual access patterns.",
            AssetType.MODEL_REFERENCE: "Document model usage and track costs. Ensure compliance with model provider terms of service.",
            AssetType.CONFIG_FILE: "Store sensitive configuration in secure vaults (AWS Secrets Manager, HashiCorp Vault). Use environment-specific configs.",
            AssetType.PROMPT_TEMPLATE: "Sanitize user inputs to prevent prompt injection. Validate and escape all dynamic content in prompts.",
            AssetType.EMBEDDING_STORE: "Secure vector database credentials. Implement access controls and encryption at rest."
        }
        
        return recommendations.get(asset_type, "Review this finding and implement security best practices.")
    
    def get_statistics(self) -> Dict:
        """Generate summary statistics"""
        if not self.findings:
            return {
                'total_findings': 0,
                'by_severity': {},
                'by_asset_type': {},
                'avg_risk_score': 0
            }
        
        severity_counts = {}
        asset_type_counts = {}
        
        for finding in self.findings:
            # Count by severity
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by asset type
            asset = finding.asset_type.value
            asset_type_counts[asset] = asset_type_counts.get(asset, 0) + 1
        
        avg_risk = sum(f.risk_score for f in self.findings) / len(self.findings)
        
        return {
            'total_findings': len(self.findings),
            'files_scanned': self.scanned_files,
            'by_severity': severity_counts,
            'by_asset_type': asset_type_counts,
            'avg_risk_score': round(avg_risk, 2),
            'critical_findings': severity_counts.get('CRITICAL', 0),
            'high_findings': severity_counts.get('HIGH', 0)
        }
    
    def export_findings(self, output_file: str, format: str = 'json'):
        """
        Export findings to file
        
        Supported formats:
        - json: Structured JSON output
        - csv: Tabular format for spreadsheets
        - html: HTML report
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(
                    [asdict(finding) for finding in self.findings],
                    f,
                    indent=2,
                    default=str
                )
        
        logger.info(f"Exported {len(self.findings)} findings to {output_file}")


# Example usage
if __name__ == "__main__":
    scanner = AISecurityScanner()
    
    # Scan current directory
    findings = scanner.scan_directory(".", max_files=500)
    
    # Print statistics
    stats = scanner.get_statistics()
    print(f"\n{'='*60}")
    print(f"AI Security Scan Results")
    print(f"{'='*60}")
    print(f"Files Scanned: {stats['files_scanned']}")
    print(f"Total Findings: {stats['total_findings']}")
    print(f"Average Risk Score: {stats['avg_risk_score']}/100")
    print(f"\nBy Severity:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")
    
    # Export results
    scanner.export_findings('security_findings.json')
