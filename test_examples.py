"""
Test Suite & Usage Examples for AI Security Scanner
Demonstrates scanner capabilities and provides test cases
"""

import pytest
from pathlib import Path
import tempfile
import json
from ai_security_scanner import (
    AISecurityScanner,
    SecurityFinding,
    Severity,
    AssetType
)

# ============================================================
# UNIT TESTS
# ============================================================

class TestAISecurityScanner:
    """Unit tests for the AI Security Scanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for tests"""
        return AISecurityScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_openai_key_detection(self, scanner, temp_dir):
        """Test OpenAI API key detection"""
        # Create test file with OpenAI key
        test_file = temp_dir / "config.py"
        test_file.write_text("""
# Configuration file
OPENAI_API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        """)
        
        # Run scan
        findings = scanner.scan_directory(str(temp_dir))
        
        # Assertions
        assert len(findings) > 0
        assert any(f.asset_type == AssetType.API_KEY for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any('OpenAI' in f.title for f in findings)
    
    def test_anthropic_key_detection(self, scanner, temp_dir):
        """Test Anthropic API key detection"""
        test_file = temp_dir / "app.py"
        test_file.write_text("""
import anthropic

# Initialize client
client = anthropic.Anthropic(
    api_key="sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
)
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        
        assert len(findings) > 0
        assert any('Anthropic' in f.title for f in findings)
    
    def test_context_aware_detection(self, scanner, temp_dir):
        """Test context-aware pattern matching"""
        # Azure key WITH context - should match
        azure_file = temp_dir / "azure_config.py"
        azure_file.write_text("""
# Azure OpenAI Configuration
azure_endpoint = "https://myservice.openai.azure.com/"
azure_api_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        """)
        
        # Random hash WITHOUT context - should NOT match
        hash_file = temp_dir / "utils.py"
        hash_file.write_text("""
# File utilities
file_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        
        # Should find Azure key but not random hash
        azure_findings = [f for f in findings if 'azure' in f.file_path.lower()]
        hash_findings = [f for f in findings if 'utils' in f.file_path.lower()]
        
        assert len(azure_findings) > 0
        assert len(hash_findings) == 0  # Should be filtered by context
    
    def test_file_exclusion(self, scanner, temp_dir):
        """Test that excluded files are skipped"""
        # Create files that should be excluded
        (temp_dir / "node_modules").mkdir()
        (temp_dir / "node_modules" / "package.json").write_text("""
{
  "api_key": "sk-test123456789012345678901234567890123456789"
}
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        
        # Should not find anything in node_modules
        assert not any('node_modules' in f.file_path for f in findings)
    
    def test_risk_scoring(self, scanner, temp_dir):
        """Test risk score calculation"""
        # Critical finding in public directory
        public_dir = temp_dir / "public"
        public_dir.mkdir()
        (public_dir / "app.js").write_text("""
const OPENAI_KEY = "sk-proj1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";
        """)
        
        # Same finding in .env file
        (temp_dir / ".env").write_text("""
OPENAI_API_KEY=sk-proj1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        
        public_findings = [f for f in findings if 'public' in f.file_path]
        env_findings = [f for f in findings if '.env' in f.file_path]
        
        # Public directory should have HIGHER risk score
        if public_findings and env_findings:
            assert public_findings[0].risk_score > env_findings[0].risk_score
    
    def test_statistics_generation(self, scanner, temp_dir):
        """Test statistics calculation"""
        # Create multiple findings
        test_file = temp_dir / "multi_findings.py"
        test_file.write_text("""
OPENAI_KEY = "sk-test123456789012345678901234567890123456789"
ANTHROPIC_KEY = "sk-ant-api03-test123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"
PASSWORD = "hardcoded_password_123"
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        stats = scanner.get_statistics()
        
        assert stats['total_findings'] > 0
        assert 'by_severity' in stats
        assert 'by_asset_type' in stats
        assert 'avg_risk_score' in stats
    
    def test_export_functionality(self, scanner, temp_dir):
        """Test findings export"""
        test_file = temp_dir / "test.py"
        test_file.write_text("""
API_KEY = "sk-proj1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        """)
        
        findings = scanner.scan_directory(str(temp_dir))
        
        # Export to JSON
        export_file = temp_dir / "export.json"
        scanner.export_findings(str(export_file), format='json')
        
        # Verify export
        assert export_file.exists()
        with open(export_file) as f:
            exported_data = json.load(f)
        
        assert len(exported_data) > 0
        assert 'severity' in exported_data[0]


# ============================================================
# USAGE EXAMPLES
# ============================================================

def example_basic_scan():
    """
    Example 1: Basic repository scan
    
    Use case: Quick security check of a project
    """
    print("=" * 60)
    print("Example 1: Basic Scan")
    print("=" * 60)
    
    scanner = AISecurityScanner()
    
    # Scan current directory
    findings = scanner.scan_directory(".", max_files=500)
    
    # Print summary
    stats = scanner.get_statistics()
    print(f"\nScan Results:")
    print(f"  Files scanned: {stats['files_scanned']}")
    print(f"  Total findings: {stats['total_findings']}")
    print(f"  Critical: {stats.get('critical_findings', 0)}")
    print(f"  High: {stats.get('high_findings', 0)}")
    
    # Show critical findings
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    if critical:
        print(f"\n⚠️  CRITICAL ISSUES FOUND:")
        for finding in critical[:3]:  # Show first 3
            print(f"  - {finding.title}")
            print(f"    File: {finding.file_path}:{finding.line_number}")
            print(f"    Risk: {finding.risk_score}/100")


def example_filtered_scan():
    """
    Example 2: Filtered scan with custom settings
    
    Use case: Focus on specific asset types or severities
    """
    print("\n" + "=" * 60)
    print("Example 2: Filtered Scan")
    print("=" * 60)
    
    scanner = AISecurityScanner()
    findings = scanner.scan_directory(".")
    
    # Filter for API keys only
    api_keys = [f for f in findings 
                if f.asset_type == AssetType.API_KEY]
    
    print(f"\nAPI Keys Found: {len(api_keys)}")
    for finding in api_keys:
        print(f"  - {finding.title}")
        print(f"    Location: {finding.file_path}")
        print(f"    Severity: {finding.severity.value}")
    
    # Filter by severity
    high_priority = [f for f in findings 
                     if f.severity in [Severity.CRITICAL, Severity.HIGH]]
    
    print(f"\nHigh Priority Issues: {len(high_priority)}")


def example_custom_patterns():
    """
    Example 3: Adding custom detection patterns
    
    Use case: Detect organization-specific secrets
    """
    print("\n" + "=" * 60)
    print("Example 3: Custom Patterns")
    print("=" * 60)
    
    scanner = AISecurityScanner()
    
    # Add custom pattern for internal API
    scanner.ai_patterns['internal_api'] = {
        'pattern': r'internal_api_[a-zA-Z0-9]{32}',
        'description': 'Internal API Token',
        'severity': Severity.CRITICAL,
        'asset_type': AssetType.API_KEY
    }
    
    # Add pattern for database URLs
    scanner.ai_patterns['mongodb_uri'] = {
        'pattern': r'mongodb://[^:]+:[^@]+@[^/]+',
        'description': 'MongoDB Connection String',
        'severity': Severity.HIGH,
        'asset_type': AssetType.CONFIG_FILE
    }
    
    findings = scanner.scan_directory(".")
    
    # Check for custom patterns
    custom_findings = [f for f in findings 
                      if 'Internal' in f.title or 'MongoDB' in f.title]
    
    print(f"\nCustom Pattern Findings: {len(custom_findings)}")


def example_ci_integration():
    """
    Example 4: CI/CD integration script
    
    Use case: Fail builds on critical findings
    """
    print("\n" + "=" * 60)
    print("Example 4: CI/CD Integration")
    print("=" * 60)
    
    scanner = AISecurityScanner()
    findings = scanner.scan_directory(".")
    
    # Get critical count
    critical_count = len([f for f in findings 
                         if f.severity == Severity.CRITICAL])
    
    if critical_count > 0:
        print(f"\n❌ BUILD FAILED: {critical_count} critical issues found")
        
        # Export for artifacts
        scanner.export_findings('security_report.json')
        print("  Report saved to: security_report.json")
        
        # Exit with error code
        # import sys; sys.exit(1)  # Uncomment in real CI
    else:
        print("\n✅ BUILD PASSED: No critical issues found")


def example_scheduled_audit():
    """
    Example 5: Scheduled security audit
    
    Use case: Weekly security reports
    """
    print("\n" + "=" * 60)
    print("Example 5: Scheduled Audit")
    print("=" * 60)
    
    from datetime import datetime
    
    scanner = AISecurityScanner()
    findings = scanner.scan_directory(".")
    stats = scanner.get_statistics()
    
    # Generate audit report
    report = {
        'audit_date': datetime.now().isoformat(),
        'summary': stats,
        'findings': [
            {
                'id': f.id,
                'severity': f.severity.value,
                'title': f.title,
                'file': f.file_path,
                'risk_score': f.risk_score
            }
            for f in findings
        ]
    }
    
    # Save report
    report_file = f"audit_{datetime.now().strftime('%Y%m%d')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Audit complete")
    print(f"  Report: {report_file}")
    print(f"  Total findings: {stats['total_findings']}")
    print(f"  Risk score: {stats['avg_risk_score']}/100")


def example_progressive_scan():
    """
    Example 6: Progressive scan with live updates
    
    Use case: Real-time feedback during scan
    """
    print("\n" + "=" * 60)
    print("Example 6: Progressive Scan")
    print("=" * 60)
    
    scanner = AISecurityScanner()
    
    # Override scan method to show progress
    original_scan = scanner._scan_file
    
    def scan_with_progress(file_path):
        result = original_scan(file_path)
        if scanner.scanned_files % 10 == 0:
            print(f"  Scanned {scanner.scanned_files} files...", end='\r')
        return result
    
    scanner._scan_file = scan_with_progress
    
    findings = scanner.scan_directory(".")
    print(f"\n  Complete! Found {len(findings)} issues")


# ============================================================
# TEST DATA GENERATORS
# ============================================================

def generate_test_files(output_dir: Path):
    """
    Generate test files with known vulnerabilities
    
    Use case: Testing scanner accuracy
    """
    output_dir.mkdir(exist_ok=True)
    
    # File 1: Exposed API keys
    (output_dir / "exposed_keys.py").write_text("""
# SECURITY ISSUE: Exposed API keys
OPENAI_API_KEY = "sk-proj1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
ANTHROPIC_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
    """)
    
    # File 2: Hardcoded credentials
    (output_dir / "db_config.py").write_text("""
# SECURITY ISSUE: Hardcoded credentials
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'super_secret_password_123',
    'database': 'production'
}
    """)
    
    # File 3: Prompt injection vulnerability
    (output_dir / "chat_handler.py").write_text("""
# SECURITY ISSUE: Prompt injection vulnerability
def handle_user_query(user_input):
    prompt = f"Answer this question: {user_input}"
    # No input sanitization!
    return openai.chat(prompt)
    """)
    
    # File 4: Safe code (should not trigger)
    (output_dir / "safe_code.py").write_text("""
import os
from dotenv import load_dotenv

# SAFE: Uses environment variables
load_dotenv()
api_key = os.getenv('OPENAI_API_KEY')
    """)
    
    print(f"✅ Generated test files in {output_dir}")


# ============================================================
# MAIN EXECUTION
# ============================================================

if __name__ == "__main__":
    print("\n🔐 AI Security Scanner - Test & Examples Suite\n")
    
    # Run examples
    example_basic_scan()
    example_filtered_scan()
    example_custom_patterns()
    example_ci_integration()
    example_scheduled_audit()
    example_progressive_scan()
    
    print("\n" + "=" * 60)
    print("All examples complete!")
    print("=" * 60)
    
    # Generate test files for manual testing
    test_dir = Path("./test_files")
    generate_test_files(test_dir)
    
    print(f"\n💡 Tip: Run pytest to execute unit tests")
    print(f"   Command: pytest test_examples.py -v")
