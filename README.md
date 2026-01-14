# 🔐 AI Security Posture Scanner

A comprehensive security tool for discovering AI/LLM assets and identifying security misconfigurations in your codebase and infrastructure.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [CI/CD Integration](#cicd-integration)
- [Security Patterns](#security-patterns)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## ✨ Features

### Asset Discovery
- **API Key Detection**: OpenAI, Anthropic, Google AI, AWS Bedrock, Azure OpenAI
- **Endpoint Scanning**: AI service URLs and configurations
- **Model References**: Track usage of GPT-4, Claude, LLaMA, etc.
- **Configuration Analysis**: Detect misconfigurations in AI service setup
- **Prompt Templates**: Identify potential prompt injection vulnerabilities
- **Vector Stores**: Find Pinecone, Weaviate, and other embedding database credentials

### Risk Assessment
- **Severity Scoring**: CRITICAL, HIGH, MEDIUM, LOW, INFO levels
- **Risk Calculation**: 0-100 score based on exposure and context
- **Context-Aware Detection**: Reduces false positives with intelligent matching
- **File Location Analysis**: Prioritizes public vs. configuration files
- **Exposure Assessment**: Evaluates credential visibility risk

### Reporting & Visualization
- **Interactive Dashboard**: Streamlit-based UI with real-time insights
- **Multiple Export Formats**: JSON, CSV, HTML reports
- **Visual Analytics**: Charts, graphs, and trend analysis
- **Detailed Findings**: Line-by-line code references
- **Actionable Recommendations**: Security remediation guidance

### Automation
- **GitHub Actions Integration**: Automated scanning on commits and PRs
- **Scheduled Scans**: Daily security checks
- **Issue Creation**: Automatic GitHub issues for critical findings
- **PR Comments**: Security feedback directly on pull requests

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Security Scanner                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────┐  │
│  │   Scanner    │─────▶│     Risk     │─────▶│ Report   │  │
│  │   Engine     │      │  Assessment  │      │ Generator│  │
│  └──────────────┘      └──────────────┘      └──────────┘  │
│         │                      │                     │       │
│         │                      │                     │       │
│         ▼                      ▼                     ▼       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────┐  │
│  │   Pattern    │      │   Severity   │      │Dashboard │  │
│  │   Matcher    │      │   Scorer     │      │   UI     │  │
│  └──────────────┘      └──────────────┘      └──────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

1. **Scanner Engine** (`ai_security_scanner.py`)
   - File traversal and exclusion logic
   - Pattern matching engine
   - Multi-format support (Python, JS, JSON, YAML, etc.)

2. **Risk Assessment Module**
   - Context-aware severity scoring
   - Location-based risk calculation
   - False positive reduction

3. **Dashboard** (`streamlit_dashboard.py`)
   - Real-time visualization
   - Interactive filtering
   - Export capabilities

4. **Configuration Management** (`config.py`)
   - Environment-based settings
   - Pattern customization
   - Exclusion rules

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Git (for repository scanning)

### 5-Minute Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/ai-security-scanner.git
cd ai-security-scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run a quick scan
python ai_security_scanner.py

# 4. Launch the dashboard
streamlit run streamlit_dashboard.py
```

That's it! Open your browser to `http://localhost:8501` to view the results.

## 📦 Installation

### Standard Installation

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation (Coming Soon)

```bash
docker build -t ai-security-scanner .
docker run -v $(pwd):/app ai-security-scanner
```

## 💻 Usage

### Command Line Scanning

```python
from ai_security_scanner import AISecurityScanner

# Initialize scanner
scanner = AISecurityScanner()

# Scan current directory
findings = scanner.scan_directory(".", max_files=1000)

# Get statistics
stats = scanner.get_statistics()
print(f"Found {stats['total_findings']} issues")

# Export results
scanner.export_findings('report.json', format='json')
```

### Advanced Scanning

```python
from ai_security_scanner import AISecurityScanner
from config import ScannerConfig

# Configure scanner
scanner = AISecurityScanner()
scanner.excluded_dirs = ScannerConfig.EXCLUDED_DIRS
scanner.excluded_extensions = ScannerConfig.EXCLUDED_EXTENSIONS

# Scan specific directory
findings = scanner.scan_directory(
    "/path/to/project",
    max_files=5000
)

# Filter critical findings
critical = [f for f in findings if f.severity.value == 'CRITICAL']

# Export critical findings only
for finding in critical:
    print(f"{finding.title}: {finding.file_path}:{finding.line_number}")
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Scanner Settings
SCAN_MAX_FILES=1000
SCAN_MAX_FILE_SIZE_MB=10
SCAN_TIMEOUT_SECONDS=300

# Exclusions
EXCLUDED_DIRS=.git,node_modules,venv,__pycache__
EXCLUDED_EXTENSIONS=.pyc,.png,.jpg,.pdf

# Logging
LOG_LEVEL=INFO
LOG_FILE=scanner.log

# Export
EXPORT_FORMAT=json
EXPORT_DIR=./reports
```

### Custom Patterns

Add custom detection patterns in `ai_security_scanner.py`:

```python
'custom_pattern': {
    'pattern': r'your-regex-here',
    'description': 'Your Pattern Description',
    'severity': Severity.HIGH,
    'asset_type': AssetType.API_KEY
}
```

## 📊 Dashboard

### Features

The Streamlit dashboard provides:

- **Real-time Scanning**: Scan while you watch
- **Visual Analytics**: 
  - Severity distribution charts
  - Asset type breakdowns
  - Risk score histograms
  - Timeline views
- **Interactive Filtering**: Filter by severity and asset type
- **Detailed Findings**: Expandable cards with full context
- **Export Options**: Download results in multiple formats

### Running the Dashboard

```bash
streamlit run streamlit_dashboard.py
```

Access at: `http://localhost:8501`

### Dashboard Configuration

Customize the dashboard in the sidebar:
- Scan directory path
- Max files to scan
- Severity filters
- Asset type filters
- Sort options

## 🔄 CI/CD Integration

### GitHub Actions

The included workflow (`.github/workflows/security-scan.yml`) provides:

- **Automated Scanning**: On every push and PR
- **Scheduled Scans**: Daily security checks
- **Issue Creation**: Automatic issues for critical findings
- **PR Comments**: Security feedback on pull requests
- **Artifact Storage**: 90-day retention of scan results

### Setup

1. Copy workflow file to your repository:
```bash
mkdir -p .github/workflows
cp security-scan.yml .github/workflows/
```

2. Commit and push:
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add AI security scanning workflow"
git push
```

3. The workflow runs automatically!

### Custom Actions

Add to your existing workflow:

```yaml
- name: AI Security Scan
  run: |
    pip install -r requirements.txt
    python ai_security_scanner.py
    
- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan
    path: security_findings.json
```

## 🔍 Security Patterns

### Detected Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| OpenAI Keys | CRITICAL | `sk-[a-zA-Z0-9]{48}` |
| Anthropic Keys | CRITICAL | `sk-ant-api03-...` |
| Google AI Keys | CRITICAL | `AIza[0-9A-Za-z_-]{35}` |
| AWS Access Keys | CRITICAL | `AKIA[0-9A-Z]{16}` |
| Azure Keys | HIGH | 32-char hex with context |
| AI Endpoints | MEDIUM | api.openai.com, etc. |
| Model References | INFO | gpt-4, claude-3, etc. |
| Hardcoded Creds | HIGH | password="..." patterns |
| Prompt Injection | MEDIUM | Unsafe f-strings |

### Pattern Matching Logic

```
1. Read file content
2. Apply regex patterns
3. Check context requirements (for Azure, etc.)
4. Calculate line numbers
5. Score risk (0-100)
6. Generate recommendations
7. Mask sensitive content
```

### Context-Aware Detection

Reduces false positives by requiring context:

```python
'azure_key': {
    'pattern': r'[0-9a-f]{32}',
    'context_required': ['azure', 'openai', 'cognitive']
}
```

This ensures "azure_key" only matches when Azure-related keywords are nearby.

## 🛡️ Best Practices

### 1. Use Environment Variables

❌ **Bad:**
```python
api_key = "sk-abc123..."
```

✅ **Good:**
```python
import os
api_key = os.getenv('OPENAI_API_KEY')
```

### 2. Use .gitignore

Add to `.gitignore`:
```
.env
.env.local
secrets.json
credentials.json
*.key
*.pem
```

### 3. Rotate Compromised Keys

If keys are found in git history:
1. Rotate keys immediately via provider dashboard
2. Use `git-filter-repo` to remove from history
3. Force push changes
4. Notify your team

### 4. Use Secret Managers

Production applications should use:
- **AWS Secrets Manager**
- **Azure Key Vault**
- **Google Secret Manager**
- **HashiCorp Vault**

### 5. Regular Scanning

- Run scans on every commit
- Schedule daily scans
- Review findings weekly
- Update patterns monthly

## 🐛 Troubleshooting

### Common Issues

**Issue: Scanner is slow**
- Reduce `max_files` parameter
- Add more directories to `EXCLUDED_DIRS`
- Scan specific subdirectories

**Issue: Too many false positives**
- Adjust severity thresholds
- Add context requirements to patterns
- Exclude test/mock files

**Issue: Dashboard won't start**
```bash
# Check Streamlit installation
pip install --upgrade streamlit

# Clear cache
streamlit cache clear

# Check port availability
lsof -i :8501
```

**Issue: No findings detected**
- Verify scan path is correct
- Check file permissions
- Review excluded directories
- Increase `max_files` limit

## 📈 Roadmap

- [ ] Plugin system for custom patterns
- [ ] AWS S3 bucket scanning
- [ ] Docker image distribution
- [ ] Integration with SIEM tools
- [ ] Machine learning for pattern detection
- [ ] Real-time monitoring mode
- [ ] Webhook notifications
- [ ] REST API for integration

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Anthropic for Claude API patterns
- OpenAI for security best practices
- OWASP for vulnerability research
- Security research community

## 📞 Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: dhairyav@hotmail.com

---

**⭐ Star this repo if you find it useful!**

Built with ❤️ for secure AI development
