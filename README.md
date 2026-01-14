# VigiScanner

A security scanner that finds exposed API keys in your code. Built this because I kept accidentally committing keys to repos.

## What it does

Scans your codebase for:
- OpenAI API keys (sk-...)
- Anthropic Claude keys (sk-ant-...)
- Google AI keys
- AWS credentials
- Azure OpenAI keys
- Other common AI service credentials

It also scores each finding based on how risky it is (where the file is, what type of key, etc).

## Quick start

```bash
pip install -r requirements.txt
python ai_security_scanner.py
```

Want a dashboard? Run:
```bash
streamlit run streamlit_dashboard.py
```

## Usage

Basic scan:
```python
from ai_security_scanner import AISecurityScanner

scanner = AISecurityScanner()
findings = scanner.scan_directory(".")
stats = scanner.get_statistics()

print(f"Found {stats['total_findings']} potential issues")
```

Export results:
```python
scanner.export_findings('report.json', format='json')
```

## Configuration

Copy `.env.example` to `.env` and adjust settings:
- `SCAN_MAX_FILES` - how many files to scan
- `EXCLUDED_DIRS` - directories to skip
- `LOG_LEVEL` - logging verbosity

You can also modify patterns directly in `config.py`.

## What gets detected

The scanner looks for these patterns:

| Type | Example | Risk |
|------|---------|------|
| OpenAI keys | sk-proj... | Critical |
| Anthropic keys | sk-ant-api03-... | Critical |
| AWS keys | AKIA... | Critical |
| API endpoints | api.openai.com | Medium |
| Hardcoded passwords | password="..." | High |

## GitHub Actions

There's a workflow file in `.github/workflows/` that runs the scanner on every push. It'll create issues for critical findings automatically.

To use it, just copy the workflow to your repo:
```bash
cp .github/workflows/security-scan.yml your-repo/.github/workflows/
```

## How it works

Pretty straightforward:
1. Recursively walks through your directories
2. Skips common stuff like node_modules, .git, etc
3. Runs regex patterns against each file
4. Calculates a risk score based on context
5. Generates a report

The risk scoring considers:
- File location (is it in a public directory?)
- File type (config files are riskier)
- Pattern type (API keys vs model names)
- Context around the match

## False positives

Yeah, there will be some. The scanner tries to reduce them by:
- Requiring context for ambiguous patterns
- Excluding test/mock data directories
- Checking file extensions

If you get too many false positives, you can:
- Add directories to exclude in `config.py`
- Adjust the severity thresholds
- Add context requirements to patterns

## Testing

Run tests with:
```bash
pytest test_examples.py -v
```

Tests cover key detection, risk scoring, file exclusion, and export functionality.

## Why I built this

Got tired of manually checking for exposed keys before pushing code. Plus, wanted something that:
- Actually understands AI service keys (not just generic secret scanning)
- Gives risk scores instead of just flagging everything
- Has a decent UI for reviewing findings
- Works in CI/CD without much setup

## Contributing

If you want to add patterns for other AI services or improve the detection, PRs are welcome. The pattern definitions are in `ai_security_scanner.py`.

## License

MIT - do whatever you want with it

## Notes

- This doesn't catch everything. Use it as one layer of defense, not the only one
- If you find a key in your git history, rotate it immediately
- Use environment variables and secret managers in production
- The dashboard is for local use - don't expose it publicly without auth

---

Made by [@drvigilant](https://github.com/drvigilant)
