# SiteGuard

A simple website security scanner for detecting common web vulnerabilities.

## Features

- XSS (Cross-Site Scripting) detection
- SQL Injection testing
- Directory traversal checks
- Sensitive file exposure detection
- Multiple output formats (text, JSON)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
python siteguard.py http://example.com
```

Save report to file:
```bash
python siteguard.py http://example.com -o report.txt
```

JSON output:
```bash
python siteguard.py http://example.com -o report.json -f json
```

Using configuration file:
```bash
python siteguard.py http://example.com -c config.json
```

Create sample configuration:
```bash
python siteguard.py --create-config sample_config.json
```

## Security Tests

### XSS Detection
Tests forms for reflected XSS vulnerabilities using common payloads.

### SQL Injection
Checks form inputs for SQL injection by testing error-based detection.

### Directory Traversal
Tests for path traversal vulnerabilities and sensitive file exposure.

## Output

The tool provides detailed console output during scanning and can generate reports in text or JSON format.

## Disclaimer

This tool is for educational and authorized testing purposes only. Do not use on systems you do not own or have explicit permission to test.

## License

MIT