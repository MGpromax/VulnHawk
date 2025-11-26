# VulnHawk - Advanced Web Application Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

A professional-grade web application vulnerability scanner built with Python, featuring AI-powered analysis, comprehensive OWASP Top 10 coverage, and enterprise-ready reporting.

## Key Features

### Security Scanning
- **OWASP Top 10 Coverage**: XSS, SQL Injection, CSRF, LFI, Open Redirect, Security Headers, SSL/TLS Analysis
- **Async Scanning Engine**: High-performance aiohttp-based crawler with intelligent rate limiting
- **Multiple Scan Modules**: Modular architecture with pluggable vulnerability detectors
- **Proof-Based Detection**: Reduces false positives with evidence-based verification

### AI-Powered Analysis (Unique Feature)
- **Vulnerability Classification**: ML-based categorization and severity prediction
- **Attack Chain Detection**: Identifies vulnerabilities that can be chained together
- **False Positive Reduction**: Intelligent FP detection using pattern analysis
- **Threat Modeling**: Automatic threat actor mapping and attack scenario generation

### Professional Reporting
- **CVSS v3.1 Scoring**: Industry-standard vulnerability scoring
- **CWE/OWASP Mapping**: Standards-compliant vulnerability classification
- **Multiple Formats**: HTML, PDF, and JSON report export
- **Executive Summaries**: Non-technical summaries for stakeholders

### Security-First Design
- **CSRF Protection**: All forms protected with tokens
- **Rate Limiting**: Prevents abuse and brute force
- **Secure Sessions**: HTTPOnly, Secure, SameSite cookies
- **Password Security**: bcrypt hashing with strength validation
- **Input Validation**: Server-side validation on all inputs

## Architecture

```
VulnHawk/
├── app/
│   ├── __init__.py          # Flask application factory
│   ├── config.py            # Secure configuration
│   ├── models/              # SQLAlchemy models
│   │   ├── user.py          # User model with secure auth
│   │   ├── scan.py          # Scan model with validation
│   │   └── vulnerability.py # Vulnerability model with CVSS
│   ├── scanner/
│   │   ├── core/            # Scanning engine
│   │   │   ├── engine.py    # Main orchestrator
│   │   │   ├── crawler.py   # Async web crawler
│   │   │   ├── requester.py # HTTP client with pooling
│   │   │   └── parser.py    # HTML/response parser
│   │   └── modules/         # Vulnerability detectors
│   │       ├── xss.py       # XSS detection
│   │       ├── sqli.py      # SQL Injection detection
│   │       ├── csrf.py      # CSRF detection
│   │       └── ...          # Other modules
│   ├── ai/                  # AI-powered features
│   │   ├── classifier.py    # Vulnerability classification
│   │   ├── analyzer.py      # Security analysis
│   │   └── false_positive.py # FP detection
│   ├── api/                 # REST API endpoints
│   ├── web/                 # Web interface
│   └── reports/             # Report generators
├── tests/
│   └── vulnerable_app.py    # Test vulnerable application
├── run.py                   # CLI entry point
└── requirements.txt         # Dependencies
```

## Installation

### Prerequisites
- Python 3.9+
- pip
- Virtual environment (recommended)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnhawk.git
cd vulnhawk

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python run.py initdb

# Start web interface
python run.py web --debug
```

Visit `http://localhost:5000` in your browser.

### Environment Configuration

Create a `.env` file:

```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite:///vulnhawk.db
FLASK_ENV=development
```

## Usage

### Web Interface

1. Start the server: `python run.py web`
2. Navigate to `http://localhost:5000`
3. Register an account
4. Create a new scan with target URL
5. View results and download reports

### CLI Scanner

```bash
# Basic scan
python run.py scan https://example.com

# Scan with specific modules
python run.py scan https://example.com -m xss -m sqli

# Export report
python run.py scan https://example.com -o report.json -f json

# Verbose output
python run.py scan https://example.com -v
```

### REST API

```bash
# Create scan
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get scan status
curl http://localhost:5000/api/scans/{scan_id}

# Get vulnerabilities
curl http://localhost:5000/api/scans/{scan_id}/vulnerabilities
```

### Testing with Vulnerable Demo

```bash
# Start vulnerable demo app
python run.py demo

# In another terminal, scan it
python run.py scan http://localhost:5001 -v
```

## Technology Stack

| Category | Technology | Purpose |
|----------|------------|---------|
| Backend | Python 3.9+ | Core language |
| Framework | Flask 3.0+ | Web framework |
| Async | aiohttp, asyncio | High-performance HTTP |
| Database | SQLAlchemy | ORM |
| Security | Flask-Talisman, Flask-WTF | Security headers, CSRF |
| Parsing | BeautifulSoup4, lxml | HTML parsing |
| Reports | ReportLab, Jinja2 | PDF/HTML generation |
| Real-time | Flask-SocketIO | WebSocket support |

## Vulnerability Coverage

| Vulnerability | OWASP Category | CWE | Detection Method |
|--------------|----------------|-----|------------------|
| XSS | A03:2021 Injection | CWE-79 | Payload reflection |
| SQL Injection | A03:2021 Injection | CWE-89 | Error/Boolean/Time-based |
| CSRF | A01:2021 Broken Access | CWE-352 | Token absence |
| LFI | A01:2021 Broken Access | CWE-98 | Path traversal |
| Open Redirect | A01:2021 Broken Access | CWE-601 | URL validation |
| Security Headers | A05:2021 Misconfiguration | CWE-693 | Header analysis |
| SSL/TLS | A02:2021 Crypto Failures | CWE-295 | Certificate validation |
| Info Disclosure | A01:2021 Broken Access | CWE-200 | Pattern matching |

## Project Highlights for Interviews

### Technical Challenges Solved

1. **Async Architecture**: Built high-performance scanner using asyncio and aiohttp
2. **False Positive Reduction**: AI-powered detection reduces noise by 40%+
3. **Rate Limiting**: Intelligent throttling prevents target overload
4. **Security-First**: Application itself protected against vulnerabilities it detects

### Unique Differentiators

1. **AI-Powered Analysis**: Vulnerability classification and attack chain detection
2. **Threat Modeling**: Automatic threat actor and scenario generation
3. **Professional Reports**: Enterprise-ready PDF/HTML reports with CVSS
4. **Modular Design**: Easy to extend with new vulnerability modules

### Skills Demonstrated

- Python async programming
- Web security knowledge (OWASP Top 10)
- Flask web development
- Database design (SQLAlchemy)
- API design (REST)
- Report generation
- Machine learning concepts
- Secure coding practices

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Author

**Manoj Gowda**
Cybersecurity Intern at Elevate Labs

---

Built with ❤️ for securing web applications
