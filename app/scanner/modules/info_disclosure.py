"""
Information Disclosure Detection Module

Detects sensitive information leakage in responses.
"""

import re
from typing import List, Dict, Optional
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


# Patterns for sensitive information
SENSITIVE_PATTERNS = {
    'api_key': {
        'patterns': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
            r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})',
        ],
        'severity': Severity.HIGH,
        'name': 'API Key Exposed',
        'cwe_id': 'CWE-312'
    },
    'aws_key': {
        'patterns': [
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})',
            r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
        ],
        'severity': Severity.CRITICAL,
        'name': 'AWS Credentials Exposed',
        'cwe_id': 'CWE-798'
    },
    'private_key': {
        'patterns': [
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ],
        'severity': Severity.CRITICAL,
        'name': 'Private Key Exposed',
        'cwe_id': 'CWE-321'
    },
    'password': {
        'patterns': [
            r'password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'passwd["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'pwd["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
        ],
        'severity': Severity.HIGH,
        'name': 'Password Exposed in Source',
        'cwe_id': 'CWE-798'
    },
    'database_connection': {
        'patterns': [
            r'mongodb(\+srv)?://[a-zA-Z0-9_-]+:[^@]+@[^\s"\']+',
            r'mysql://[a-zA-Z0-9_-]+:[^@]+@[^\s"\']+',
            r'postgres(ql)?://[a-zA-Z0-9_-]+:[^@]+@[^\s"\']+',
            r'redis://[a-zA-Z0-9_-]+:[^@]+@[^\s"\']+',
        ],
        'severity': Severity.CRITICAL,
        'name': 'Database Connection String Exposed',
        'cwe_id': 'CWE-312'
    },
    'jwt_secret': {
        'patterns': [
            r'jwt[_-]?secret["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
        ],
        'severity': Severity.HIGH,
        'name': 'JWT/Secret Key Exposed',
        'cwe_id': 'CWE-798'
    },
    'email': {
        'patterns': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'severity': Severity.INFO,
        'name': 'Email Addresses Disclosed',
        'cwe_id': 'CWE-200',
        'threshold': 5  # Only report if more than 5 found
    },
    'internal_ip': {
        'patterns': [
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            r'\b(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b',
            r'\b(192\.168\.\d{1,3}\.\d{1,3})\b',
        ],
        'severity': Severity.LOW,
        'name': 'Internal IP Address Disclosed',
        'cwe_id': 'CWE-200'
    },
    'debug_info': {
        'patterns': [
            r'Traceback \(most recent call last\)',
            r'at\s+\w+\.\w+\([\w\.]+:\d+\)',  # Java stack trace
            r'File "[^"]+", line \d+',  # Python stack trace
            r'#\d+\s+[^\n]+\(\d+\)',  # PHP stack trace
        ],
        'severity': Severity.MEDIUM,
        'name': 'Stack Trace/Debug Information Exposed',
        'cwe_id': 'CWE-209'
    },
    'sql_query': {
        'patterns': [
            r'SELECT\s+.+\s+FROM\s+\w+',
            r'INSERT\s+INTO\s+\w+',
            r'UPDATE\s+\w+\s+SET',
            r'DELETE\s+FROM\s+\w+',
        ],
        'severity': Severity.LOW,
        'name': 'SQL Query Exposed in Response',
        'cwe_id': 'CWE-200'
    },
    'file_path': {
        'patterns': [
            r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',  # Windows path
            r'/(?:home|var|etc|opt|usr)/[a-zA-Z0-9_/.-]+',  # Unix path
        ],
        'severity': Severity.LOW,
        'name': 'File System Path Disclosed',
        'cwe_id': 'CWE-200'
    },
    'credit_card': {
        'patterns': [
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        ],
        'severity': Severity.CRITICAL,
        'name': 'Credit Card Number Exposed',
        'cwe_id': 'CWE-312'
    },
    'ssn': {
        'patterns': [
            r'\b\d{3}-\d{2}-\d{4}\b',
        ],
        'severity': Severity.CRITICAL,
        'name': 'Social Security Number Exposed',
        'cwe_id': 'CWE-312'
    }
}


class InfoDisclosureModule(BaseModule):
    """
    Information Disclosure Detection Module

    Detects:
    - Hardcoded credentials
    - API keys and secrets
    - Debug information
    - Sensitive personal data
    - Internal infrastructure details
    """

    name = "Information Disclosure Scanner"
    description = "Detects sensitive information leakage"
    vulnerability_type = "info_disclosure"
    cwe_id = "CWE-200"
    owasp_category = "A01:2021"

    def __init__(self):
        super().__init__()
        # Pre-compile patterns for performance
        self._compiled_patterns = {}
        for category, config in SENSITIVE_PATTERNS.items():
            self._compiled_patterns[category] = {
                'patterns': [re.compile(p, re.IGNORECASE) for p in config['patterns']],
                'severity': config['severity'],
                'name': config['name'],
                'cwe_id': config['cwe_id'],
                'threshold': config.get('threshold', 1)
            }

    async def check(self, response, url: str, parsed=None, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Check for information disclosure in response.

        Args:
            response: HTTP response object
            url: Page URL
            parsed: Parsed page data

        Returns:
            List of VulnerabilityResult objects
        """
        results = []

        if not response or not hasattr(response, 'body'):
            return results

        body = response.body

        # Check for each category of sensitive information
        for category, config in self._compiled_patterns.items():
            matches = []

            for pattern in config['patterns']:
                found = pattern.findall(body)
                matches.extend(found)

            # Apply threshold
            if len(matches) >= config['threshold']:
                # Limit matches to show
                sample_matches = matches[:3]

                # Mask sensitive data
                masked_matches = [self._mask_sensitive(m) for m in sample_matches]

                description = (
                    f"Found {len(matches)} instance(s) of {config['name'].lower()} in the response. "
                    f"This could expose sensitive information to attackers."
                )

                results.append(self.create_vulnerability(
                    name=config['name'],
                    severity=config['severity'],
                    url=url,
                    description=description,
                    confidence=Confidence.HIGH if config['severity'] in [Severity.CRITICAL, Severity.HIGH] else Confidence.MEDIUM,
                    evidence=f"Found: {', '.join(masked_matches)}" + (f" and {len(matches) - 3} more" if len(matches) > 3 else ""),
                    cwe_id=config['cwe_id'],
                    remediation=self._get_remediation(category),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"
                    ]
                ))

        # Check HTML comments for sensitive info
        if parsed and parsed.comments:
            comment_vulns = self._check_comments(parsed.comments, url)
            results.extend(comment_vulns)

        # Check for directory listing
        if self._is_directory_listing(body):
            results.append(self.create_vulnerability(
                name="Directory Listing Enabled",
                severity=Severity.MEDIUM,
                url=url,
                description="Directory listing is enabled, exposing file structure and potentially sensitive files.",
                confidence=Confidence.HIGH,
                cwe_id='CWE-548',
                remediation="Disable directory listing in web server configuration."
            ))

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """Information disclosure is detected passively."""
        return []

    def _mask_sensitive(self, value: str) -> str:
        """Mask sensitive data for safe display."""
        if isinstance(value, tuple):
            value = value[0] if value else ''

        value = str(value)

        if len(value) <= 8:
            return '*' * len(value)

        # Show first 4 and last 4 characters
        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def _check_comments(self, comments: List[str], url: str) -> List[VulnerabilityResult]:
        """Check HTML comments for sensitive information."""
        results = []
        sensitive_comments = []

        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api',
            'todo', 'fixme', 'bug', 'hack', 'debug',
            'admin', 'root', 'internal', 'private',
            'database', 'sql', 'query', 'credentials'
        ]

        for comment in comments:
            comment_lower = comment.lower()
            for keyword in sensitive_keywords:
                if keyword in comment_lower:
                    sensitive_comments.append(self.truncate(comment, 100))
                    break

        if sensitive_comments:
            results.append(self.create_vulnerability(
                name="Sensitive Information in HTML Comments",
                severity=Severity.LOW,
                url=url,
                description=f"Found {len(sensitive_comments)} HTML comment(s) containing potentially sensitive information.",
                confidence=Confidence.MEDIUM,
                evidence=f"Comments: {'; '.join(sensitive_comments[:3])}",
                cwe_id='CWE-615',
                remediation="Remove comments containing sensitive information before deployment."
            ))

        return results

    def _is_directory_listing(self, body: str) -> bool:
        """Check if response is a directory listing."""
        indicators = [
            'Index of /',
            '<title>Index of',
            'Directory listing for',
            'Parent Directory</a>',
            '[To Parent Directory]',
        ]

        body_lower = body.lower()
        return any(indicator.lower() in body_lower for indicator in indicators)

    def _get_remediation(self, category: str) -> str:
        """Get category-specific remediation."""
        remediations = {
            'api_key': "Store API keys in environment variables or secure vaults. Never commit secrets to source code.",
            'aws_key': "Use IAM roles instead of hardcoded credentials. Store secrets in AWS Secrets Manager.",
            'private_key': "Never expose private keys. Use secure key management systems.",
            'password': "Use environment variables for credentials. Implement proper secrets management.",
            'database_connection': "Use environment variables for connection strings. Restrict database access by IP.",
            'jwt_secret': "Store JWT secrets in secure vaults. Rotate secrets regularly.",
            'email': "Minimize email exposure. Use contact forms instead of displaying emails directly.",
            'internal_ip': "Configure proper error handling to avoid exposing internal infrastructure.",
            'debug_info': "Disable debug mode in production. Implement custom error pages.",
            'sql_query': "Never expose SQL queries in responses. Use proper logging instead.",
            'file_path': "Configure proper error handling. Avoid exposing server file paths.",
            'credit_card': "Never store or display full credit card numbers. Use tokenization.",
            'ssn': "Never expose SSNs. Implement proper data masking and access controls."
        }

        return remediations.get(category, "Review and remove sensitive information from responses.")


# Module interface functions
async def check(response, url: str, parsed=None, *args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = InfoDisclosureModule()
    results = await module.check(response, url, parsed, *args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(*args, **kwargs) -> List[Dict]:
    """Active test interface (not applicable)."""
    return []
