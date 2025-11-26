"""
Security Headers Detection Module

Checks for missing or misconfigured security headers.
"""

from typing import List, Dict, Optional
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'name': 'HTTP Strict Transport Security (HSTS)',
        'severity': Severity.MEDIUM,
        'description': 'HSTS header is missing. This header forces browsers to use HTTPS, preventing downgrade attacks and cookie hijacking.',
        'remediation': "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        'cwe_id': 'CWE-319',
        'check_https_only': True
    },
    'Content-Security-Policy': {
        'name': 'Content Security Policy (CSP)',
        'severity': Severity.MEDIUM,
        'description': 'CSP header is missing. CSP helps prevent XSS attacks by controlling which resources can be loaded.',
        'remediation': "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'",
        'cwe_id': 'CWE-693',
        'check_https_only': False
    },
    'X-Content-Type-Options': {
        'name': 'X-Content-Type-Options',
        'severity': Severity.LOW,
        'description': 'X-Content-Type-Options header is missing. This header prevents MIME type sniffing attacks.',
        'remediation': "Add header: X-Content-Type-Options: nosniff",
        'cwe_id': 'CWE-693',
        'check_https_only': False,
        'expected_value': 'nosniff'
    },
    'X-Frame-Options': {
        'name': 'X-Frame-Options (Clickjacking Protection)',
        'severity': Severity.MEDIUM,
        'description': 'X-Frame-Options header is missing. This header prevents clickjacking attacks by controlling if the page can be embedded in frames.',
        'remediation': "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        'cwe_id': 'CWE-1021',
        'check_https_only': False,
        'expected_values': ['DENY', 'SAMEORIGIN']
    },
    'X-XSS-Protection': {
        'name': 'X-XSS-Protection',
        'severity': Severity.LOW,
        'description': 'X-XSS-Protection header is missing. While deprecated in modern browsers, it provides protection in older browsers.',
        'remediation': "Add header: X-XSS-Protection: 1; mode=block",
        'cwe_id': 'CWE-79',
        'check_https_only': False
    },
    'Referrer-Policy': {
        'name': 'Referrer-Policy',
        'severity': Severity.LOW,
        'description': 'Referrer-Policy header is missing. This header controls how much referrer information is included with requests.',
        'remediation': "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        'cwe_id': 'CWE-200',
        'check_https_only': False
    },
    'Permissions-Policy': {
        'name': 'Permissions-Policy (Feature-Policy)',
        'severity': Severity.INFO,
        'description': 'Permissions-Policy header is missing. This header controls which browser features can be used.',
        'remediation': "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        'cwe_id': 'CWE-693',
        'check_https_only': False
    },
    'X-Permitted-Cross-Domain-Policies': {
        'name': 'X-Permitted-Cross-Domain-Policies',
        'severity': Severity.INFO,
        'description': 'X-Permitted-Cross-Domain-Policies header is missing. This header controls Adobe Flash and PDF cross-domain requests.',
        'remediation': "Add header: X-Permitted-Cross-Domain-Policies: none",
        'cwe_id': 'CWE-693',
        'check_https_only': False
    }
}

# Dangerous header configurations
DANGEROUS_HEADERS = {
    'Server': {
        'name': 'Server Header Information Disclosure',
        'severity': Severity.LOW,
        'description': 'Server header reveals server software and version information, which could help attackers identify known vulnerabilities.',
        'remediation': 'Remove or minimize the Server header to avoid information disclosure.',
        'cwe_id': 'CWE-200'
    },
    'X-Powered-By': {
        'name': 'X-Powered-By Information Disclosure',
        'severity': Severity.LOW,
        'description': 'X-Powered-By header reveals technology stack information, which could help attackers target known vulnerabilities.',
        'remediation': 'Remove the X-Powered-By header.',
        'cwe_id': 'CWE-200'
    },
    'X-AspNet-Version': {
        'name': 'ASP.NET Version Disclosure',
        'severity': Severity.LOW,
        'description': 'X-AspNet-Version header reveals the ASP.NET version, which could help attackers identify vulnerabilities.',
        'remediation': 'Remove the X-AspNet-Version header.',
        'cwe_id': 'CWE-200'
    }
}


class SecurityHeadersModule(BaseModule):
    """
    Security Headers Detection Module

    Checks for:
    - Missing security headers
    - Misconfigured security headers
    - Information disclosure headers
    """

    name = "Security Headers Scanner"
    description = "Checks for missing or misconfigured security headers"
    vulnerability_type = "headers"
    cwe_id = "CWE-693"
    owasp_category = "A05:2021"

    async def check(self, response, url: str, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Check security headers in HTTP response.

        Args:
            response: HTTP response object
            url: Page URL

        Returns:
            List of VulnerabilityResult objects
        """
        results = []

        if not response or not hasattr(response, 'headers'):
            return results

        headers = response.headers
        is_https = url.startswith('https://')

        # Check for missing security headers
        for header_name, config in SECURITY_HEADERS.items():
            # Skip HTTPS-only checks for HTTP sites
            if config.get('check_https_only') and not is_https:
                continue

            header_value = self._get_header(headers, header_name)

            if not header_value:
                results.append(self.create_vulnerability(
                    name=f"Missing {config['name']}",
                    severity=config['severity'],
                    url=url,
                    description=config['description'],
                    confidence=Confidence.CONFIRMED,
                    cwe_id=config['cwe_id'],
                    remediation=config['remediation'],
                    references=[
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                        "https://securityheaders.com/"
                    ]
                ))
            else:
                # Check for misconfiguration
                misconfig = self._check_misconfiguration(header_name, header_value, config)
                if misconfig:
                    results.append(misconfig)

        # Check for information disclosure headers
        for header_name, config in DANGEROUS_HEADERS.items():
            header_value = self._get_header(headers, header_name)

            if header_value:
                results.append(self.create_vulnerability(
                    name=config['name'],
                    severity=config['severity'],
                    url=url,
                    description=f"{config['description']} Detected value: {header_value}",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"{header_name}: {header_value}",
                    cwe_id=config['cwe_id'],
                    remediation=config['remediation']
                ))

        # Check for insecure cookie settings
        cookie_issues = self._check_cookies(headers, is_https)
        results.extend(cookie_issues)

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """Security headers are checked passively."""
        return []

    def _get_header(self, headers: Dict, name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def _check_misconfiguration(self, header_name: str, value: str, config: Dict) -> Optional[VulnerabilityResult]:
        """Check for header misconfiguration."""
        value_lower = value.lower()

        # X-Content-Type-Options should be 'nosniff'
        if header_name == 'X-Content-Type-Options':
            if value_lower != 'nosniff':
                return self.create_vulnerability(
                    name=f"Misconfigured {config['name']}",
                    severity=Severity.LOW,
                    url='',
                    description=f"X-Content-Type-Options is set to '{value}' instead of 'nosniff'.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"{header_name}: {value}",
                    remediation=config['remediation']
                )

        # X-Frame-Options should be DENY or SAMEORIGIN
        if header_name == 'X-Frame-Options':
            if value_lower not in ['deny', 'sameorigin']:
                return self.create_vulnerability(
                    name=f"Misconfigured {config['name']}",
                    severity=Severity.LOW,
                    url='',
                    description=f"X-Frame-Options is set to '{value}'. Recommended values are DENY or SAMEORIGIN.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"{header_name}: {value}",
                    remediation=config['remediation']
                )

        # HSTS should have reasonable max-age
        if header_name == 'Strict-Transport-Security':
            if 'max-age=' in value_lower:
                try:
                    max_age = int(value_lower.split('max-age=')[1].split(';')[0])
                    if max_age < 31536000:  # Less than 1 year
                        return self.create_vulnerability(
                            name="Weak HSTS Configuration",
                            severity=Severity.LOW,
                            url='',
                            description=f"HSTS max-age is set to {max_age} seconds. Recommended minimum is 31536000 (1 year).",
                            confidence=Confidence.CONFIRMED,
                            evidence=f"{header_name}: {value}",
                            remediation="Increase max-age to at least 31536000 seconds (1 year)."
                        )
                except (ValueError, IndexError):
                    pass

        # CSP with unsafe-inline or unsafe-eval
        if header_name == 'Content-Security-Policy':
            issues = []
            if "'unsafe-inline'" in value_lower:
                issues.append("'unsafe-inline'")
            if "'unsafe-eval'" in value_lower:
                issues.append("'unsafe-eval'")

            if issues:
                return self.create_vulnerability(
                    name="Weak Content Security Policy",
                    severity=Severity.LOW,
                    url='',
                    description=f"CSP contains unsafe directives: {', '.join(issues)}. These weaken XSS protection.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"{header_name}: {self.truncate(value, 200)}",
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes instead."
                )

        return None

    def _check_cookies(self, headers: Dict, is_https: bool) -> List[VulnerabilityResult]:
        """Check for insecure cookie settings."""
        results = []

        set_cookie = self._get_header(headers, 'Set-Cookie')
        if not set_cookie:
            return results

        cookies = set_cookie if isinstance(set_cookie, list) else [set_cookie]

        for cookie in cookies:
            cookie_lower = cookie.lower()

            # Extract cookie name
            cookie_name = cookie.split('=')[0].strip() if '=' in cookie else 'Unknown'

            # Check for missing Secure flag on HTTPS
            if is_https and 'secure' not in cookie_lower:
                results.append(self.create_vulnerability(
                    name="Cookie Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    url='',
                    description=f"Cookie '{cookie_name}' is missing the Secure flag. This allows the cookie to be sent over unencrypted connections.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Set-Cookie: {self.truncate(cookie, 100)}",
                    cwe_id='CWE-614',
                    remediation="Add the 'Secure' flag to all cookies on HTTPS sites."
                ))

            # Check for missing HttpOnly flag
            if 'httponly' not in cookie_lower:
                # More severe for session-like cookies
                severity = Severity.MEDIUM if any(s in cookie_name.lower() for s in ['session', 'auth', 'token']) else Severity.LOW

                results.append(self.create_vulnerability(
                    name="Cookie Missing HttpOnly Flag",
                    severity=severity,
                    url='',
                    description=f"Cookie '{cookie_name}' is missing the HttpOnly flag. This allows JavaScript to access the cookie, increasing XSS risk.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Set-Cookie: {self.truncate(cookie, 100)}",
                    cwe_id='CWE-1004',
                    remediation="Add the 'HttpOnly' flag to prevent JavaScript access to cookies."
                ))

            # Check for missing SameSite attribute
            if 'samesite' not in cookie_lower:
                results.append(self.create_vulnerability(
                    name="Cookie Missing SameSite Attribute",
                    severity=Severity.LOW,
                    url='',
                    description=f"Cookie '{cookie_name}' is missing the SameSite attribute. This may allow CSRF attacks.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Set-Cookie: {self.truncate(cookie, 100)}",
                    cwe_id='CWE-1275',
                    remediation="Add 'SameSite=Lax' or 'SameSite=Strict' to prevent CSRF attacks."
                ))

        return results


# Module interface functions
async def check(response, url: str, *args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = SecurityHeadersModule()
    results = await module.check(response, url, *args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(*args, **kwargs) -> List[Dict]:
    """Active test interface (not applicable for headers)."""
    return []
