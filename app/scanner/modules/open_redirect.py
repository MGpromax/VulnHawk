"""
Open Redirect Detection Module

Detects open redirect vulnerabilities that can be used for phishing.
"""

import re
from typing import List, Dict
from urllib.parse import urlparse, urljoin
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# Open Redirect Payloads
REDIRECT_PAYLOADS = [
    # Basic external redirects
    'https://evil.com',
    '//evil.com',
    'https://evil.com/',

    # Protocol-relative
    '//evil.com',
    '\\/\\/evil.com',

    # Bypass attempts
    'https://evil.com@legitimate.com',
    'https://legitimate.com.evil.com',
    '//evil.com/legitimate.com',

    # Encoded
    'https:%2F%2Fevil.com',
    '%2F%2Fevil.com',
    '//evil%2Ecom',

    # With paths
    'https://evil.com/path',
    '//evil.com/path?foo=bar',

    # JavaScript (might cause redirect)
    'javascript:alert(1)',

    # Double URL encoding
    '%252F%252Fevil.com',

    # Mixed case
    'HTTPS://evil.com',
    '//EVIL.COM',

    # Backslash
    '\\evil.com',
    '\\/evil.com',

    # Data URI
    'data:text/html,<script>alert(1)</script>',
]

# Parameters commonly vulnerable to open redirect
REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_url', 'redirect_uri',
    'return', 'return_url', 'returnurl', 'return_to',
    'next', 'next_url', 'destination', 'dest', 'redir',
    'goto', 'target', 'link', 'continue', 'callback',
    'forward', 'forward_url', 'out', 'view', 'ref',
    'site', 'login_url', 'logout', 'checkout_url'
]


class OpenRedirectModule(BaseModule):
    """
    Open Redirect Detection Module

    Detects:
    - URL-based open redirects
    - Header-based open redirects
    - JavaScript-based redirects
    """

    name = "Open Redirect Scanner"
    description = "Detects Open Redirect vulnerabilities"
    vulnerability_type = "open_redirect"
    cwe_id = "CWE-601"
    owasp_category = "A01:2021"

    # CVSS for Open Redirect
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    CVSS_SCORE = 6.1

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """Open redirect requires active testing."""
        return []

    async def test(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: str = 'GET'
    ) -> List[VulnerabilityResult]:
        """
        Test for open redirect vulnerability.

        Args:
            requester: HTTP requester
            url: Target URL
            parameter: Parameter to test
            original_value: Original parameter value
            method: HTTP method

        Returns:
            List of open redirect vulnerabilities found
        """
        results = []

        # Only test parameters that look like redirect parameters
        param_lower = parameter.lower()
        is_redirect_param = any(rp in param_lower for rp in REDIRECT_PARAMS)

        # Also check if original value looks like a URL
        is_url_value = original_value.startswith(('http', '/', '//'))

        if not is_redirect_param and not is_url_value:
            return results

        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        for payload in REDIRECT_PAYLOADS[:8]:  # Test top payloads
            try:
                response, injected = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method=request_method,
                    original_value=''
                )

                if response.error:
                    continue

                # Check for redirect
                is_vulnerable, evidence = self._check_redirect(response, payload)

                if is_vulnerable:
                    vuln = self.create_vulnerability(
                        name="Open Redirect",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=(
                            f"The parameter '{parameter}' is vulnerable to open redirect. "
                            f"An attacker can redirect users to malicious websites for phishing attacks."
                        ),
                        confidence=Confidence.HIGH,
                        parameter=parameter,
                        method=method,
                        payload=payload,
                        evidence=evidence,
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation(),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                        ]
                    )

                    results.append(vuln.to_dict())
                    break  # One finding per parameter

            except Exception as e:
                logger.error(f"Error testing open redirect: {e}")
                continue

        return results

    def _check_redirect(self, response, payload: str) -> tuple:
        """Check if response indicates successful redirect."""
        # Check HTTP redirect status
        if response.status in (301, 302, 303, 307, 308):
            location = response.headers.get('Location', '')

            # Check if Location header contains our payload domain
            if 'evil.com' in location.lower():
                return True, f"Redirect to: {location}"

            # Check for partial payload in Location
            payload_domain = self._extract_domain(payload)
            if payload_domain and payload_domain in location:
                return True, f"Redirect to: {location}"

        # Check for redirect URL in response body
        if response.redirect_url:
            if 'evil.com' in response.redirect_url.lower():
                return True, f"Redirected to: {response.redirect_url}"

        # Check for meta refresh or JavaScript redirect in body
        body_lower = response.body.lower()

        if 'evil.com' in body_lower:
            # Check for meta refresh
            if 'http-equiv="refresh"' in body_lower or "http-equiv='refresh'" in body_lower:
                return True, "Meta refresh redirect to external domain"

            # Check for JavaScript redirect
            js_patterns = [
                'window.location',
                'document.location',
                'location.href',
                'location.replace'
            ]
            for pattern in js_patterns:
                if pattern in body_lower:
                    return True, f"JavaScript redirect using {pattern}"

        return False, ""

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            # Handle protocol-relative URLs
            if url.startswith('//'):
                url = 'https:' + url

            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""

    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return """
1. **Whitelist Allowed Domains**:
   - Maintain a list of allowed redirect domains
   - Validate redirect URL against whitelist

2. **Use Indirect References**:
   - Map user input to predefined redirect targets
   - Never use user input directly as redirect URL

3. **Validate URL Structure**:
   - Ensure redirect URL is relative (starts with /)
   - Block absolute URLs and protocol-relative URLs (//)

4. **Warning Page**:
   - Show a warning page before redirecting to external sites
   - Require user confirmation for external redirects

5. **Encode/Sign Redirect URLs**:
   - Use signed tokens for redirect URLs
   - Validate signature before redirecting

Example validation:
```python
ALLOWED_DOMAINS = ['example.com', 'trusted.com']

def is_safe_redirect(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)

    # Allow relative URLs
    if not parsed.netloc:
        return True

    # Check against whitelist
    return parsed.netloc in ALLOWED_DOMAINS
```
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    return []


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = OpenRedirectModule()
    return await module.test(requester, url, parameter, value, method)
