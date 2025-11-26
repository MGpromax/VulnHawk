"""
XSS (Cross-Site Scripting) Detection Module

Detects reflected and DOM-based XSS vulnerabilities.
"""

import re
import html
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# XSS Payloads - carefully crafted for detection with minimal false positives
XSS_PAYLOADS = [
    # Basic script injection
    '<script>alert("VH1")</script>',
    '<script>alert(1)</script>',

    # Event handlers
    '<img src=x onerror=alert("VH2")>',
    '<svg onload=alert("VH3")>',
    '<body onload=alert("VH4")>',
    '<input onfocus=alert("VH5") autofocus>',
    '<marquee onstart=alert("VH6")>',
    '<video><source onerror=alert("VH7")>',

    # Encoded variants
    '<img src=x onerror=alert&#40;1&#41;>',
    '<svg/onload=alert(1)>',
    '<img src=x onerror="alert(1)">',

    # JavaScript protocol
    'javascript:alert("VH8")',
    'java\nscript:alert("VH9")',

    # Template injection
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',

    # Breaking out of attributes
    '"><script>alert("VH10")</script>',
    "'-alert(1)-'",
    '"><img src=x onerror=alert(1)>',

    # Unicode/encoding bypass
    '<script>alert(String.fromCharCode(86,72))</script>',

    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
]

# Patterns to detect XSS in response
XSS_DETECTION_PATTERNS = [
    # Script tags
    r'<script[^>]*>.*?alert\s*\([^)]*VH\d+[^)]*\).*?</script>',
    r'<script[^>]*>.*?alert\s*\(\s*[\'"]?1[\'"]?\s*\).*?</script>',

    # Event handlers with our payload
    r'onerror\s*=\s*["\']?alert\s*\([^)]*\)',
    r'onload\s*=\s*["\']?alert\s*\([^)]*\)',
    r'onfocus\s*=\s*["\']?alert\s*\([^)]*\)',
    r'onclick\s*=\s*["\']?alert\s*\([^)]*\)',
    r'onmouseover\s*=\s*["\']?alert\s*\([^)]*\)',

    # SVG/IMG with events
    r'<svg[^>]*onload\s*=',
    r'<img[^>]*onerror\s*=',

    # JavaScript protocol
    r'javascript\s*:\s*alert',
]


class XSSModule(BaseModule):
    """
    XSS Detection Module

    Detects:
    - Reflected XSS
    - DOM-based XSS
    - Stored XSS indicators
    """

    name = "XSS Scanner"
    description = "Detects Cross-Site Scripting vulnerabilities"
    vulnerability_type = "xss"
    cwe_id = "CWE-79"
    owasp_category = "A03:2021"

    # CVSS for reflected XSS
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    CVSS_SCORE = 6.1

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive XSS check - look for dangerous patterns in responses.

        This doesn't inject payloads, just analyzes existing content.
        """
        results = []

        # Check for DOM-based XSS sources and sinks
        response = kwargs.get('response')
        url = kwargs.get('url', '')

        if response and hasattr(response, 'body'):
            # Check for dangerous JavaScript patterns
            dangerous_patterns = [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'\.html\s*\(',  # jQuery
                r'eval\s*\(',
                r'setTimeout\s*\([\'"]',
                r'setInterval\s*\([\'"]',
                r'document\.location\s*=',
                r'window\.location\s*=',
                r'location\.href\s*=',
            ]

            dom_sinks = []
            for pattern in dangerous_patterns:
                if re.search(pattern, response.body, re.IGNORECASE):
                    dom_sinks.append(pattern)

            if dom_sinks:
                results.append(self.create_vulnerability(
                    name="Potential DOM-based XSS",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"Page contains potentially dangerous JavaScript patterns that could lead to DOM-based XSS: {', '.join(dom_sinks[:3])}",
                    confidence=Confidence.LOW,
                    evidence=f"Found DOM sinks: {', '.join(dom_sinks)}",
                    remediation="Review JavaScript code for unsafe DOM manipulation. Use textContent instead of innerHTML, avoid eval(), and sanitize user input before using it in DOM operations."
                ))

        return results

    async def test(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: str = 'GET'
    ) -> List[VulnerabilityResult]:
        """
        Active XSS testing - inject payloads and check for reflection.

        Args:
            requester: HTTP requester
            url: Target URL
            parameter: Parameter to test
            original_value: Original parameter value
            method: HTTP method

        Returns:
            List of XSS vulnerabilities found
        """
        results = []
        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        for payload in XSS_PAYLOADS[:10]:  # Test top 10 payloads
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

                # Check if payload is reflected
                if self._is_xss_detected(response.body, payload):
                    # Determine confidence based on reflection type
                    confidence = self._determine_confidence(response.body, payload)

                    vuln = self.create_vulnerability(
                        name="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH if confidence == Confidence.CONFIRMED else Severity.MEDIUM,
                        url=url,
                        description=f"The parameter '{parameter}' is vulnerable to reflected XSS. "
                                    f"The injected payload was reflected in the response without proper encoding.",
                        confidence=confidence,
                        parameter=parameter,
                        method=method,
                        payload=payload,
                        evidence=self._extract_evidence(response.body, payload),
                        response_snippet=self.truncate(response.body, 500),
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ]
                    )

                    results.append(vuln.to_dict())

                    # One confirmed XSS is enough per parameter
                    if confidence == Confidence.CONFIRMED:
                        break

            except Exception as e:
                logger.error(f"Error testing XSS payload: {e}")
                continue

        return results

    def _is_xss_detected(self, body: str, payload: str) -> bool:
        """Check if XSS payload was reflected in response."""
        body_lower = body.lower()

        # Check for exact payload reflection
        if payload.lower() in body_lower:
            return True

        # Check for detection patterns
        for pattern in XSS_DETECTION_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return True

        # Check for unencoded dangerous characters from our payload
        if '<script' in body_lower and 'alert' in body_lower:
            return True

        if 'onerror=' in body_lower and 'alert' in body_lower:
            return True

        return False

    def _determine_confidence(self, body: str, payload: str) -> Confidence:
        """Determine confidence level of XSS detection."""
        # High confidence if payload is reflected exactly
        if payload in body:
            # Check if it's inside a script tag or event handler
            if re.search(r'<script[^>]*>' + re.escape(payload), body, re.IGNORECASE):
                return Confidence.CONFIRMED
            if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload), body, re.IGNORECASE):
                return Confidence.CONFIRMED
            return Confidence.HIGH

        # Medium confidence if partially reflected
        if 'alert' in body.lower() and ('VH' in body or 'onerror' in body.lower()):
            return Confidence.MEDIUM

        return Confidence.LOW

    def _extract_evidence(self, body: str, payload: str) -> str:
        """Extract evidence showing where XSS was reflected."""
        # Find the payload or alert pattern in body
        payload_lower = payload.lower()
        body_lower = body.lower()

        idx = body_lower.find(payload_lower[:20])
        if idx == -1:
            idx = body_lower.find('alert')

        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(body), idx + len(payload) + 50)
            return f"...{body[start:end]}..."

        return "Payload reflected in response"

    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return """
1. **Output Encoding**: Always encode user input before rendering in HTML:
   - HTML entity encoding for HTML context
   - JavaScript encoding for JavaScript context
   - URL encoding for URL parameters

2. **Content Security Policy (CSP)**: Implement a strict CSP header:
   - `Content-Security-Policy: default-src 'self'; script-src 'self'`

3. **Input Validation**: Validate and sanitize all user inputs:
   - Whitelist allowed characters
   - Reject or encode dangerous characters (<, >, ", ', &)

4. **Use Security Libraries**:
   - DOMPurify for client-side sanitization
   - OWASP Java Encoder for server-side
   - Bleach for Python

5. **HTTPOnly Cookies**: Set HTTPOnly flag on session cookies to prevent JavaScript access.
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = XSSModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = XSSModule()
    return await module.test(requester, url, parameter, value, method)
