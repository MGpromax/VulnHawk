"""
DOM-based XSS Detection Module

Detects DOM XSS vulnerabilities by analyzing JavaScript code for dangerous patterns.
This is a HARD-TO-FIND vulnerability type because:
- No server reflection needed
- Vulnerability exists purely in client-side JavaScript
- Requires static analysis of JS code
"""

import re
from typing import List, Dict, Optional
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


# DOM XSS Sources - where user input comes from
DOM_SOURCES = [
    # URL-based sources
    r'document\.URL',
    r'document\.documentURI',
    r'document\.baseURI',
    r'location\.href',
    r'location\.search',
    r'location\.hash',
    r'location\.pathname',
    r'location\.protocol',
    r'location\.hostname',
    r'window\.name',
    r'document\.referrer',
    r'document\.cookie',

    # URL parameter parsing
    r'URLSearchParams\s*\(',
    r'new\s+URL\s*\(',
    r'\.get\s*\(\s*[\'"]',
    r'\.getAll\s*\(',

    # Storage
    r'localStorage\.getItem',
    r'sessionStorage\.getItem',
    r'localStorage\[',
    r'sessionStorage\[',

    # PostMessage
    r'\.addEventListener\s*\(\s*[\'"]message[\'"]',
    r'event\.data',
    r'e\.data',

    # Form data
    r'\.value(?!\s*=)',  # Reading value, not setting
]

# DOM XSS Sinks - where user input is used dangerously
DOM_SINKS = {
    'critical': [
        # Direct code execution
        (r'eval\s*\(', 'eval() - Direct code execution'),
        (r'Function\s*\(', 'Function() constructor - Code execution'),
        (r'setTimeout\s*\(\s*[^\d]', 'setTimeout() with string - Code execution'),
        (r'setInterval\s*\(\s*[^\d]', 'setInterval() with string - Code execution'),
        (r'new\s+Function\s*\(', 'new Function() - Code execution'),
        (r'execScript\s*\(', 'execScript() - Direct code execution'),
    ],
    'high': [
        # HTML injection
        (r'\.innerHTML\s*=', 'innerHTML assignment - HTML injection'),
        (r'\.outerHTML\s*=', 'outerHTML assignment - HTML injection'),
        (r'document\.write\s*\(', 'document.write() - HTML injection'),
        (r'document\.writeln\s*\(', 'document.writeln() - HTML injection'),
        (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML() - HTML injection'),

        # jQuery dangerous methods
        (r'\$\s*\(\s*[^\)]+\)\.html\s*\(', 'jQuery .html() - HTML injection'),
        (r'\$\s*\(\s*[^\)]+\)\.append\s*\(', 'jQuery .append() - Potential HTML injection'),
        (r'\$\s*\(\s*[^\)]+\)\.prepend\s*\(', 'jQuery .prepend() - Potential HTML injection'),
        (r'\$\s*\(\s*[^\)]+\)\.after\s*\(', 'jQuery .after() - Potential HTML injection'),
        (r'\$\s*\(\s*[^\)]+\)\.before\s*\(', 'jQuery .before() - Potential HTML injection'),
        (r'\$\s*\(\s*[^\)]+\)\.replaceWith\s*\(', 'jQuery .replaceWith() - Potential HTML injection'),
    ],
    'medium': [
        # URL-based sinks
        (r'location\s*=', 'location assignment - Open redirect/XSS'),
        (r'location\.href\s*=', 'location.href assignment - Open redirect/XSS'),
        (r'location\.replace\s*\(', 'location.replace() - Open redirect'),
        (r'location\.assign\s*\(', 'location.assign() - Open redirect'),
        (r'window\.open\s*\(', 'window.open() - Potential XSS in URL'),

        # Attribute manipulation
        (r'\.setAttribute\s*\(\s*[\'"](?:href|src|data|action)[\'"]',
         'setAttribute() on dangerous attribute'),
        (r'\.src\s*=', '.src assignment - Potential script injection'),
        (r'\.href\s*=', '.href assignment - Potential redirect'),

        # DOM creation
        (r'document\.createElement\s*\(\s*[\'"]script[\'"]',
         'Creating script element - Code injection'),
    ],
    'low': [
        # Text content (usually safe but worth noting)
        (r'\.textContent\s*=', 'textContent assignment - Usually safe'),
        (r'\.innerText\s*=', 'innerText assignment - Usually safe'),
    ]
}

# Dangerous patterns combining sources and sinks
DANGEROUS_PATTERNS = [
    # Direct source-to-sink flows
    (r'\.innerHTML\s*=\s*.*location\.hash', 'location.hash to innerHTML'),
    (r'\.innerHTML\s*=\s*.*location\.search', 'location.search to innerHTML'),
    (r'\.innerHTML\s*=\s*.*URLSearchParams', 'URL parameter to innerHTML'),
    (r'document\.write\s*\(.*location', 'location to document.write'),
    (r'eval\s*\(.*location', 'location to eval'),
    (r'eval\s*\(.*URLSearchParams', 'URL parameter to eval'),
    (r'setTimeout\s*\(\s*[\'"]?\s*\+?\s*.*location', 'location to setTimeout string'),

    # jQuery patterns
    (r'\$\s*\([^\)]*location\.hash', 'location.hash in jQuery selector'),
    (r'\$\s*\([^\)]*\)\.html\s*\([^\)]*location', 'location to jQuery .html()'),

    # Prototype pollution patterns
    (r'Object\.assign\s*\([^,]*,\s*JSON\.parse', 'JSON.parse to Object.assign - Prototype pollution'),
    (r'\[key\]\s*=\s*value', 'Dynamic property assignment - Potential prototype pollution'),
    (r'__proto__', '__proto__ reference - Prototype pollution indicator'),
    (r'constructor\.prototype', 'constructor.prototype access - Prototype pollution'),
]


class DOMXSSModule(BaseModule):
    """
    DOM-based XSS Detection Module

    Detects client-side XSS vulnerabilities through static analysis of JavaScript code.
    This finds vulnerabilities that server-side scanners miss because they only
    exist in the browser.
    """

    name = "DOM XSS Scanner"
    description = "Detects DOM-based Cross-Site Scripting vulnerabilities"
    vulnerability_type = "dom_xss"
    cwe_id = "CWE-79"
    owasp_category = "A03:2021"

    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    CVSS_SCORE = 6.1

    def __init__(self):
        super().__init__()
        self._compiled_sources = [re.compile(p, re.IGNORECASE) for p in DOM_SOURCES]
        self._compiled_sinks = {
            severity: [(re.compile(p, re.IGNORECASE), desc) for p, desc in patterns]
            for severity, patterns in DOM_SINKS.items()
        }
        self._compiled_dangerous = [
            (re.compile(p, re.IGNORECASE), desc) for p, desc in DANGEROUS_PATTERNS
        ]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive DOM XSS check - analyze JavaScript for dangerous patterns.
        """
        results = []
        response = kwargs.get('response')
        url = kwargs.get('url', '')

        if not response or not hasattr(response, 'body'):
            return results

        body = response.body

        # Extract JavaScript code from response
        js_code = self._extract_javascript(body)

        if not js_code:
            return results

        # Find sources
        sources_found = self._find_sources(js_code)

        # Find sinks
        sinks_found = self._find_sinks(js_code)

        # Check for direct dangerous patterns (source -> sink)
        dangerous_flows = self._find_dangerous_flows(js_code)

        # Report dangerous flows (highest priority)
        for pattern_desc, match in dangerous_flows:
            results.append(self.create_vulnerability(
                name="DOM-based XSS (Direct Data Flow)",
                severity=Severity.HIGH,
                url=url,
                description=f"Detected dangerous data flow pattern: {pattern_desc}. "
                           f"User-controlled input flows directly into a dangerous sink.",
                confidence=Confidence.HIGH,
                evidence=f"Pattern: {match[:200]}",
                remediation=self._get_remediation(),
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
                ]
            ))

        # Report critical sinks
        for sink_desc, context in sinks_found.get('critical', []):
            results.append(self.create_vulnerability(
                name="DOM XSS Sink (Critical)",
                severity=Severity.HIGH,
                url=url,
                description=f"Critical DOM XSS sink detected: {sink_desc}. "
                           f"If user input reaches this sink, arbitrary code execution is possible.",
                confidence=Confidence.MEDIUM,
                evidence=f"Code: {context[:200]}",
                remediation=self._get_remediation()
            ))

        # Report high severity sinks with sources present
        if sources_found and sinks_found.get('high'):
            for sink_desc, context in sinks_found['high'][:3]:
                results.append(self.create_vulnerability(
                    name="Potential DOM XSS",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"DOM XSS sink ({sink_desc}) found with user input sources present. "
                               f"Manual verification needed to confirm data flow.",
                    confidence=Confidence.LOW,
                    evidence=f"Sources: {', '.join(sources_found[:3])}. Sink: {context[:150]}",
                    remediation=self._get_remediation()
                ))

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        DOM XSS is detected passively through code analysis.
        Active testing would require browser automation.
        """
        return []

    def _extract_javascript(self, html: str) -> str:
        """Extract JavaScript code from HTML."""
        js_parts = []

        # Extract inline scripts
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in script_pattern.finditer(html):
            content = match.group(1).strip()
            if content and not content.startswith('<!--'):
                js_parts.append(content)

        # Extract event handlers
        event_pattern = re.compile(
            r'on\w+\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in event_pattern.finditer(html):
            js_parts.append(match.group(1))

        # Extract javascript: URLs
        js_url_pattern = re.compile(r'javascript:([^"\'>\s]+)', re.IGNORECASE)
        for match in js_url_pattern.finditer(html):
            js_parts.append(match.group(1))

        return '\n'.join(js_parts)

    def _find_sources(self, js_code: str) -> List[str]:
        """Find DOM XSS sources in JavaScript code."""
        sources = []
        for pattern in self._compiled_sources:
            if pattern.search(js_code):
                sources.append(pattern.pattern)
        return sources

    def _find_sinks(self, js_code: str) -> Dict[str, List[tuple]]:
        """Find DOM XSS sinks in JavaScript code."""
        sinks = {'critical': [], 'high': [], 'medium': [], 'low': []}

        for severity, patterns in self._compiled_sinks.items():
            for pattern, description in patterns:
                for match in pattern.finditer(js_code):
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(js_code), match.end() + 100)
                    context = js_code[start:end]
                    sinks[severity].append((description, context))

        return sinks

    def _find_dangerous_flows(self, js_code: str) -> List[tuple]:
        """Find direct source-to-sink data flows."""
        flows = []
        for pattern, description in self._compiled_dangerous:
            for match in pattern.finditer(js_code):
                flows.append((description, match.group(0)))
        return flows

    def _get_remediation(self) -> str:
        """Get remediation guidance for DOM XSS."""
        return """
1. **Avoid Dangerous Sinks**: Never use innerHTML, document.write(), or eval() with user input.

2. **Use Safe APIs**:
   - Use textContent instead of innerHTML
   - Use createElement + appendChild instead of document.write
   - Use JSON.parse instead of eval for JSON

3. **Sanitize Input**: Use DOMPurify or similar library:
   ```javascript
   element.innerHTML = DOMPurify.sanitize(userInput);
   ```

4. **Encode Output**: Properly encode data based on context:
   - HTML entities for HTML context
   - URL encoding for URLs
   - JavaScript encoding for JS strings

5. **Content Security Policy**: Implement strict CSP to prevent inline script execution:
   ```
   Content-Security-Policy: script-src 'self'
   ```

6. **Avoid URL Fragment/Parameter Direct Use**:
   ```javascript
   // BAD
   document.getElementById('msg').innerHTML = location.hash;

   // GOOD
   document.getElementById('msg').textContent = location.hash.substring(1);
   ```
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = DOMXSSModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface - DOM XSS requires passive analysis."""
    return []
