"""
IDOR (Insecure Direct Object Reference) Detection Module

Detects IDOR vulnerabilities by testing for unauthorized access to objects.
This is a HARD-TO-FIND vulnerability type because:
- Requires understanding of authorization context
- Often returns valid responses even when vulnerable
- Needs comparison between different user contexts
"""

import re
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# Patterns that indicate ID parameters
ID_PATTERNS = [
    r'id',
    r'user_?id',
    r'account_?id',
    r'profile_?id',
    r'order_?id',
    r'document_?id',
    r'file_?id',
    r'record_?id',
    r'item_?id',
    r'product_?id',
    r'customer_?id',
    r'invoice_?id',
    r'transaction_?id',
    r'report_?id',
    r'message_?id',
    r'comment_?id',
    r'post_?id',
    r'ref',
    r'uid',
    r'pid',
    r'oid',
    r'num',
    r'number',
    r'key',
    r'token',
]

# Patterns in URLs that suggest IDOR-vulnerable endpoints
IDOR_URL_PATTERNS = [
    r'/api/v\d+/users?/\d+',
    r'/api/v\d+/accounts?/\d+',
    r'/api/v\d+/profiles?/\d+',
    r'/api/v\d+/orders?/\d+',
    r'/api/v\d+/documents?/\d+',
    r'/api/v\d+/files?/\d+',
    r'/api/v\d+/records?/\d+',
    r'/users?/\d+',
    r'/accounts?/\d+',
    r'/profiles?/\d+',
    r'/orders?/\d+',
    r'/download/\d+',
    r'/view/\d+',
    r'/edit/\d+',
    r'/delete/\d+',
    r'/admin/users?/\d+',
    r'/my/\w+/\d+',
]

# Sensitive data patterns in response
SENSITIVE_DATA_PATTERNS = [
    # Personal info
    (r'email["\s:]+["\']?[\w.-]+@[\w.-]+\.[a-z]{2,}', 'Email address'),
    (r'phone["\s:]+["\']?[\d\s\-\+\(\)]{10,}', 'Phone number'),
    (r'ssn["\s:]+["\']?\d{3}-?\d{2}-?\d{4}', 'Social Security Number'),
    (r'credit_?card["\s:]+["\']?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}', 'Credit card'),

    # Authentication data
    (r'password["\s:]+["\'][^"\']+["\']', 'Password'),
    (r'api_?key["\s:]+["\'][^"\']+["\']', 'API Key'),
    (r'secret["\s:]+["\'][^"\']+["\']', 'Secret'),
    (r'token["\s:]+["\'][^"\']+["\']', 'Token'),
    (r'auth["\s:]+["\'][^"\']+["\']', 'Auth data'),

    # Financial
    (r'salary["\s:]+["\']?\d+', 'Salary'),
    (r'balance["\s:]+["\']?\d+', 'Account balance'),
    (r'income["\s:]+["\']?\d+', 'Income'),

    # Internal info
    (r'internal_?id["\s:]+', 'Internal ID'),
    (r'admin["\s:]+true', 'Admin flag'),
    (r'role["\s:]+["\']?admin', 'Admin role'),
    (r'is_?admin["\s:]+', 'Admin status'),
]


class IDORModule(BaseModule):
    """
    IDOR Detection Module

    Detects Insecure Direct Object Reference vulnerabilities by:
    1. Identifying endpoints with ID parameters
    2. Testing with modified IDs
    3. Analyzing responses for sensitive data exposure
    4. Detecting missing authorization checks
    """

    name = "IDOR Scanner"
    description = "Detects Insecure Direct Object Reference vulnerabilities"
    vulnerability_type = "idor"
    cwe_id = "CWE-639"
    owasp_category = "A01:2021"

    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    CVSS_SCORE = 8.1

    def __init__(self):
        super().__init__()
        self._id_patterns = [re.compile(f'^{p}$', re.IGNORECASE) for p in ID_PATTERNS]
        self._url_patterns = [re.compile(p, re.IGNORECASE) for p in IDOR_URL_PATTERNS]
        self._sensitive_patterns = [
            (re.compile(p, re.IGNORECASE), desc) for p, desc in SENSITIVE_DATA_PATTERNS
        ]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive IDOR check - analyze URLs and responses for potential IDOR.
        """
        results = []
        response = kwargs.get('response')
        url = kwargs.get('url', '')

        if not response or not hasattr(response, 'body'):
            return results

        # Check if URL matches IDOR-vulnerable patterns
        for pattern in self._url_patterns:
            if pattern.search(url):
                # Check response for sensitive data
                sensitive_found = self._find_sensitive_data(response.body)

                if sensitive_found:
                    results.append(self.create_vulnerability(
                        name="Potential IDOR Endpoint",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"This endpoint follows a pattern commonly vulnerable to IDOR "
                                   f"and exposes sensitive data: {', '.join(sensitive_found[:3])}",
                        confidence=Confidence.LOW,
                        evidence=f"Sensitive data types found: {', '.join(sensitive_found)}",
                        remediation=self._get_remediation()
                    ))
                    break

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
        Active IDOR testing - modify IDs and check for unauthorized access.
        """
        results = []
        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        # Check if parameter is an ID
        if not self._is_id_parameter(parameter):
            return results

        # Get baseline response
        baseline = await requester.get(url, use_cache=True)
        if baseline.error:
            return results

        # Try to parse original value as number
        test_values = self._generate_test_ids(original_value)

        for test_value in test_values:
            try:
                response, injected = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=str(test_value),
                    method=request_method,
                    original_value=original_value
                )

                if response.error or response.status_code in [401, 403, 404]:
                    continue

                # Check if we got a valid response with different data
                if response.status_code == 200:
                    # Compare responses
                    is_different = self._responses_differ_significantly(
                        baseline.body, response.body
                    )

                    # Check for sensitive data in response
                    sensitive_data = self._find_sensitive_data(response.body)

                    if is_different and sensitive_data:
                        return [self.create_vulnerability(
                            name="Insecure Direct Object Reference (IDOR)",
                            severity=Severity.HIGH,
                            url=url,
                            description=f"The parameter '{parameter}' is vulnerable to IDOR. "
                                       f"Changing the ID from '{original_value}' to '{test_value}' "
                                       f"returned different user data without proper authorization.",
                            confidence=Confidence.HIGH,
                            parameter=parameter,
                            method=method,
                            payload=str(test_value),
                            evidence=f"Sensitive data exposed: {', '.join(sensitive_data[:5])}",
                            cvss_vector=self.CVSS_VECTOR,
                            cvss_score=self.CVSS_SCORE,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                            ]
                        ).to_dict()]

            except Exception as e:
                logger.error(f"Error testing IDOR: {e}")
                continue

        # Also test URL path segments
        path_idor_result = await self._test_path_idor(requester, url)
        if path_idor_result:
            results.append(path_idor_result.to_dict())

        return results

    async def _test_path_idor(self, requester: AsyncRequester, url: str) -> Optional[VulnerabilityResult]:
        """Test for IDOR in URL path segments like /api/users/123"""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')

        for i, part in enumerate(path_parts):
            if part.isdigit():
                original_id = int(part)

                # Try adjacent IDs
                test_ids = [original_id + 1, original_id - 1, 1, 2]

                for test_id in test_ids:
                    if test_id <= 0 or test_id == original_id:
                        continue

                    # Build new URL with modified ID
                    new_parts = path_parts.copy()
                    new_parts[i] = str(test_id)
                    new_path = '/'.join(new_parts)
                    new_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))

                    try:
                        response = await requester.get(new_url)

                        if response.error or response.status_code in [401, 403, 404]:
                            continue

                        if response.status_code == 200:
                            sensitive_data = self._find_sensitive_data(response.body)

                            if sensitive_data:
                                return self.create_vulnerability(
                                    name="IDOR in URL Path",
                                    severity=Severity.HIGH,
                                    url=url,
                                    description=f"URL path contains ID that can be modified. "
                                               f"Changed '{original_id}' to '{test_id}' and "
                                               f"accessed different user's data.",
                                    confidence=Confidence.HIGH,
                                    payload=new_url,
                                    evidence=f"Sensitive data: {', '.join(sensitive_data[:3])}",
                                    cvss_vector=self.CVSS_VECTOR,
                                    cvss_score=self.CVSS_SCORE,
                                    remediation=self._get_remediation()
                                )
                    except Exception as e:
                        logger.error(f"Error testing path IDOR: {e}")
                        continue

        return None

    def _is_id_parameter(self, param: str) -> bool:
        """Check if parameter name suggests it's an ID."""
        for pattern in self._id_patterns:
            if pattern.match(param):
                return True
        return False

    def _generate_test_ids(self, original_value: str) -> List:
        """Generate test IDs based on original value."""
        test_values = []

        try:
            original_int = int(original_value)
            # Adjacent IDs
            test_values.extend([original_int + 1, original_int - 1])
            # Common IDs
            test_values.extend([1, 2, 0, -1])
            # Remove original and invalid values
            test_values = [v for v in test_values if v != original_int and v > 0]
        except ValueError:
            # Non-numeric ID (UUID, etc.)
            # Try some common test values
            test_values = ['1', '2', 'admin', 'test', '00000000-0000-0000-0000-000000000001']

        return test_values[:5]  # Limit tests

    def _responses_differ_significantly(self, body1: str, body2: str) -> bool:
        """Check if two responses differ significantly (different data)."""
        # Quick length check
        len_diff = abs(len(body1) - len(body2))
        if len_diff < 10:
            return False

        # Content similarity check
        if body1 == body2:
            return False

        # Check if it's just pagination or timestamp differences
        # vs actual different object data
        return True

    def _find_sensitive_data(self, body: str) -> List[str]:
        """Find sensitive data patterns in response."""
        sensitive_found = []
        for pattern, description in self._sensitive_patterns:
            if pattern.search(body):
                sensitive_found.append(description)
        return list(set(sensitive_found))

    def _get_remediation(self) -> str:
        """Get remediation guidance for IDOR."""
        return """
1. **Implement Proper Authorization Checks**:
   ```python
   # Always verify the user owns the requested resource
   def get_order(order_id, current_user):
       order = Order.query.get(order_id)
       if order.user_id != current_user.id:
           abort(403)  # Forbidden
       return order
   ```

2. **Use Indirect References**:
   - Map internal IDs to user-specific tokens
   - Use UUIDs instead of sequential integers

3. **Access Control Lists (ACL)**:
   - Implement role-based access control
   - Check permissions at every access point

4. **Avoid Exposing Internal IDs**:
   - Use random, unpredictable identifiers
   - Hash or encrypt object references

5. **Audit Logging**:
   - Log all access attempts
   - Monitor for enumeration attacks

6. **Rate Limiting**:
   - Limit requests to prevent ID enumeration
   - Implement CAPTCHA for suspicious activity
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = IDORModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = IDORModule()
    return await module.test(requester, url, parameter, value, method)
