"""
Mass Assignment Vulnerability Detection Module

Detects mass assignment/object injection vulnerabilities where
hidden parameters can modify sensitive fields.

This is a HARD-TO-FIND vulnerability because:
- Server accepts parameters that aren't visible in the UI
- Requires knowledge of backend data model
- No obvious error messages indicate the vulnerability
"""

import re
from typing import List, Dict, Optional, Set
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# Common hidden/dangerous parameters to test
DANGEROUS_PARAMS = {
    # Privilege escalation
    'role': ['admin', 'administrator', 'superuser', 'root'],
    'admin': ['1', 'true', 'yes'],
    'is_admin': ['1', 'true', 'yes'],
    'isAdmin': ['1', 'true', 'yes'],
    'is_superuser': ['1', 'true', 'yes'],
    'is_staff': ['1', 'true', 'yes'],
    'permissions': ['*', 'admin', 'all'],
    'privilege': ['admin', 'elevated'],
    'level': ['admin', '0', '999'],
    'user_type': ['admin', 'administrator'],
    'userType': ['admin', 'administrator'],
    'account_type': ['admin', 'premium', 'enterprise'],
    'group': ['admin', 'administrators'],
    'groups': ['admin', 'administrators'],

    # Status manipulation
    'verified': ['1', 'true'],
    'is_verified': ['1', 'true'],
    'email_verified': ['1', 'true'],
    'approved': ['1', 'true'],
    'is_approved': ['1', 'true'],
    'active': ['1', 'true'],
    'is_active': ['1', 'true'],
    'banned': ['0', 'false'],
    'is_banned': ['0', 'false'],
    'locked': ['0', 'false'],

    # Financial manipulation
    'balance': ['999999', '1000000'],
    'credits': ['999999', '1000000'],
    'points': ['999999'],
    'discount': ['100', '99'],
    'price': ['0', '0.01'],
    'amount': ['0', '0.01'],

    # Internal fields
    'id': ['1', '0'],
    'user_id': ['1', '0'],
    'userId': ['1', '0'],
    'created_at': ['2000-01-01'],
    'updated_at': ['2000-01-01'],
    'internal': ['1', 'true'],
    'debug': ['1', 'true'],
    'test': ['1', 'true'],

    # API/Security
    'api_key': ['test123'],
    'apiKey': ['test123'],
    'secret': ['test123'],
    'token': ['admin_token'],
    'access_token': ['admin_token'],
}

# Response patterns indicating successful injection
SUCCESS_PATTERNS = [
    # JSON field presence
    (r'"role"\s*:\s*"admin"', 'role set to admin'),
    (r'"admin"\s*:\s*true', 'admin flag set'),
    (r'"is_admin"\s*:\s*true', 'is_admin set'),
    (r'"isAdmin"\s*:\s*true', 'isAdmin set'),
    (r'"verified"\s*:\s*true', 'verified flag set'),
    (r'"is_verified"\s*:\s*true', 'verified flag set'),
    (r'"permissions"\s*:\s*"admin"', 'admin permissions'),
    (r'"balance"\s*:\s*9999', 'balance modified'),

    # Success messages
    (r'profile\s+updated', 'profile updated'),
    (r'account\s+updated', 'account updated'),
    (r'successfully\s+updated', 'update success'),
    (r'changes\s+saved', 'changes saved'),
]


class MassAssignmentModule(BaseModule):
    """
    Mass Assignment Detection Module

    Detects vulnerabilities where applications accept more parameters
    than intended, allowing attackers to modify sensitive fields like:
    - Admin/role flags
    - Account status
    - Financial fields
    - Internal IDs
    """

    name = "Mass Assignment Scanner"
    description = "Detects Mass Assignment / Object Injection vulnerabilities"
    vulnerability_type = "mass_assignment"
    cwe_id = "CWE-915"
    owasp_category = "A04:2021"

    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"
    CVSS_SCORE = 7.6

    def __init__(self):
        super().__init__()
        self._success_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in SUCCESS_PATTERNS
        ]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive check - analyze forms for potential mass assignment.
        """
        results = []
        response = kwargs.get('response')
        url = kwargs.get('url', '')

        if not response or not hasattr(response, 'body'):
            return results

        # Look for forms that might be vulnerable
        forms = self._find_forms(response.body)

        for form in forms:
            if self._is_registration_or_update_form(form):
                results.append(self.create_vulnerability(
                    name="Potential Mass Assignment Endpoint",
                    severity=Severity.LOW,
                    url=url,
                    description="This form handles user registration or updates and may be "
                               "vulnerable to mass assignment if the server doesn't properly "
                               "whitelist allowed parameters.",
                    confidence=Confidence.LOW,
                    evidence=f"Form action: {form.get('action', 'N/A')}",
                    remediation=self._get_remediation()
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
        Active mass assignment testing - inject hidden parameters.
        """
        results = []

        # Only test POST/PUT/PATCH endpoints (data modification)
        if method.upper() not in ['POST', 'PUT', 'PATCH']:
            return results

        request_method = RequestMethod.POST

        # Get baseline response
        baseline = await requester.get(url, use_cache=True)
        if baseline.error:
            return results

        # Test each dangerous parameter
        for param_name, test_values in DANGEROUS_PARAMS.items():
            for test_value in test_values[:2]:  # Limit tests per param
                try:
                    # Build payload with original + injected parameter
                    response, injected = await requester.test_payload(
                        url=url,
                        parameter=param_name,  # Inject new parameter
                        payload=test_value,
                        method=request_method,
                        original_value=''
                    )

                    if response.error:
                        continue

                    # Check if the parameter was accepted
                    acceptance = self._check_param_accepted(
                        response, param_name, test_value
                    )

                    if acceptance:
                        severity = self._get_severity(param_name)
                        results.append(self.create_vulnerability(
                            name=f"Mass Assignment - {param_name}",
                            severity=severity,
                            url=url,
                            description=f"The server accepted the hidden parameter '{param_name}' "
                                       f"with value '{test_value}'. {acceptance}",
                            confidence=Confidence.MEDIUM,
                            parameter=param_name,
                            method=method,
                            payload=f"{param_name}={test_value}",
                            evidence=acceptance,
                            cvss_vector=self.CVSS_VECTOR,
                            cvss_score=self.CVSS_SCORE,
                            remediation=self._get_remediation(),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_HTTP_Incoming_Requests"
                            ]
                        ).to_dict())

                        # Found vulnerability for this param, move to next
                        break

                except Exception as e:
                    logger.error(f"Error testing mass assignment: {e}")
                    continue

        return results

    def _find_forms(self, html: str) -> List[Dict]:
        """Find forms in HTML."""
        forms = []
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL
        )

        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            form = {
                'html': form_html,
                'action': self._extract_attr(form_html, 'action'),
                'method': self._extract_attr(form_html, 'method'),
            }
            forms.append(form)

        return forms

    def _extract_attr(self, html: str, attr: str) -> str:
        """Extract attribute value from HTML tag."""
        pattern = re.compile(f'{attr}\\s*=\\s*["\']([^"\']*)["\']', re.IGNORECASE)
        match = pattern.search(html)
        return match.group(1) if match else ''

    def _is_registration_or_update_form(self, form: Dict) -> bool:
        """Check if form is for registration or profile update."""
        keywords = [
            'register', 'signup', 'sign-up', 'sign_up',
            'profile', 'update', 'edit', 'settings',
            'account', 'user'
        ]

        action = form.get('action', '').lower()
        html = form.get('html', '').lower()

        for keyword in keywords:
            if keyword in action or keyword in html:
                return True

        return False

    def _check_param_accepted(
            self,
            response,
            param_name: str,
            test_value: str
    ) -> Optional[str]:
        """Check if the injected parameter was accepted."""
        body = response.body if hasattr(response, 'body') else ''

        # Success status codes
        if response.status_code not in [200, 201, 202, 204]:
            return None

        # Check for success patterns
        for pattern, description in self._success_patterns:
            if pattern.search(body):
                return f"Success indicator: {description}"

        # Check if our value appears in response
        if test_value in body:
            return f"Injected value '{test_value}' reflected in response"

        # Check if param name appears in response (often in JSON)
        if f'"{param_name}"' in body:
            return f"Parameter '{param_name}' appears in response"

        # No obvious rejection (error message)
        error_patterns = [
            'invalid parameter', 'unknown field', 'not allowed',
            'forbidden', 'unauthorized', 'access denied'
        ]
        body_lower = body.lower()
        if not any(err in body_lower for err in error_patterns):
            # No rejection message might indicate acceptance
            if len(body) > 100:  # Got a real response
                return "No rejection message - parameter may be accepted"

        return None

    def _get_severity(self, param_name: str) -> Severity:
        """Determine severity based on parameter type."""
        critical_params = ['role', 'admin', 'is_admin', 'isAdmin', 'permissions',
                         'is_superuser', 'privilege']
        high_params = ['balance', 'credits', 'price', 'amount', 'verified',
                      'is_verified', 'approved']

        if param_name in critical_params:
            return Severity.CRITICAL
        elif param_name in high_params:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _get_remediation(self) -> str:
        """Get remediation guidance for mass assignment."""
        return """
1. **Whitelist Allowed Parameters**:
   ```python
   # Python/Flask example
   ALLOWED_PARAMS = ['email', 'name', 'bio']

   def update_profile():
       data = {k: v for k, v in request.form.items() if k in ALLOWED_PARAMS}
       user.update(**data)
   ```

2. **Use DTOs (Data Transfer Objects)**:
   ```python
   # Define exactly what's allowed
   class UserUpdateDTO:
       email: str
       name: str
       bio: str
       # role, is_admin NOT included
   ```

3. **Strong Typing with Pydantic/Marshmallow**:
   ```python
   from pydantic import BaseModel

   class UserUpdate(BaseModel):
       email: str
       name: str

       class Config:
           extra = 'forbid'  # Reject extra fields
   ```

4. **Separate Admin/User Endpoints**:
   - `/api/users/update` - limited params
   - `/api/admin/users/update` - requires admin auth

5. **Input Validation**:
   - Validate each parameter explicitly
   - Reject unknown parameters
   - Log unexpected parameter attempts

6. **Framework-Specific Protections**:
   - Rails: `strong_parameters`
   - Django: `forms` with explicit fields
   - Express: validation middleware
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = MassAssignmentModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = MassAssignmentModule()
    return await module.test(requester, url, parameter, value, method)
