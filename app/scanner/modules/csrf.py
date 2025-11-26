"""
CSRF (Cross-Site Request Forgery) Detection Module

Detects missing or weak CSRF protection in forms.
"""

from typing import List, Dict, Optional
import re
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


# Common CSRF token names
CSRF_TOKEN_NAMES = [
    'csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken',
    '_token', 'token', 'authenticity_token', '_csrf',
    'anti-csrf-token', 'anticsrf', '__requestverificationtoken',
    'xsrf', 'xsrf_token', '_xsrf', 'nonce', '__csrf_magic',
    'csrf-token', 'request_token', 'form_token', 'security_token'
]

# Forms that typically need CSRF protection
SENSITIVE_ACTIONS = [
    'login', 'signin', 'register', 'signup', 'password',
    'delete', 'remove', 'update', 'edit', 'create', 'add',
    'transfer', 'payment', 'checkout', 'settings', 'profile',
    'admin', 'logout', 'signout', 'submit', 'post', 'comment'
]


class CSRFModule(BaseModule):
    """
    CSRF Detection Module

    Detects:
    - Missing CSRF tokens in forms
    - Weak CSRF token patterns
    - State-changing operations without protection
    """

    name = "CSRF Scanner"
    description = "Detects Cross-Site Request Forgery vulnerabilities"
    vulnerability_type = "csrf"
    cwe_id = "CWE-352"
    owasp_category = "A01:2021"

    # CVSS for CSRF
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
    CVSS_SCORE = 6.5

    async def check(self, form, url: str, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Check form for CSRF protection.

        Args:
            form: Parsed form object
            url: Page URL

        Returns:
            List of VulnerabilityResult objects
        """
        results = []

        # Only check POST forms (GET forms don't need CSRF protection)
        if form.method.upper() == 'GET':
            return results

        # Check if form appears to perform sensitive action
        is_sensitive = self._is_sensitive_form(form, url)

        # Check for CSRF token
        has_csrf = self._has_csrf_token(form)

        if not has_csrf:
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            confidence = Confidence.HIGH if is_sensitive else Confidence.MEDIUM

            # Build description based on form type
            if is_sensitive:
                form_type = self._get_form_type(form, url)
                description = (
                    f"A {form_type} form at '{url}' is missing CSRF protection. "
                    f"This form submits to '{form.action}' using {form.method} method. "
                    f"An attacker could craft a malicious page that submits this form on behalf of authenticated users."
                )
            else:
                description = (
                    f"Form at '{url}' is missing CSRF token. "
                    f"Forms that change server state should include CSRF protection."
                )

            results.append(self.create_vulnerability(
                name="Missing CSRF Token",
                severity=severity,
                url=url,
                description=description,
                confidence=confidence,
                parameter="csrf_token",
                method=form.method,
                evidence=self._format_form_evidence(form),
                cvss_vector=self.CVSS_VECTOR,
                cvss_score=self.CVSS_SCORE,
                remediation=self._get_remediation(),
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                ]
            ))

        else:
            # Check for weak CSRF token
            weak_token = self._check_weak_token(form)
            if weak_token:
                results.append(weak_token)

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """CSRF is detected passively by analyzing forms."""
        return []

    def _has_csrf_token(self, form) -> bool:
        """Check if form has a CSRF token."""
        if form.has_csrf_token:
            return True

        # Check all hidden fields for CSRF-like names
        for field in form.fields:
            if field.is_hidden:
                field_name_lower = field.name.lower()
                for csrf_name in CSRF_TOKEN_NAMES:
                    if csrf_name in field_name_lower:
                        return True

                # Check for token-like values (long random strings)
                if field.value and len(field.value) >= 32:
                    if re.match(r'^[a-zA-Z0-9+/=_-]+$', field.value):
                        return True

        return False

    def _is_sensitive_form(self, form, url: str) -> bool:
        """Check if form performs sensitive action."""
        # Check form action URL
        action_lower = form.action.lower()
        for action in SENSITIVE_ACTIONS:
            if action in action_lower:
                return True

        # Check page URL
        url_lower = url.lower()
        for action in SENSITIVE_ACTIONS:
            if action in url_lower:
                return True

        # Check for password fields
        for field in form.fields:
            if field.is_password:
                return True

        # Check field names
        sensitive_fields = ['password', 'email', 'amount', 'account', 'credit', 'ssn']
        for field in form.fields:
            for sensitive in sensitive_fields:
                if sensitive in field.name.lower():
                    return True

        return False

    def _get_form_type(self, form, url: str) -> str:
        """Determine the type of form."""
        action_lower = (form.action + url).lower()

        if 'login' in action_lower or 'signin' in action_lower:
            return 'login'
        elif 'register' in action_lower or 'signup' in action_lower:
            return 'registration'
        elif 'password' in action_lower:
            return 'password change'
        elif 'delete' in action_lower or 'remove' in action_lower:
            return 'deletion'
        elif 'payment' in action_lower or 'checkout' in action_lower:
            return 'payment'
        elif 'transfer' in action_lower:
            return 'money transfer'
        elif 'settings' in action_lower or 'profile' in action_lower:
            return 'settings'
        elif 'admin' in action_lower:
            return 'administrative'

        return 'state-changing'

    def _check_weak_token(self, form) -> Optional[VulnerabilityResult]:
        """Check for weak CSRF token patterns."""
        token_value = form.csrf_token_value

        if not token_value:
            return None

        # Check for predictable patterns
        issues = []

        # Too short
        if len(token_value) < 16:
            issues.append(f"Token is too short ({len(token_value)} chars, recommend 32+)")

        # Sequential or simple patterns
        if re.match(r'^[0-9]+$', token_value):
            issues.append("Token appears to be numeric only")

        if token_value == token_value[::-1]:  # Palindrome
            issues.append("Token is a palindrome (potentially weak)")

        # Common weak tokens
        weak_tokens = ['csrf', 'token', '1234', 'test', 'demo']
        for weak in weak_tokens:
            if weak in token_value.lower():
                issues.append(f"Token contains predictable pattern: '{weak}'")

        if issues:
            return self.create_vulnerability(
                name="Weak CSRF Token",
                severity=Severity.MEDIUM,
                url='',
                description=f"CSRF token appears to be weak or predictable. Issues: {'; '.join(issues)}",
                confidence=Confidence.MEDIUM,
                evidence=f"Token: {self.truncate(token_value, 50)}",
                remediation="Use a cryptographically secure random token generator with at least 128 bits of entropy."
            )

        return None

    def _format_form_evidence(self, form) -> str:
        """Format form details as evidence."""
        fields_info = []
        for field in form.fields[:5]:  # Limit to first 5 fields
            fields_info.append(f"{field.name}({field.field_type})")

        evidence = f"Form action: {form.action}\n"
        evidence += f"Method: {form.method}\n"
        evidence += f"Fields: {', '.join(fields_info)}"

        if len(form.fields) > 5:
            evidence += f" ... and {len(form.fields) - 5} more"

        return evidence

    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return """
1. **Synchronizer Token Pattern**:
   - Generate a unique, random token per session/request
   - Include the token in a hidden form field
   - Validate the token on form submission

2. **Double Submit Cookie**:
   - Set a random value in both a cookie and request parameter
   - Validate that both values match on the server

3. **SameSite Cookie Attribute**:
   - Set SameSite=Strict or SameSite=Lax on session cookies
   - This prevents cookies from being sent with cross-site requests

4. **Framework-Specific Protection**:
   - Django: Use {% csrf_token %} in forms
   - Flask: Use Flask-WTF's csrf_token()
   - Rails: Use authenticity_token
   - Laravel: Use @csrf directive

5. **Custom Headers for AJAX**:
   - Require custom headers (X-Requested-With)
   - These cannot be set by simple cross-origin requests

6. **Re-authentication for Critical Actions**:
   - Require password confirmation for sensitive operations
"""


# Module interface functions
async def check(form, url: str, *args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = CSRFModule()
    results = await module.check(form, url, *args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(*args, **kwargs) -> List[Dict]:
    """Active test interface (not applicable for CSRF)."""
    return []
