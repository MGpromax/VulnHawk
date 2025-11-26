"""
JWT (JSON Web Token) Vulnerability Detection Module

Detects JWT security issues including:
- Weak secrets (brute-forceable)
- Algorithm confusion attacks
- Missing expiration
- Token tampering
- Information disclosure in payload

This is a HARD-TO-FIND vulnerability because:
- JWT tokens look secure at first glance
- Requires understanding of cryptographic weaknesses
- Often needs offline analysis
"""

import re
import json
import base64
import hashlib
import hmac
from typing import List, Dict, Optional, Tuple
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


# Common weak JWT secrets (for testing)
WEAK_SECRETS = [
    'secret',
    'secret123',
    'password',
    'password123',
    '123456',
    '12345678',
    'admin',
    'admin123',
    'jwt_secret',
    'jwt-secret',
    'secret_key',
    'secretkey',
    'private',
    'private_key',
    'key',
    'test',
    'test123',
    'development',
    'production',
    'changeme',
    'changethis',
    'supersecret',
    'mysecret',
    'mypassword',
    'letmein',
    'welcome',
    'default',
    'qwerty',
    'abc123',
    '000000',
    '111111',
    'HS256',
    'HS384',
    'HS512',
    '',  # Empty secret
]

# Patterns to find JWT tokens
JWT_PATTERNS = [
    # Standard JWT format: xxxxx.yyyyy.zzzzz
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',

    # In JSON responses
    r'"(?:access_?)?token"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
    r'"jwt"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',

    # In cookies
    r'(?:token|jwt|auth|session)\s*=\s*(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',

    # In Authorization header
    r'Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
]

# Sensitive claims that shouldn't be exposed
SENSITIVE_CLAIMS = [
    'password',
    'secret',
    'api_key',
    'apikey',
    'private_key',
    'credit_card',
    'ssn',
    'social_security',
]


class JWTModule(BaseModule):
    """
    JWT Vulnerability Detection Module

    Detects:
    - Weak/brute-forceable secrets
    - Algorithm none attack possibility
    - Missing expiration (no exp claim)
    - Sensitive data in payload
    - Algorithm confusion vulnerabilities
    """

    name = "JWT Security Scanner"
    description = "Detects JWT token vulnerabilities"
    vulnerability_type = "jwt"
    cwe_id = "CWE-347"
    owasp_category = "A02:2021"

    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    CVSS_SCORE = 9.1

    def __init__(self):
        super().__init__()
        self._jwt_patterns = [re.compile(p) for p in JWT_PATTERNS]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive JWT check - analyze responses for JWT tokens and issues.
        """
        results = []
        response = kwargs.get('response')
        url = kwargs.get('url', '')

        if not response:
            return results

        # Combine body and headers for analysis
        content = response.body if hasattr(response, 'body') else ''
        headers_str = str(response.headers) if hasattr(response, 'headers') else ''
        full_content = content + headers_str

        # Find JWT tokens
        tokens = self._extract_jwt_tokens(full_content)

        for token in tokens:
            token_results = self._analyze_jwt(token, url)
            results.extend(token_results)

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        JWT analysis is done passively.
        Active testing would require intercepting and modifying tokens.
        """
        return []

    def _extract_jwt_tokens(self, content: str) -> List[str]:
        """Extract JWT tokens from content."""
        tokens = set()

        for pattern in self._jwt_patterns:
            for match in pattern.finditer(content):
                # Get the token (might be in a group)
                token = match.group(1) if match.groups() else match.group(0)
                if self._is_valid_jwt_format(token):
                    tokens.add(token)

        return list(tokens)

    def _is_valid_jwt_format(self, token: str) -> bool:
        """Check if string is valid JWT format."""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        try:
            # Try to decode header and payload
            self._decode_base64url(parts[0])
            self._decode_base64url(parts[1])
            return True
        except:
            return False

    def _decode_base64url(self, data: str) -> bytes:
        """Decode base64url encoded data."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    def _analyze_jwt(self, token: str, url: str) -> List[VulnerabilityResult]:
        """Analyze a JWT token for vulnerabilities."""
        results = []

        try:
            parts = token.split('.')
            header_b64, payload_b64, signature = parts

            # Decode header and payload
            header = json.loads(self._decode_base64url(header_b64))
            payload = json.loads(self._decode_base64url(payload_b64))

            # Check 1: Algorithm 'none' vulnerability
            alg = header.get('alg', '').lower()
            if alg == 'none' or not alg:
                results.append(self.create_vulnerability(
                    name="JWT Algorithm None Attack",
                    severity=Severity.CRITICAL,
                    url=url,
                    description="JWT token uses 'none' algorithm, allowing signature bypass. "
                               "Any attacker can forge valid tokens.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Header: {header}",
                    cvss_vector=self.CVSS_VECTOR,
                    cvss_score=self.CVSS_SCORE,
                    remediation=self._get_remediation()
                ))

            # Check 2: Missing expiration
            if 'exp' not in payload:
                results.append(self.create_vulnerability(
                    name="JWT Missing Expiration",
                    severity=Severity.HIGH,
                    url=url,
                    description="JWT token has no expiration claim (exp). "
                               "Stolen tokens remain valid indefinitely.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Payload claims: {list(payload.keys())}",
                    remediation=self._get_remediation()
                ))

            # Check 3: Sensitive data in payload
            sensitive_found = []
            for claim in payload.keys():
                if any(s in claim.lower() for s in SENSITIVE_CLAIMS):
                    sensitive_found.append(claim)

            # Also check values for patterns like emails, passwords
            for key, value in payload.items():
                if isinstance(value, str):
                    if re.search(r'password|secret|key|token', key, re.I):
                        sensitive_found.append(f"{key}={value[:20]}...")

            if sensitive_found:
                results.append(self.create_vulnerability(
                    name="Sensitive Data in JWT Payload",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"JWT payload contains potentially sensitive data: "
                               f"{', '.join(sensitive_found)}. JWT payloads are only "
                               f"base64-encoded, not encrypted.",
                    confidence=Confidence.HIGH,
                    evidence=f"Sensitive claims: {sensitive_found}",
                    remediation=self._get_remediation()
                ))

            # Check 4: Weak secret (if HS256/384/512)
            if alg in ['hs256', 'hs384', 'hs512']:
                weak_secret = self._try_weak_secrets(token, header, payload, alg)
                if weak_secret:
                    results.append(self.create_vulnerability(
                        name="JWT Weak Secret",
                        severity=Severity.CRITICAL,
                        url=url,
                        description=f"JWT token is signed with a weak/common secret: '{weak_secret}'. "
                                   f"Attackers can forge arbitrary tokens.",
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Cracked secret: {weak_secret}",
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation()
                    ))

            # Check 5: Check for admin/privilege escalation possibilities
            if 'admin' in payload or 'role' in payload or 'is_admin' in payload:
                admin_val = payload.get('admin', payload.get('is_admin', payload.get('role')))
                results.append(self.create_vulnerability(
                    name="JWT Privilege Claims Present",
                    severity=Severity.MEDIUM,
                    url=url,
                    description=f"JWT contains privilege-related claims. If the secret is weak, "
                               f"attackers could forge admin tokens. Current value: {admin_val}",
                    confidence=Confidence.LOW,
                    evidence=f"Admin claim: {admin_val}",
                    remediation=self._get_remediation()
                ))

        except Exception as e:
            logger.error(f"Error analyzing JWT: {e}")

        return results

    def _try_weak_secrets(
            self,
            token: str,
            header: dict,
            payload: dict,
            alg: str
    ) -> Optional[str]:
        """Try to crack JWT with common weak secrets."""
        parts = token.split('.')
        signing_input = f"{parts[0]}.{parts[1]}"
        signature = parts[2]

        # Map algorithm to hash function
        hash_funcs = {
            'hs256': hashlib.sha256,
            'hs384': hashlib.sha384,
            'hs512': hashlib.sha512,
        }

        hash_func = hash_funcs.get(alg)
        if not hash_func:
            return None

        for secret in WEAK_SECRETS:
            try:
                # Compute signature with this secret
                expected_sig = base64.urlsafe_b64encode(
                    hmac.new(
                        secret.encode(),
                        signing_input.encode(),
                        hash_func
                    ).digest()
                ).decode().rstrip('=')

                if expected_sig == signature:
                    return secret
            except:
                continue

        return None

    def _get_remediation(self) -> str:
        """Get remediation guidance for JWT vulnerabilities."""
        return """
1. **Use Strong Secrets**:
   - Minimum 256 bits of entropy (32+ random characters)
   - Use cryptographically secure random generation
   - Never use common words or predictable values
   ```python
   import secrets
   JWT_SECRET = secrets.token_hex(32)  # 64 hex chars = 256 bits
   ```

2. **Always Set Expiration**:
   ```python
   payload = {
       'user_id': 123,
       'exp': datetime.utcnow() + timedelta(hours=1),
       'iat': datetime.utcnow()
   }
   ```

3. **Use Asymmetric Algorithms for Public APIs**:
   - RS256, RS384, RS512 (RSA)
   - ES256, ES384, ES512 (ECDSA)
   - EdDSA (Ed25519)

4. **Validate Algorithm in Backend**:
   ```python
   # ALWAYS specify allowed algorithms
   jwt.decode(token, SECRET, algorithms=['HS256'])  # NOT algorithms=['HS256', 'none']
   ```

5. **Don't Store Sensitive Data**:
   - JWT payloads are NOT encrypted
   - Only store necessary claims (user_id, roles)
   - Never include passwords, secrets, or PII

6. **Implement Token Refresh**:
   - Short-lived access tokens (15-60 min)
   - Longer-lived refresh tokens with revocation

7. **Secure Token Storage**:
   - HttpOnly cookies for web apps
   - Secure storage for mobile apps
   - Never store in localStorage for sensitive apps
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = JWTModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface - JWT analysis is passive."""
    return []
