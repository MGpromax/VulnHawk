"""
SSL/TLS Security Check Module

Analyzes SSL/TLS configuration for security issues.
"""

import ssl
import socket
from typing import List, Dict, Optional
from datetime import datetime
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence

logger = logging.getLogger(__name__)


class SSLCheckModule(BaseModule):
    """
    SSL/TLS Security Check Module

    Checks for:
    - Expired certificates
    - Self-signed certificates
    - Weak cipher suites
    - Protocol vulnerabilities
    - Certificate chain issues
    """

    name = "SSL/TLS Scanner"
    description = "Analyzes SSL/TLS security configuration"
    vulnerability_type = "ssl"
    cwe_id = "CWE-295"
    owasp_category = "A02:2021"

    # Weak ciphers
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'ADH'
    ]

    # Deprecated protocols
    DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

    async def check(self, response, url: str, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Check SSL/TLS configuration.

        Args:
            response: HTTP response object
            url: Target URL

        Returns:
            List of VulnerabilityResult objects
        """
        results = []

        if not url.startswith('https://'):
            return results

        # Extract hostname and port
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            # Get SSL certificate info
            cert_info = self._get_certificate_info(hostname, port)

            if cert_info:
                # Check certificate expiration
                expiry_result = self._check_expiration(cert_info, url)
                if expiry_result:
                    results.append(expiry_result)

                # Check certificate validity
                validity_result = self._check_validity(cert_info, hostname, url)
                if validity_result:
                    results.append(validity_result)

            # Check SSL info from response
            if response and hasattr(response, 'ssl_info') and response.ssl_info:
                ssl_info = response.ssl_info

                # Check protocol version
                protocol_result = self._check_protocol(ssl_info, url)
                if protocol_result:
                    results.append(protocol_result)

                # Check cipher
                cipher_result = self._check_cipher(ssl_info, url)
                if cipher_result:
                    results.append(cipher_result)

        except Exception as e:
            logger.error(f"SSL check error: {e}")

        return results

    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """SSL checks are performed passively."""
        return []

    def _get_certificate_info(self, hostname: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Get binary cert if standard fails
                        binary_cert = ssock.getpeercert(binary_form=True)
                        if binary_cert:
                            import ssl
                            cert = ssl._ssl._test_decode_cert(binary_cert)
                    return cert
        except Exception as e:
            logger.debug(f"Could not get certificate: {e}")
            return None

    def _check_expiration(self, cert: Dict, url: str) -> Optional[VulnerabilityResult]:
        """Check certificate expiration."""
        try:
            not_after = cert.get('notAfter')
            if not_after:
                # Parse expiration date
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.utcnow()

                days_until_expiry = (expiry_date - now).days

                if days_until_expiry < 0:
                    return self.create_vulnerability(
                        name="Expired SSL Certificate",
                        severity=Severity.CRITICAL,
                        url=url,
                        description=f"SSL certificate expired {abs(days_until_expiry)} days ago on {expiry_date.strftime('%Y-%m-%d')}.",
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Certificate expired: {not_after}",
                        remediation="Renew the SSL certificate immediately."
                    )
                elif days_until_expiry < 30:
                    return self.create_vulnerability(
                        name="SSL Certificate Expiring Soon",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"SSL certificate will expire in {days_until_expiry} days on {expiry_date.strftime('%Y-%m-%d')}.",
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Certificate expires: {not_after}",
                        remediation="Renew the SSL certificate before expiration."
                    )
        except Exception as e:
            logger.debug(f"Could not check expiration: {e}")

        return None

    def _check_validity(self, cert: Dict, hostname: str, url: str) -> Optional[VulnerabilityResult]:
        """Check certificate validity."""
        try:
            # Check if self-signed (issuer == subject)
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))

            if subject == issuer:
                return self.create_vulnerability(
                    name="Self-Signed SSL Certificate",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="The SSL certificate is self-signed, which browsers will not trust.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Subject and Issuer are identical: {subject.get('commonName', 'Unknown')}",
                    remediation="Obtain a certificate from a trusted Certificate Authority (CA)."
                )

            # Check hostname match
            common_name = subject.get('commonName', '')
            san = cert.get('subjectAltName', [])
            san_names = [name for type_, name in san if type_ == 'DNS']

            all_names = [common_name] + san_names

            hostname_match = False
            for name in all_names:
                if name.startswith('*.'):
                    # Wildcard match
                    if hostname.endswith(name[1:]):
                        hostname_match = True
                        break
                elif name == hostname:
                    hostname_match = True
                    break

            if not hostname_match:
                return self.create_vulnerability(
                    name="SSL Certificate Hostname Mismatch",
                    severity=Severity.HIGH,
                    url=url,
                    description=f"SSL certificate is not valid for hostname '{hostname}'.",
                    confidence=Confidence.CONFIRMED,
                    evidence=f"Certificate names: {', '.join(all_names[:5])}",
                    remediation="Obtain a certificate that includes the correct hostname."
                )

        except Exception as e:
            logger.debug(f"Could not check validity: {e}")

        return None

    def _check_protocol(self, ssl_info: Dict, url: str) -> Optional[VulnerabilityResult]:
        """Check SSL/TLS protocol version."""
        version = ssl_info.get('version', '')

        if version in self.DEPRECATED_PROTOCOLS:
            severity = Severity.HIGH if version in ['SSLv2', 'SSLv3'] else Severity.MEDIUM

            return self.create_vulnerability(
                name=f"Deprecated SSL/TLS Protocol ({version})",
                severity=severity,
                url=url,
                description=f"Server is using deprecated protocol {version} which has known vulnerabilities.",
                confidence=Confidence.CONFIRMED,
                evidence=f"Protocol: {version}",
                remediation=f"Disable {version} and use TLS 1.2 or TLS 1.3."
            )

        return None

    def _check_cipher(self, ssl_info: Dict, url: str) -> Optional[VulnerabilityResult]:
        """Check cipher suite strength."""
        cipher = ssl_info.get('cipher', ())

        if cipher and len(cipher) >= 1:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)

            for weak in self.WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    return self.create_vulnerability(
                        name=f"Weak Cipher Suite ({weak})",
                        severity=Severity.MEDIUM,
                        url=url,
                        description=f"Server is using weak cipher suite containing {weak}.",
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Cipher: {cipher_name}",
                        remediation="Configure server to use only strong cipher suites (AES-GCM, ChaCha20)."
                    )

        return None


# Module interface functions
async def check(response, url: str, *args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = SSLCheckModule()
    results = await module.check(response, url, *args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(*args, **kwargs) -> List[Dict]:
    """Active test interface (not applicable)."""
    return []
