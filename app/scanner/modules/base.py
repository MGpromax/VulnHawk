"""
Base Module for VulnHawk Vulnerability Detection

Provides common functionality for all vulnerability modules.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


class Confidence(Enum):
    """Detection confidence levels."""
    CONFIRMED = 'confirmed'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'


@dataclass
class VulnerabilityResult:
    """
    Represents a discovered vulnerability.
    """
    name: str
    vulnerability_type: str
    severity: Severity
    url: str
    description: str
    confidence: Confidence = Confidence.MEDIUM
    parameter: Optional[str] = None
    method: str = 'GET'
    payload: Optional[str] = None
    evidence: Optional[str] = None
    response_snippet: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'type': self.vulnerability_type,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'description': self.description,
            'payload': self.payload,
            'evidence': self.evidence,
            'response_snippet': self.response_snippet,
            'cvss': {
                'vector': self.cvss_vector,
                'score': self.cvss_score
            },
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'remediation': self.remediation,
            'references': self.references
        }


class BaseModule(ABC):
    """
    Abstract base class for vulnerability detection modules.

    Each module must implement:
    - name: Module name
    - description: Module description
    - check(): For passive analysis
    - test(): For active testing
    """

    name: str = "Base Module"
    description: str = "Base vulnerability detection module"
    vulnerability_type: str = "unknown"
    cwe_id: str = ""
    owasp_category: str = ""

    def __init__(self):
        """Initialize the module."""
        self.logger = logging.getLogger(f"vulnhawk.module.{self.name}")

    @abstractmethod
    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Passive check - analyze without sending attack payloads.

        Returns:
            List of VulnerabilityResult objects
        """
        pass

    @abstractmethod
    async def test(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """
        Active test - send payloads to detect vulnerabilities.

        Returns:
            List of VulnerabilityResult objects
        """
        pass

    def create_vulnerability(
            self,
            name: str,
            severity: Severity,
            url: str,
            description: str,
            **kwargs
    ) -> VulnerabilityResult:
        """
        Helper to create a VulnerabilityResult.

        Args:
            name: Vulnerability name
            severity: Severity level
            url: Affected URL
            description: Description of the issue
            **kwargs: Additional fields

        Returns:
            VulnerabilityResult object
        """
        return VulnerabilityResult(
            name=name,
            vulnerability_type=self.vulnerability_type,
            severity=severity,
            url=url,
            description=description,
            cwe_id=kwargs.get('cwe_id', self.cwe_id),
            owasp_category=kwargs.get('owasp_category', self.owasp_category),
            **{k: v for k, v in kwargs.items() if k not in ['cwe_id', 'owasp_category']}
        )

    @staticmethod
    def truncate(text: str, max_length: int = 500) -> str:
        """Truncate text to maximum length."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + '...'

    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
