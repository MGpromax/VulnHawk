"""
VulnHawk Database Models

Secure database models with proper validation and relationships.
"""

from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.user import User

__all__ = ['Scan', 'ScanStatus', 'Vulnerability', 'Severity', 'User']
