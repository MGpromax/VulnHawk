"""
Scan Model for VulnHawk

Represents a vulnerability scan with its configuration and results.
"""

from datetime import datetime
from enum import Enum
from app import db
import json


class ScanStatus(Enum):
    """Scan status enumeration."""
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class Scan(db.Model):
    """
    Scan model representing a vulnerability assessment.

    Stores scan configuration, progress, and results summary.
    """

    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, index=True)  # UUID

    # Target information
    target_url = db.Column(db.String(2048), nullable=False)
    target_domain = db.Column(db.String(255), nullable=False, index=True)

    # Scan configuration (stored as JSON)
    _config = db.Column('config', db.Text, nullable=False, default='{}')

    # Status tracking
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_task = db.Column(db.String(255), nullable=True)

    # Statistics
    urls_scanned = db.Column(db.Integer, default=0)
    forms_found = db.Column(db.Integer, default=0)
    parameters_tested = db.Column(db.Integer, default=0)

    # Results summary
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)

    # Timing
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Real-time progress tracking
    current_phase = db.Column(db.String(50), default='pending')  # pending, crawling, passive_analysis, active_testing, finalizing, completed, failed
    elapsed_seconds = db.Column(db.Float, default=0.0)
    estimated_remaining_seconds = db.Column(db.Float, default=0.0)
    items_per_second_rate = db.Column(db.Float, default=0.0)  # EMA-smoothed rate

    # Error tracking
    error_message = db.Column(db.Text, nullable=True)

    # User relationship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)

    # Vulnerabilities relationship
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic',
                                      cascade='all, delete-orphan')

    def __init__(self, target_url, config=None, user_id=None):
        """Initialize scan with target URL and configuration."""
        import uuid
        from urllib.parse import urlparse

        self.scan_id = str(uuid.uuid4())
        self.target_url = self._validate_url(target_url)
        self.target_domain = urlparse(self.target_url).netloc
        self.config = config or self.default_config()
        self.user_id = user_id

    @staticmethod
    def _validate_url(url, allow_localhost=True):
        """
        Validate and normalize target URL.

        Args:
            url: URL to validate
            allow_localhost: Allow localhost for development/testing
        """
        from urllib.parse import urlparse

        if not url:
            raise ValueError("Target URL is required")

        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)

        if not parsed.netloc:
            raise ValueError("Invalid URL format")

        # Security: Block scanning of internal/private networks in production
        hostname = parsed.hostname
        if hostname and not allow_localhost:
            # Block localhost and loopback
            if hostname in ('localhost', '127.0.0.1', '::1'):
                raise ValueError("Scanning localhost is not allowed in production")

            # Block private IP ranges
            import ipaddress
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_reserved:
                    raise ValueError("Scanning private/internal networks is not allowed")
            except ValueError:
                pass  # Not an IP address, it's a hostname

        return url

    @staticmethod
    def default_config():
        """Return default scan configuration."""
        return {
            'max_depth': 5,
            'max_pages': 100,
            'timeout': 30,
            'delay': 0.5,
            'concurrent_requests': 5,
            'follow_redirects': True,
            'respect_robots_txt': True,
            'scan_modules': [
                'xss', 'sqli', 'csrf', 'headers',
                'ssl', 'info_disclosure', 'open_redirect',
                'lfi', 'rfi', 'xxe'
            ],
            'authentication': None,
            'custom_headers': {},
            'excluded_paths': [],
            'included_paths': []
        }

    @property
    def config(self):
        """Get scan configuration as dictionary."""
        try:
            return json.loads(self._config)
        except (json.JSONDecodeError, TypeError):
            return self.default_config()

    @config.setter
    def config(self, value):
        """Set scan configuration with validation."""
        if isinstance(value, dict):
            # Merge with defaults to ensure all required keys exist
            default = self.default_config()
            default.update(value)
            self._config = json.dumps(default)
        else:
            self._config = json.dumps(self.default_config())

    @property
    def duration(self):
        """Calculate scan duration in seconds."""
        if self.started_at:
            end_time = self.completed_at or datetime.utcnow()
            return (end_time - self.started_at).total_seconds()
        return 0

    @property
    def total_vulnerabilities(self):
        """Get total count of vulnerabilities."""
        return (self.critical_count + self.high_count +
                self.medium_count + self.low_count + self.info_count)

    @property
    def risk_score(self):
        """
        Calculate overall risk score (0-100).

        Weighted scoring:
        - Critical: 40 points each (max 100)
        - High: 20 points each (max 80)
        - Medium: 10 points each (max 50)
        - Low: 5 points each (max 25)
        """
        score = 0
        score += min(self.critical_count * 40, 100)
        score += min(self.high_count * 20, 80)
        score += min(self.medium_count * 10, 50)
        score += min(self.low_count * 5, 25)
        return min(score, 100)

    @property
    def risk_level(self):
        """Get risk level based on score."""
        score = self.risk_score
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        return 'Info'

    def start(self):
        """Mark scan as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.progress = 0
        db.session.commit()

    def complete(self):
        """Mark scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress = 100
        self._update_vulnerability_counts()
        db.session.commit()

    def fail(self, error_message):
        """Mark scan as failed."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = str(error_message)[:1000]  # Limit error message length
        db.session.commit()

    def cancel(self):
        """Mark scan as cancelled."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        db.session.commit()

    def update_progress(self, progress, current_task=None):
        """Update scan progress."""
        self.progress = max(0, min(100, progress))
        if current_task:
            self.current_task = current_task[:255]
        db.session.commit()

    def _update_vulnerability_counts(self):
        """Update vulnerability count summary."""
        from app.models.vulnerability import Severity

        self.critical_count = self.vulnerabilities.filter_by(severity=Severity.CRITICAL).count()
        self.high_count = self.vulnerabilities.filter_by(severity=Severity.HIGH).count()
        self.medium_count = self.vulnerabilities.filter_by(severity=Severity.MEDIUM).count()
        self.low_count = self.vulnerabilities.filter_by(severity=Severity.LOW).count()
        self.info_count = self.vulnerabilities.filter_by(severity=Severity.INFO).count()

    def to_dict(self):
        """Convert scan to dictionary for API responses."""
        return {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'target_domain': self.target_domain,
            'status': self.status.value,
            'progress': self.progress,
            'current_task': self.current_task,
            'current_phase': self.current_phase or 'pending',
            'urls_scanned': self.urls_scanned,
            'forms_found': self.forms_found,
            'parameters_tested': self.parameters_tested,
            'vulnerabilities': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count,
                'total': self.total_vulnerabilities
            },
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'duration': self.duration,
            'timing': {
                'elapsed_seconds': self.elapsed_seconds or self.duration,
                'estimated_remaining_seconds': self.estimated_remaining_seconds or 0,
                'elapsed_formatted': self._format_duration(self.elapsed_seconds or self.duration),
                'remaining_formatted': self._format_duration(self.estimated_remaining_seconds or 0),
                'rate': round(self.items_per_second_rate or 0, 2)
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message
        }

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable format."""
        if not seconds or seconds <= 0:
            return "0s"
        seconds = int(seconds)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs}s")
        return " ".join(parts)

    def __repr__(self):
        return f'<Scan {self.scan_id} - {self.target_domain}>'
