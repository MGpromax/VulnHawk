"""
VulnHawk AI False Positive Detector

Machine learning-based false positive detection and confidence scoring.
Reduces noise in scan results through intelligent analysis.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability detection."""
    CONFIRMED = "confirmed"     # 95%+ confidence, verified
    HIGH = "high"               # 80-95% confidence
    MEDIUM = "medium"           # 60-80% confidence
    LOW = "low"                 # 40-60% confidence
    POSSIBLE = "possible"       # <40% confidence, likely FP


@dataclass
class FPAnalysisResult:
    """Result of false positive analysis."""
    is_likely_false_positive: bool
    confidence_level: ConfidenceLevel
    confidence_score: float
    reasoning: List[str]
    verification_suggestions: List[str]
    adjusted_severity: Optional[str]


class FalsePositiveDetector:
    """
    AI-powered false positive detection using pattern analysis,
    context evaluation, and heuristic scoring.
    """

    # False positive indicator patterns
    FP_INDICATORS = {
        'xss': {
            'positive': [
                (r'<script[^>]*>.*</script>', 'Script tag reflected in response'),
                (r'onerror\s*=', 'Event handler reflected'),
                (r'javascript:', 'JavaScript protocol reflected'),
                (r'alert\s*\(', 'Alert function present in response'),
            ],
            'negative': [
                (r'<!--.*<script.*-->', 'Script in HTML comment (likely FP)'),
                (r'\\u003c', 'Escaped output (likely FP)'),
                (r'&lt;script', 'HTML encoded (likely FP)'),
                (r'"<script', 'Inside JSON string (likely FP)'),
            ]
        },
        'sqli': {
            'positive': [
                (r'SQL syntax.*error', 'SQL error message'),
                (r'mysql_fetch|pg_query', 'Database function error'),
                (r'SQLSTATE\[', 'PDO error'),
                (r'ORA-\d{5}', 'Oracle error'),
                (r'syntax error.*near', 'Syntax error near injection point'),
            ],
            'negative': [
                (r'invalid.*input.*syntax', 'Generic input validation (likely FP)'),
                (r'please enter.*valid', 'Form validation message (likely FP)'),
                (r'could not connect', 'Connection error (likely FP)'),
            ]
        },
        'lfi': {
            'positive': [
                (r'root:.*:0:0:', '/etc/passwd content'),
                (r'\[boot loader\]', 'boot.ini content'),
                (r'<\?php', 'PHP source code'),
                (r'DB_PASSWORD|SECRET_KEY', 'Config file content'),
            ],
            'negative': [
                (r'file not found|no such file', 'File not found (likely FP)'),
                (r'access denied|permission', 'Access denied (likely FP)'),
            ]
        },
        'info_disclosure': {
            'positive': [
                (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
                (r'sk_live_[a-zA-Z0-9]{24}', 'Stripe Key'),
                (r'[a-zA-Z0-9]{40}', 'Potential API key'),
                (r'password\s*[:=]\s*["\'][^"\']+["\']', 'Password in config'),
            ],
            'negative': [
                (r'example|sample|test|demo', 'Example/test data (likely FP)'),
                (r'xxx+|placeholder', 'Placeholder (likely FP)'),
                (r'your[_-]?api[_-]?key', 'Documentation (likely FP)'),
            ]
        },
        'open_redirect': {
            'positive': [
                (r'Location:\s*https?://[^/]*[^\.a-z]', 'Redirect to external domain'),
                (r'window\.location\s*=', 'JavaScript redirect'),
                (r'meta.*http-equiv.*refresh.*url=', 'Meta refresh redirect'),
            ],
            'negative': [
                (r'Location:\s*/', 'Relative redirect (likely FP)'),
                (r'login|logout|auth', 'Auth redirect (likely FP)'),
            ]
        }
    }

    # Context-based scoring adjustments
    CONTEXT_MODIFIERS = {
        'has_payload': 0.1,           # Payload was used
        'has_evidence': 0.2,          # Evidence present
        'response_changed': 0.15,     # Response changed with payload
        'error_triggered': 0.15,      # Error message triggered
        'is_authenticated': -0.05,    # Auth required reduces risk
        'uses_https': -0.05,          # HTTPS suggests security awareness
        'has_waf': -0.1,              # WAF presence reduces confidence
        'common_pattern': 0.1,        # Known vulnerability pattern
    }

    # WAF detection patterns
    WAF_SIGNATURES = [
        r'cloudflare',
        r'akamai',
        r'imperva|incapsula',
        r'mod_security',
        r'aws.*waf',
        r'fortiweb',
        r'barracuda',
        r'f5.*asm',
    ]

    def __init__(self):
        self._analysis_cache: Dict[str, FPAnalysisResult] = {}

    def analyze(
        self,
        vulnerability: Dict,
        response_data: Optional[Dict] = None,
        context: Optional[Dict] = None
    ) -> FPAnalysisResult:
        """
        Analyze a vulnerability for false positive likelihood.

        Args:
            vulnerability: Vulnerability data dictionary
            response_data: Optional HTTP response data
            context: Optional additional context

        Returns:
            FPAnalysisResult with detailed analysis
        """
        # Check cache
        cache_key = self._generate_cache_key(vulnerability)
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]

        vuln_type = vulnerability.get('type', 'unknown')
        evidence = vulnerability.get('evidence', '')
        payload = vulnerability.get('payload', '')

        # Initialize scoring
        base_score = 0.5
        reasoning = []
        suggestions = []

        # Pattern-based analysis
        pattern_score, pattern_reasons = self._analyze_patterns(
            vuln_type, evidence, payload
        )
        base_score += pattern_score
        reasoning.extend(pattern_reasons)

        # Context-based adjustments
        if context:
            context_score, context_reasons = self._analyze_context(context)
            base_score += context_score
            reasoning.extend(context_reasons)

        # Response analysis
        if response_data:
            response_score, response_reasons = self._analyze_response(
                vuln_type, response_data
            )
            base_score += response_score
            reasoning.extend(response_reasons)

        # WAF detection
        waf_detected, waf_reason = self._detect_waf(evidence, response_data)
        if waf_detected:
            base_score -= 0.1
            reasoning.append(waf_reason)

        # Clamp score to valid range
        confidence_score = max(0.1, min(0.99, base_score))

        # Determine confidence level
        confidence_level = self._score_to_confidence(confidence_score)

        # Determine if likely false positive
        is_fp = confidence_score < 0.5

        # Generate verification suggestions
        suggestions = self._generate_suggestions(vuln_type, confidence_level)

        # Adjust severity if needed
        adjusted_severity = self._adjust_severity(
            vulnerability.get('severity', 'medium'),
            confidence_score
        )

        result = FPAnalysisResult(
            is_likely_false_positive=is_fp,
            confidence_level=confidence_level,
            confidence_score=round(confidence_score, 2),
            reasoning=reasoning,
            verification_suggestions=suggestions,
            adjusted_severity=adjusted_severity if adjusted_severity != vulnerability.get('severity') else None
        )

        # Cache result
        self._analysis_cache[cache_key] = result

        return result

    def _generate_cache_key(self, data: Dict) -> str:
        """Generate cache key for vulnerability."""
        key_data = f"{data.get('type')}{data.get('url')}{data.get('parameter')}{data.get('payload')}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _analyze_patterns(
        self,
        vuln_type: str,
        evidence: str,
        payload: str
    ) -> Tuple[float, List[str]]:
        """Analyze patterns in evidence and payload."""
        score = 0.0
        reasons = []

        patterns = self.FP_INDICATORS.get(vuln_type, {})

        # Check positive indicators (true positive signs)
        for pattern, description in patterns.get('positive', []):
            if re.search(pattern, evidence, re.IGNORECASE):
                score += 0.15
                reasons.append(f"✓ {description}")

        # Check negative indicators (false positive signs)
        for pattern, description in patterns.get('negative', []):
            if re.search(pattern, evidence, re.IGNORECASE):
                score -= 0.2
                reasons.append(f"✗ {description}")

        # Payload reflection check
        if payload and payload in evidence:
            score += 0.1
            reasons.append("✓ Payload reflected in response")
        elif payload:
            # Check for encoded payload
            encoded_checks = [
                payload.replace('<', '&lt;'),
                payload.replace('"', '&quot;'),
                payload.replace("'", "\\'"),
            ]
            for encoded in encoded_checks:
                if encoded in evidence:
                    score -= 0.1
                    reasons.append("✗ Payload was encoded/escaped")
                    break

        return score, reasons

    def _analyze_context(self, context: Dict) -> Tuple[float, List[str]]:
        """Analyze contextual factors."""
        score = 0.0
        reasons = []

        for factor, modifier in self.CONTEXT_MODIFIERS.items():
            if context.get(factor):
                score += modifier
                direction = "✓" if modifier > 0 else "✗"
                reasons.append(f"{direction} Context: {factor.replace('_', ' ')}")

        return score, reasons

    def _analyze_response(
        self,
        vuln_type: str,
        response_data: Dict
    ) -> Tuple[float, List[str]]:
        """Analyze HTTP response characteristics."""
        score = 0.0
        reasons = []

        status_code = response_data.get('status_code', 200)
        content_type = response_data.get('content_type', '')
        response_time = response_data.get('response_time', 0)

        # Status code analysis
        if status_code == 500 and vuln_type == 'sqli':
            score += 0.1
            reasons.append("✓ 500 error (may indicate SQLi)")
        elif status_code == 403:
            score -= 0.15
            reasons.append("✗ 403 Forbidden (security control)")
        elif status_code == 400:
            score -= 0.1
            reasons.append("✗ 400 Bad Request (input validation)")

        # Content type checks
        if 'application/json' in content_type and vuln_type == 'xss':
            score -= 0.1
            reasons.append("✗ JSON response (XSS less likely)")

        # Time-based analysis (for time-based SQLi)
        if vuln_type == 'sqli' and response_time > 3000:
            score += 0.2
            reasons.append("✓ Delayed response (time-based SQLi indicator)")

        return score, reasons

    def _detect_waf(
        self,
        evidence: str,
        response_data: Optional[Dict]
    ) -> Tuple[bool, Optional[str]]:
        """Detect presence of Web Application Firewall."""
        check_text = evidence

        if response_data:
            headers = response_data.get('headers', {})
            check_text += ' '.join(str(v) for v in headers.values())

        for pattern in self.WAF_SIGNATURES:
            if re.search(pattern, check_text, re.IGNORECASE):
                return True, "✗ WAF detected (may affect accuracy)"

        return False, None

    def _score_to_confidence(self, score: float) -> ConfidenceLevel:
        """Convert numerical score to confidence level."""
        if score >= 0.95:
            return ConfidenceLevel.CONFIRMED
        elif score >= 0.8:
            return ConfidenceLevel.HIGH
        elif score >= 0.6:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.4:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.POSSIBLE

    def _generate_suggestions(
        self,
        vuln_type: str,
        confidence: ConfidenceLevel
    ) -> List[str]:
        """Generate verification suggestions."""
        base_suggestions = {
            'xss': [
                "Manually verify XSS by checking if script executes in browser",
                "Test with different browsers to confirm XSS",
                "Check if CSP headers would prevent exploitation"
            ],
            'sqli': [
                "Attempt to extract data using UNION-based injection",
                "Try time-based blind SQLi with SLEEP/WAITFOR",
                "Use sqlmap for comprehensive verification"
            ],
            'lfi': [
                "Attempt to read known files like /etc/passwd",
                "Try null byte injection for bypasses",
                "Check if file contents are actually returned"
            ],
            'csrf': [
                "Verify no CSRF token is required",
                "Check SameSite cookie attributes",
                "Test if Origin/Referer validation exists"
            ],
            'info_disclosure': [
                "Verify exposed data is actually sensitive",
                "Check if data is test/sample data",
                "Confirm credentials are valid"
            ],
            'open_redirect': [
                "Verify redirect to external domain works",
                "Test if redirect preserves authentication",
                "Check for URL validation bypasses"
            ]
        }

        suggestions = base_suggestions.get(vuln_type, [
            "Manually verify the vulnerability",
            "Test with additional payloads",
            "Check for security controls that may prevent exploitation"
        ])

        # Add confidence-specific suggestions
        if confidence in [ConfidenceLevel.LOW, ConfidenceLevel.POSSIBLE]:
            suggestions.insert(0, "⚠ Low confidence - manual verification strongly recommended")

        return suggestions

    def _adjust_severity(self, original: str, confidence: float) -> str:
        """Adjust severity based on confidence score."""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']

        if confidence < 0.5:
            # Likely false positive - consider downgrading
            current_idx = severity_order.index(original) if original in severity_order else 2
            return severity_order[min(len(severity_order) - 1, current_idx + 1)]

        return original

    def batch_analyze(
        self,
        vulnerabilities: List[Dict],
        context: Optional[Dict] = None
    ) -> List[Tuple[Dict, FPAnalysisResult]]:
        """Analyze multiple vulnerabilities efficiently."""
        results = []
        for vuln in vulnerabilities:
            result = self.analyze(vuln, context=context)
            results.append((vuln, result))
        return results

    def filter_false_positives(
        self,
        vulnerabilities: List[Dict],
        threshold: float = 0.5
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter vulnerabilities into likely true and false positives.

        Args:
            vulnerabilities: List of vulnerabilities to filter
            threshold: Confidence threshold (below = likely FP)

        Returns:
            Tuple of (likely_true_positives, likely_false_positives)
        """
        true_positives = []
        false_positives = []

        for vuln in vulnerabilities:
            result = self.analyze(vuln)

            if result.confidence_score >= threshold:
                # Likely true positive
                vuln['confidence'] = result.confidence_score
                vuln['confidence_level'] = result.confidence_level.value
                true_positives.append(vuln)
            else:
                # Likely false positive
                vuln['fp_reasoning'] = result.reasoning
                vuln['confidence'] = result.confidence_score
                false_positives.append(vuln)

        return true_positives, false_positives

    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        if not self._analysis_cache:
            return {'total_analyzed': 0}

        total = len(self._analysis_cache)
        fp_count = sum(
            1 for r in self._analysis_cache.values()
            if r.is_likely_false_positive
        )

        confidence_dist = {}
        for result in self._analysis_cache.values():
            level = result.confidence_level.value
            confidence_dist[level] = confidence_dist.get(level, 0) + 1

        avg_confidence = sum(
            r.confidence_score for r in self._analysis_cache.values()
        ) / total

        return {
            'total_analyzed': total,
            'likely_false_positives': fp_count,
            'likely_true_positives': total - fp_count,
            'false_positive_rate': round(fp_count / total * 100, 1),
            'average_confidence': round(avg_confidence, 2),
            'confidence_distribution': confidence_dist
        }
