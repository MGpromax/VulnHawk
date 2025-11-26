"""
VulnHawk AI Vulnerability Classifier

Machine learning-based vulnerability classification and severity prediction.
Uses pattern recognition and heuristics for intelligent analysis.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import json


class VulnerabilityCategory(Enum):
    """Vulnerability categories based on OWASP and CWE."""
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XXE = "xml_external_entities"
    BROKEN_ACCESS = "broken_access_control"
    MISCONFIG = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    COMPONENTS = "vulnerable_components"
    LOGGING = "insufficient_logging"
    SSRF = "server_side_request_forgery"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Result of vulnerability classification."""
    category: VulnerabilityCategory
    confidence: float
    severity_prediction: str
    attack_vector: str
    exploitation_difficulty: str
    potential_impact: str
    similar_cves: List[str]
    remediation_priority: int


class VulnerabilityClassifier:
    """
    AI-powered vulnerability classifier using pattern matching,
    feature extraction, and heuristic analysis.
    """

    # Pattern weights for classification
    INJECTION_PATTERNS = {
        r"sql.*injection|sqli|' or '|union select|1=1": 0.9,
        r"command.*injection|os\.(system|popen)|subprocess": 0.85,
        r"ldap.*injection|ldap_search": 0.8,
        r"xpath.*injection|//user\[": 0.8,
        r"template.*injection|{{.*}}|\${.*}": 0.75,
    }

    XSS_PATTERNS = {
        r"<script|javascript:|onerror=|onload=|onclick=": 0.9,
        r"document\.cookie|document\.write|innerHTML": 0.85,
        r"xss|cross.?site.?script": 0.8,
        r"alert\(|confirm\(|prompt\(": 0.75,
        r"<img.*src=|<svg.*onload": 0.7,
    }

    AUTH_PATTERNS = {
        r"authentication.*bypass|auth.*bypass": 0.9,
        r"session.*fixation|session.*hijack": 0.85,
        r"password.*leak|credential.*expos": 0.8,
        r"weak.*password|default.*password": 0.75,
        r"brute.*force|rate.*limit": 0.7,
    }

    DATA_EXPOSURE_PATTERNS = {
        r"api.?key|secret.?key|private.?key": 0.9,
        r"password|passwd|pwd": 0.85,
        r"credit.?card|ssn|social.?security": 0.9,
        r"aws.?access|azure.?key|gcp.?key": 0.85,
        r"jwt|bearer.*token|auth.*token": 0.8,
    }

    MISCONFIG_PATTERNS = {
        r"missing.*header|security.*header": 0.8,
        r"cors.*misconfig|access-control-allow": 0.75,
        r"debug.*mode|debug.*enabled": 0.7,
        r"default.*config|default.*cred": 0.8,
        r"directory.*listing|index.*of": 0.65,
    }

    # CVE database for similar vulnerabilities (simplified)
    CVE_DATABASE = {
        'xss': ['CVE-2023-29017', 'CVE-2022-32149', 'CVE-2021-41182'],
        'sqli': ['CVE-2023-27350', 'CVE-2022-42889', 'CVE-2021-44228'],
        'csrf': ['CVE-2023-22515', 'CVE-2022-36804', 'CVE-2021-21311'],
        'lfi': ['CVE-2023-24489', 'CVE-2022-37434', 'CVE-2021-3129'],
        'ssrf': ['CVE-2023-42793', 'CVE-2022-42889', 'CVE-2021-26855'],
        'rce': ['CVE-2023-44487', 'CVE-2022-22965', 'CVE-2021-44228'],
    }

    def __init__(self):
        self._cache: Dict[str, ClassificationResult] = {}

    def classify(
        self,
        vulnerability_data: Dict,
        context: Optional[Dict] = None
    ) -> ClassificationResult:
        """
        Classify a vulnerability using AI-powered analysis.

        Args:
            vulnerability_data: Dictionary containing vulnerability details
            context: Optional additional context about the scan

        Returns:
            ClassificationResult with detailed analysis
        """
        # Generate cache key
        cache_key = self._generate_cache_key(vulnerability_data)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Extract features
        features = self._extract_features(vulnerability_data)

        # Determine category
        category, confidence = self._categorize(features)

        # Predict severity
        severity = self._predict_severity(features, category)

        # Analyze attack vector
        attack_vector = self._analyze_attack_vector(features)

        # Assess exploitation difficulty
        difficulty = self._assess_difficulty(features, category)

        # Evaluate potential impact
        impact = self._evaluate_impact(features, category)

        # Find similar CVEs
        similar_cves = self._find_similar_cves(category, features)

        # Calculate remediation priority (1-10, higher = more urgent)
        priority = self._calculate_priority(severity, difficulty, impact)

        result = ClassificationResult(
            category=category,
            confidence=confidence,
            severity_prediction=severity,
            attack_vector=attack_vector,
            exploitation_difficulty=difficulty,
            potential_impact=impact,
            similar_cves=similar_cves,
            remediation_priority=priority
        )

        # Cache result
        self._cache[cache_key] = result

        return result

    def _generate_cache_key(self, data: Dict) -> str:
        """Generate a unique cache key for vulnerability data."""
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(serialized.encode()).hexdigest()

    def _extract_features(self, data: Dict) -> Dict:
        """Extract features from vulnerability data for classification."""
        name = data.get('name', '').lower()
        description = data.get('description', '').lower()
        vuln_type = data.get('type', '').lower()
        url = data.get('url', '').lower()
        payload = data.get('payload', '').lower()
        evidence = data.get('evidence', '').lower()
        parameter = data.get('parameter', '').lower()
        method = data.get('method', 'GET').upper()

        # Combine text for analysis
        full_text = f"{name} {description} {vuln_type} {payload} {evidence}"

        # Feature extraction
        features = {
            'text': full_text,
            'name': name,
            'type': vuln_type,
            'url': url,
            'payload': payload,
            'evidence': evidence,
            'parameter': parameter,
            'method': method,
            'has_payload': bool(payload),
            'has_evidence': bool(evidence),
            'is_authenticated': 'auth' in url or 'login' in url,
            'is_api': '/api/' in url or 'json' in evidence,
            'uses_post': method == 'POST',
            'has_parameter': bool(parameter),
            'payload_length': len(payload) if payload else 0,
        }

        # Pattern matching scores
        features['injection_score'] = self._calculate_pattern_score(
            full_text, self.INJECTION_PATTERNS
        )
        features['xss_score'] = self._calculate_pattern_score(
            full_text, self.XSS_PATTERNS
        )
        features['auth_score'] = self._calculate_pattern_score(
            full_text, self.AUTH_PATTERNS
        )
        features['data_exposure_score'] = self._calculate_pattern_score(
            full_text, self.DATA_EXPOSURE_PATTERNS
        )
        features['misconfig_score'] = self._calculate_pattern_score(
            full_text, self.MISCONFIG_PATTERNS
        )

        return features

    def _calculate_pattern_score(
        self,
        text: str,
        patterns: Dict[str, float]
    ) -> float:
        """Calculate weighted score based on pattern matches."""
        total_score = 0.0
        matches = 0

        for pattern, weight in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                total_score += weight
                matches += 1

        if matches == 0:
            return 0.0

        return min(1.0, total_score / matches)

    def _categorize(self, features: Dict) -> Tuple[VulnerabilityCategory, float]:
        """Categorize vulnerability based on extracted features."""
        scores = {
            VulnerabilityCategory.INJECTION: features['injection_score'],
            VulnerabilityCategory.XSS: features['xss_score'],
            VulnerabilityCategory.BROKEN_AUTH: features['auth_score'],
            VulnerabilityCategory.SENSITIVE_DATA: features['data_exposure_score'],
            VulnerabilityCategory.MISCONFIG: features['misconfig_score'],
        }

        # Check explicit type mapping
        type_mapping = {
            'xss': VulnerabilityCategory.XSS,
            'sqli': VulnerabilityCategory.INJECTION,
            'sql': VulnerabilityCategory.INJECTION,
            'injection': VulnerabilityCategory.INJECTION,
            'csrf': VulnerabilityCategory.BROKEN_AUTH,
            'auth': VulnerabilityCategory.BROKEN_AUTH,
            'info': VulnerabilityCategory.SENSITIVE_DATA,
            'disclosure': VulnerabilityCategory.SENSITIVE_DATA,
            'header': VulnerabilityCategory.MISCONFIG,
            'config': VulnerabilityCategory.MISCONFIG,
            'lfi': VulnerabilityCategory.INJECTION,
            'rfi': VulnerabilityCategory.INJECTION,
            'ssrf': VulnerabilityCategory.SSRF,
        }

        vuln_type = features.get('type', '')
        for key, category in type_mapping.items():
            if key in vuln_type:
                return category, 0.95

        # Find highest scoring category
        best_category = max(scores, key=scores.get)
        best_score = scores[best_category]

        if best_score < 0.3:
            return VulnerabilityCategory.UNKNOWN, 0.5

        return best_category, min(0.95, best_score + 0.2)

    def _predict_severity(
        self,
        features: Dict,
        category: VulnerabilityCategory
    ) -> str:
        """Predict severity level based on features and category."""
        # Base severity by category
        category_severity = {
            VulnerabilityCategory.INJECTION: 'high',
            VulnerabilityCategory.XSS: 'medium',
            VulnerabilityCategory.BROKEN_AUTH: 'high',
            VulnerabilityCategory.SENSITIVE_DATA: 'high',
            VulnerabilityCategory.MISCONFIG: 'medium',
            VulnerabilityCategory.SSRF: 'high',
            VulnerabilityCategory.UNKNOWN: 'medium',
        }

        base_severity = category_severity.get(category, 'medium')

        # Elevate severity based on features
        if features.get('has_evidence') and features.get('has_payload'):
            if base_severity == 'medium':
                return 'high'
            elif base_severity == 'high':
                return 'critical'

        # Check for authentication context
        if features.get('is_authenticated'):
            if base_severity == 'low':
                return 'medium'

        # API vulnerabilities can be more severe
        if features.get('is_api') and category == VulnerabilityCategory.INJECTION:
            return 'critical'

        return base_severity

    def _analyze_attack_vector(self, features: Dict) -> str:
        """Determine the attack vector."""
        if features.get('is_api'):
            return "Network (API)"
        elif features.get('uses_post'):
            return "Network (POST)"
        elif features.get('has_parameter'):
            return "Network (GET parameter)"
        else:
            return "Network"

    def _assess_difficulty(
        self,
        features: Dict,
        category: VulnerabilityCategory
    ) -> str:
        """Assess exploitation difficulty."""
        # Categories with typically easy exploitation
        easy_categories = {
            VulnerabilityCategory.XSS,
            VulnerabilityCategory.MISCONFIG,
        }

        # Categories with moderate difficulty
        moderate_categories = {
            VulnerabilityCategory.INJECTION,
            VulnerabilityCategory.SENSITIVE_DATA,
        }

        if category in easy_categories:
            return "Low"
        elif category in moderate_categories:
            if features.get('has_payload') and features.get('has_evidence'):
                return "Low"
            return "Medium"
        else:
            if features.get('is_authenticated'):
                return "Medium"
            return "High"

    def _evaluate_impact(
        self,
        features: Dict,
        category: VulnerabilityCategory
    ) -> str:
        """Evaluate potential impact of exploitation."""
        high_impact_categories = {
            VulnerabilityCategory.INJECTION,
            VulnerabilityCategory.BROKEN_AUTH,
            VulnerabilityCategory.SSRF,
        }

        if category in high_impact_categories:
            return "Complete system compromise possible"
        elif category == VulnerabilityCategory.XSS:
            return "Session hijacking, data theft"
        elif category == VulnerabilityCategory.SENSITIVE_DATA:
            return "Sensitive data exposure"
        elif category == VulnerabilityCategory.MISCONFIG:
            return "Information disclosure, weakened security"
        else:
            return "Variable impact depending on context"

    def _find_similar_cves(
        self,
        category: VulnerabilityCategory,
        features: Dict
    ) -> List[str]:
        """Find similar CVEs for reference."""
        vuln_type = features.get('type', '')

        # Direct type mapping
        for key, cves in self.CVE_DATABASE.items():
            if key in vuln_type:
                return cves[:3]

        # Category mapping
        category_cve_map = {
            VulnerabilityCategory.XSS: 'xss',
            VulnerabilityCategory.INJECTION: 'sqli',
            VulnerabilityCategory.BROKEN_AUTH: 'csrf',
            VulnerabilityCategory.SSRF: 'ssrf',
        }

        cve_key = category_cve_map.get(category)
        if cve_key and cve_key in self.CVE_DATABASE:
            return self.CVE_DATABASE[cve_key][:3]

        return []

    def _calculate_priority(
        self,
        severity: str,
        difficulty: str,
        impact: str
    ) -> int:
        """Calculate remediation priority (1-10)."""
        severity_score = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        }.get(severity, 5)

        difficulty_modifier = {
            'Low': 1.2,
            'Medium': 1.0,
            'High': 0.8
        }.get(difficulty, 1.0)

        impact_modifier = 1.0
        if 'compromise' in impact.lower():
            impact_modifier = 1.3
        elif 'hijack' in impact.lower():
            impact_modifier = 1.2

        priority = int(severity_score * difficulty_modifier * impact_modifier)
        return min(10, max(1, priority))

    def batch_classify(
        self,
        vulnerabilities: List[Dict]
    ) -> List[ClassificationResult]:
        """Classify multiple vulnerabilities efficiently."""
        return [self.classify(vuln) for vuln in vulnerabilities]

    def get_statistics(self) -> Dict:
        """Get classification statistics."""
        if not self._cache:
            return {'total_classified': 0}

        categories = {}
        severities = {}
        avg_confidence = 0.0

        for result in self._cache.values():
            cat = result.category.value
            categories[cat] = categories.get(cat, 0) + 1
            severities[result.severity_prediction] = severities.get(
                result.severity_prediction, 0
            ) + 1
            avg_confidence += result.confidence

        return {
            'total_classified': len(self._cache),
            'categories': categories,
            'severities': severities,
            'average_confidence': avg_confidence / len(self._cache)
        }
