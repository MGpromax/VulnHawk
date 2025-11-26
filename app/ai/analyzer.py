"""
VulnHawk AI Security Analyzer

Advanced AI-powered security analysis with context-aware recommendations,
threat modeling, and intelligent vulnerability correlation.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib
from datetime import datetime


@dataclass
class ThreatModel:
    """Threat modeling results."""
    attack_surface: List[str]
    threat_actors: List[str]
    attack_scenarios: List[Dict]
    risk_rating: str
    mitigation_strategies: List[str]


@dataclass
class CorrelatedVulnerability:
    """Vulnerabilities that are related or can be chained."""
    primary_vuln: Dict
    related_vulns: List[Dict]
    attack_chain: List[str]
    combined_severity: str
    exploitation_narrative: str


@dataclass
class SecurityInsight:
    """AI-generated security insight."""
    category: str
    title: str
    description: str
    recommendation: str
    confidence: float
    references: List[str] = field(default_factory=list)


class AISecurityAnalyzer:
    """
    AI-powered security analyzer providing intelligent insights,
    vulnerability correlation, and threat modeling.
    """

    # Attack chain patterns
    ATTACK_CHAINS = {
        ('info_disclosure', 'sqli'): {
            'name': 'Reconnaissance to Database Compromise',
            'description': 'Information disclosure reveals database structure, enabling targeted SQL injection',
            'severity_boost': 1.5
        },
        ('xss', 'csrf'): {
            'name': 'XSS-Assisted CSRF',
            'description': 'XSS vulnerability can be used to bypass CSRF protections and perform actions',
            'severity_boost': 1.3
        },
        ('lfi', 'info_disclosure'): {
            'name': 'LFI Chain Attack',
            'description': 'Local file inclusion combined with info disclosure can expose sensitive files',
            'severity_boost': 1.4
        },
        ('open_redirect', 'xss'): {
            'name': 'Phishing Enhancement',
            'description': 'Open redirect legitimizes malicious links, XSS steals credentials',
            'severity_boost': 1.2
        },
        ('headers', 'xss'): {
            'name': 'Weakened XSS Defense',
            'description': 'Missing CSP headers make XSS exploitation easier',
            'severity_boost': 1.1
        },
        ('sqli', 'rce'): {
            'name': 'SQL to Shell',
            'description': 'SQL injection can lead to remote code execution via file writes or stored procedures',
            'severity_boost': 2.0
        },
    }

    # Threat actor profiles
    THREAT_ACTORS = {
        'script_kiddie': {
            'name': 'Script Kiddie',
            'skill_level': 'low',
            'targets': ['xss', 'sqli', 'lfi'],
            'motivation': 'experimentation'
        },
        'cybercriminal': {
            'name': 'Cybercriminal',
            'skill_level': 'medium',
            'targets': ['sqli', 'auth_bypass', 'data_exposure'],
            'motivation': 'financial gain'
        },
        'apt': {
            'name': 'Advanced Persistent Threat',
            'skill_level': 'high',
            'targets': ['all'],
            'motivation': 'espionage, sabotage'
        },
        'insider': {
            'name': 'Malicious Insider',
            'skill_level': 'variable',
            'targets': ['access_control', 'data_exposure'],
            'motivation': 'revenge, financial'
        }
    }

    # Security best practices knowledge base
    BEST_PRACTICES = {
        'xss': {
            'title': 'XSS Prevention',
            'practices': [
                'Implement Content Security Policy (CSP) headers',
                'Use output encoding for all user-supplied data',
                'Validate and sanitize all input on the server side',
                'Use HTTPOnly and Secure flags for session cookies',
                'Consider using a templating engine with auto-escaping'
            ]
        },
        'sqli': {
            'title': 'SQL Injection Prevention',
            'practices': [
                'Use parameterized queries or prepared statements',
                'Implement input validation with whitelisting',
                'Apply principle of least privilege to database accounts',
                'Use stored procedures with parameterized inputs',
                'Implement Web Application Firewall (WAF) rules'
            ]
        },
        'csrf': {
            'title': 'CSRF Prevention',
            'practices': [
                'Implement anti-CSRF tokens for all state-changing operations',
                'Use SameSite cookie attribute',
                'Verify Origin/Referer headers',
                'Require re-authentication for sensitive actions',
                'Use custom request headers for AJAX calls'
            ]
        },
        'headers': {
            'title': 'Security Headers Best Practices',
            'practices': [
                'Enable Strict-Transport-Security (HSTS)',
                'Implement Content-Security-Policy (CSP)',
                'Set X-Content-Type-Options: nosniff',
                'Set X-Frame-Options: DENY or SAMEORIGIN',
                'Configure proper CORS policies'
            ]
        },
        'auth': {
            'title': 'Authentication Best Practices',
            'practices': [
                'Implement multi-factor authentication (MFA)',
                'Use secure password hashing (bcrypt, Argon2)',
                'Implement account lockout after failed attempts',
                'Use secure session management',
                'Implement proper logout functionality'
            ]
        }
    }

    def __init__(self):
        self._analysis_cache: Dict[str, Dict] = {}

    def analyze_scan_results(
        self,
        vulnerabilities: List[Dict],
        scan_metadata: Optional[Dict] = None
    ) -> Dict:
        """
        Perform comprehensive AI analysis on scan results.

        Args:
            vulnerabilities: List of detected vulnerabilities
            scan_metadata: Optional metadata about the scan

        Returns:
            Comprehensive analysis results
        """
        analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'vulnerability_count': len(vulnerabilities),
            'insights': [],
            'correlations': [],
            'threat_model': None,
            'risk_assessment': {},
            'recommendations': [],
            'executive_summary': ''
        }

        if not vulnerabilities:
            analysis['executive_summary'] = (
                "No vulnerabilities were detected during this scan. "
                "Continue regular security assessments and maintain secure development practices."
            )
            return analysis

        # Generate insights
        analysis['insights'] = self._generate_insights(vulnerabilities)

        # Correlate vulnerabilities
        analysis['correlations'] = self._correlate_vulnerabilities(vulnerabilities)

        # Build threat model
        analysis['threat_model'] = self._build_threat_model(vulnerabilities)

        # Risk assessment
        analysis['risk_assessment'] = self._assess_risk(vulnerabilities)

        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(vulnerabilities)

        # Executive summary
        analysis['executive_summary'] = self._generate_executive_summary(
            vulnerabilities, analysis
        )

        return analysis

    def _generate_insights(self, vulnerabilities: List[Dict]) -> List[SecurityInsight]:
        """Generate AI-powered security insights."""
        insights = []

        # Categorize vulnerabilities
        vuln_types = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            vuln_types[vuln_type].append(vuln)

        # Generate type-specific insights
        for vuln_type, vulns in vuln_types.items():
            count = len(vulns)
            severity_counts = defaultdict(int)
            for v in vulns:
                severity_counts[v.get('severity', 'medium')] += 1

            # Pattern analysis
            if count >= 3:
                insights.append(SecurityInsight(
                    category='pattern',
                    title=f'Systematic {vuln_type.upper()} Issue Detected',
                    description=(
                        f'Multiple {vuln_type} vulnerabilities ({count}) detected across '
                        f'different endpoints. This suggests a systemic coding practice issue '
                        f'rather than isolated mistakes.'
                    ),
                    recommendation=(
                        f'Review all code handling user input for {vuln_type} vulnerabilities. '
                        f'Consider implementing a centralized input validation library.'
                    ),
                    confidence=0.85
                ))

            # High severity cluster
            critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
            if critical_high >= 2:
                insights.append(SecurityInsight(
                    category='severity',
                    title=f'Critical {vuln_type.upper()} Exposure',
                    description=(
                        f'{critical_high} high/critical severity {vuln_type} vulnerabilities '
                        f'require immediate attention.'
                    ),
                    recommendation='Prioritize remediation of these vulnerabilities immediately.',
                    confidence=0.95
                ))

        # Attack surface insight
        unique_urls = set()
        unique_params = set()
        for vuln in vulnerabilities:
            if vuln.get('url'):
                unique_urls.add(vuln['url'].split('?')[0])
            if vuln.get('parameter'):
                unique_params.add(vuln['parameter'])

        if len(unique_urls) > 5:
            insights.append(SecurityInsight(
                category='attack_surface',
                title='Large Attack Surface Identified',
                description=(
                    f'{len(unique_urls)} unique endpoints contain vulnerabilities. '
                    f'This indicates a wide attack surface requiring comprehensive review.'
                ),
                recommendation=(
                    'Implement security controls at the framework/middleware level '
                    'to provide consistent protection across all endpoints.'
                ),
                confidence=0.8
            ))

        # Parameter analysis
        common_vulnerable_params = {'id', 'user', 'page', 'search', 'query', 'url', 'file', 'path'}
        risky_params = unique_params.intersection(common_vulnerable_params)
        if risky_params:
            insights.append(SecurityInsight(
                category='parameters',
                title='Common Vulnerable Parameters Found',
                description=(
                    f'Parameters commonly targeted by attackers are vulnerable: '
                    f'{", ".join(risky_params)}. These are frequently exploited in automated attacks.'
                ),
                recommendation=(
                    'Apply strict validation and sanitization to these parameters. '
                    'Consider implementing a WAF rule set for common attack patterns.'
                ),
                confidence=0.75,
                references=['OWASP Testing Guide', 'CWE-20: Improper Input Validation']
            ))

        return insights

    def _correlate_vulnerabilities(
        self,
        vulnerabilities: List[Dict]
    ) -> List[CorrelatedVulnerability]:
        """Find correlated vulnerabilities that can be chained."""
        correlations = []

        # Group by type
        by_type = defaultdict(list)
        for vuln in vulnerabilities:
            by_type[vuln.get('type', 'unknown')].append(vuln)

        # Check for attack chains
        types_present = set(by_type.keys())

        for (type1, type2), chain_info in self.ATTACK_CHAINS.items():
            if type1 in types_present and type2 in types_present:
                primary = by_type[type1][0]
                related = by_type[type2]

                # Build attack narrative
                narrative = self._build_attack_narrative(
                    type1, type2, chain_info, primary, related[0]
                )

                # Calculate combined severity
                combined_severity = self._calculate_combined_severity(
                    primary, related, chain_info['severity_boost']
                )

                correlations.append(CorrelatedVulnerability(
                    primary_vuln=primary,
                    related_vulns=related,
                    attack_chain=[
                        f"1. Exploit {type1} vulnerability at {primary.get('url', 'unknown')}",
                        f"2. Use information/access to enhance {type2} attack",
                        f"3. Chain: {chain_info['name']}"
                    ],
                    combined_severity=combined_severity,
                    exploitation_narrative=narrative
                ))

        # Check for same-endpoint vulnerabilities
        by_url = defaultdict(list)
        for vuln in vulnerabilities:
            url = vuln.get('url', '').split('?')[0]
            by_url[url].append(vuln)

        for url, url_vulns in by_url.items():
            if len(url_vulns) >= 2:
                types = [v.get('type') for v in url_vulns]
                correlations.append(CorrelatedVulnerability(
                    primary_vuln=url_vulns[0],
                    related_vulns=url_vulns[1:],
                    attack_chain=[
                        f"Multiple vulnerabilities at same endpoint: {url}",
                        f"Types: {', '.join(types)}",
                        "Single endpoint can be exploited multiple ways"
                    ],
                    combined_severity='high',
                    exploitation_narrative=(
                        f"The endpoint {url} contains multiple vulnerabilities "
                        f"({', '.join(types)}) making it a high-value target. "
                        f"An attacker can choose the most effective attack vector."
                    )
                ))

        return correlations

    def _build_attack_narrative(
        self,
        type1: str,
        type2: str,
        chain_info: Dict,
        vuln1: Dict,
        vuln2: Dict
    ) -> str:
        """Build a narrative explaining the attack chain."""
        return (
            f"An attacker could first exploit the {type1} vulnerability at "
            f"{vuln1.get('url', 'the application')} to {self._get_action(type1)}. "
            f"This information or access can then be used to enhance an attack on "
            f"the {type2} vulnerability at {vuln2.get('url', 'another endpoint')}, "
            f"resulting in {chain_info['description'].lower()}. "
            f"This attack chain is known as '{chain_info['name']}'."
        )

    def _get_action(self, vuln_type: str) -> str:
        """Get action description for vulnerability type."""
        actions = {
            'info_disclosure': 'gather sensitive information about the system',
            'xss': 'execute malicious scripts in user browsers',
            'sqli': 'access or modify database contents',
            'csrf': 'perform unauthorized actions on behalf of users',
            'lfi': 'read sensitive local files',
            'open_redirect': 'redirect users to malicious sites',
            'headers': 'bypass browser security controls',
        }
        return actions.get(vuln_type, 'compromise the application')

    def _calculate_combined_severity(
        self,
        primary: Dict,
        related: List[Dict],
        boost: float
    ) -> str:
        """Calculate combined severity when vulnerabilities are chained."""
        severity_scores = {
            'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1
        }

        primary_score = severity_scores.get(primary.get('severity', 'medium'), 3)
        max_related = max(
            severity_scores.get(v.get('severity', 'medium'), 3)
            for v in related
        )

        combined = (primary_score + max_related) * boost / 2

        if combined >= 4.5:
            return 'critical'
        elif combined >= 3.5:
            return 'high'
        elif combined >= 2.5:
            return 'medium'
        return 'low'

    def _build_threat_model(self, vulnerabilities: List[Dict]) -> ThreatModel:
        """Build a threat model based on identified vulnerabilities."""
        # Identify attack surface
        attack_surface = []
        vuln_types = set()

        for vuln in vulnerabilities:
            vuln_types.add(vuln.get('type', 'unknown'))
            if vuln.get('url'):
                attack_surface.append(vuln['url'].split('?')[0])

        attack_surface = list(set(attack_surface))[:10]  # Top 10

        # Identify relevant threat actors
        relevant_actors = []
        for actor_id, actor in self.THREAT_ACTORS.items():
            targets = set(actor['targets'])
            if 'all' in targets or targets.intersection(vuln_types):
                relevant_actors.append(actor['name'])

        # Build attack scenarios
        scenarios = []
        for vuln in vulnerabilities[:5]:  # Top 5 vulnerabilities
            scenarios.append({
                'vulnerability': vuln.get('name', 'Unknown'),
                'attack_type': vuln.get('type', 'unknown'),
                'scenario': self._generate_attack_scenario(vuln),
                'likelihood': self._assess_likelihood(vuln),
                'impact': self._assess_impact(vuln)
            })

        # Calculate overall risk
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity_counts[vuln.get('severity', 'medium')] += 1

        if severity_counts['critical'] > 0:
            risk_rating = 'Critical'
        elif severity_counts['high'] >= 3:
            risk_rating = 'Critical'
        elif severity_counts['high'] > 0:
            risk_rating = 'High'
        elif severity_counts['medium'] >= 5:
            risk_rating = 'High'
        elif severity_counts['medium'] > 0:
            risk_rating = 'Medium'
        else:
            risk_rating = 'Low'

        # Mitigation strategies
        mitigation = self._generate_mitigation_strategies(vuln_types)

        return ThreatModel(
            attack_surface=attack_surface,
            threat_actors=relevant_actors,
            attack_scenarios=scenarios,
            risk_rating=risk_rating,
            mitigation_strategies=mitigation
        )

    def _generate_attack_scenario(self, vuln: Dict) -> str:
        """Generate a realistic attack scenario."""
        vuln_type = vuln.get('type', 'unknown')
        url = vuln.get('url', 'the application')

        scenarios = {
            'xss': f"Attacker crafts a malicious link containing XSS payload targeting {url}. "
                   f"Victim clicks link, script executes stealing session cookie.",
            'sqli': f"Attacker discovers SQL injection at {url}, extracts user credentials "
                    f"from database, potentially gaining admin access.",
            'csrf': f"Attacker creates malicious page that submits form to {url} when victim "
                    f"visits, performing unauthorized actions.",
            'lfi': f"Attacker manipulates file parameter at {url} to read /etc/passwd or "
                   f"application configuration files.",
            'info_disclosure': f"Attacker accesses {url} discovering exposed API keys, "
                              f"configuration details, or user data.",
            'open_redirect': f"Attacker crafts legitimate-looking link using {url} that "
                            f"redirects to phishing site.",
            'headers': f"Missing security headers at {url} enable various attacks including "
                       f"XSS, clickjacking, and protocol downgrade.",
        }

        return scenarios.get(
            vuln_type,
            f"Attacker exploits {vuln_type} vulnerability at {url} to compromise security."
        )

    def _assess_likelihood(self, vuln: Dict) -> str:
        """Assess attack likelihood."""
        severity = vuln.get('severity', 'medium')
        has_payload = bool(vuln.get('payload'))

        if severity in ['critical', 'high'] and has_payload:
            return 'High'
        elif severity in ['critical', 'high']:
            return 'Medium-High'
        elif severity == 'medium':
            return 'Medium'
        return 'Low'

    def _assess_impact(self, vuln: Dict) -> str:
        """Assess potential impact."""
        vuln_type = vuln.get('type', 'unknown')
        severity = vuln.get('severity', 'medium')

        high_impact_types = {'sqli', 'rce', 'auth_bypass', 'ssrf'}

        if vuln_type in high_impact_types or severity == 'critical':
            return 'Severe - Complete system compromise possible'
        elif severity == 'high':
            return 'Significant - Data breach or service disruption'
        elif severity == 'medium':
            return 'Moderate - Limited data exposure or functionality abuse'
        return 'Minimal - Information disclosure'

    def _generate_mitigation_strategies(self, vuln_types: Set[str]) -> List[str]:
        """Generate mitigation strategies."""
        strategies = []

        # Type-specific strategies
        for vuln_type in vuln_types:
            if vuln_type in self.BEST_PRACTICES:
                strategies.extend(self.BEST_PRACTICES[vuln_type]['practices'][:2])

        # General strategies
        strategies.extend([
            "Implement defense in depth with multiple security layers",
            "Conduct regular security training for development team",
            "Integrate security testing into CI/CD pipeline",
            "Perform regular penetration testing",
            "Maintain an incident response plan"
        ])

        return list(set(strategies))[:10]

    def _assess_risk(self, vulnerabilities: List[Dict]) -> Dict:
        """Perform comprehensive risk assessment."""
        total = len(vulnerabilities)
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for vuln in vulnerabilities:
            severity_counts[vuln.get('severity', 'medium')] += 1
            type_counts[vuln.get('type', 'unknown')] += 1

        # Calculate risk score (0-100)
        severity_weights = {
            'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 1
        }

        risk_score = min(100, sum(
            count * severity_weights.get(sev, 5)
            for sev, count in severity_counts.items()
        ))

        return {
            'risk_score': risk_score,
            'risk_level': self._score_to_level(risk_score),
            'total_vulnerabilities': total,
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'most_common_type': max(type_counts, key=type_counts.get) if type_counts else None,
            'highest_severity': self._get_highest_severity(severity_counts)
        }

    def _score_to_level(self, score: int) -> str:
        """Convert risk score to level."""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        return 'Minimal'

    def _get_highest_severity(self, counts: Dict) -> str:
        """Get highest severity present."""
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if counts.get(sev, 0) > 0:
                return sev
        return 'none'

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations."""
        recommendations = []
        vuln_types = set(v.get('type') for v in vulnerabilities)

        # Priority 1: Critical/High severity
        critical_high = [v for v in vulnerabilities if v.get('severity') in ['critical', 'high']]
        if critical_high:
            recommendations.append({
                'priority': 1,
                'title': 'Immediate Remediation Required',
                'description': f'{len(critical_high)} critical/high severity vulnerabilities need immediate attention',
                'actions': [
                    f"Fix {v.get('name')} at {v.get('url', 'N/A')}"
                    for v in critical_high[:5]
                ]
            })

        # Priority 2: Type-specific recommendations
        for vuln_type in vuln_types:
            if vuln_type in self.BEST_PRACTICES:
                bp = self.BEST_PRACTICES[vuln_type]
                recommendations.append({
                    'priority': 2,
                    'title': bp['title'],
                    'description': f'Implement {vuln_type} prevention measures',
                    'actions': bp['practices'][:3]
                })

        # Priority 3: General security improvements
        recommendations.append({
            'priority': 3,
            'title': 'Security Program Enhancement',
            'description': 'Long-term security improvements',
            'actions': [
                'Implement security code review process',
                'Deploy Web Application Firewall (WAF)',
                'Enable security monitoring and alerting',
                'Schedule regular security assessments'
            ]
        })

        return sorted(recommendations, key=lambda x: x['priority'])

    def _generate_executive_summary(
        self,
        vulnerabilities: List[Dict],
        analysis: Dict
    ) -> str:
        """Generate executive summary for non-technical stakeholders."""
        total = len(vulnerabilities)
        risk_level = analysis['risk_assessment'].get('risk_level', 'Unknown')
        risk_score = analysis['risk_assessment'].get('risk_score', 0)

        severity_counts = analysis['risk_assessment'].get('by_severity', {})
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)

        # Build summary
        summary_parts = [
            f"This security assessment identified {total} vulnerabilities "
            f"with an overall risk level of {risk_level} (score: {risk_score}/100)."
        ]

        if critical > 0 or high > 0:
            summary_parts.append(
                f" Of these, {critical} are critical and {high} are high severity, "
                f"requiring immediate remediation to protect against potential attacks."
            )

        if analysis.get('correlations'):
            summary_parts.append(
                f" Analysis identified {len(analysis['correlations'])} vulnerability "
                f"combinations that could be chained together for more severe attacks."
            )

        # Threat context
        threat_model = analysis.get('threat_model')
        if threat_model and threat_model.threat_actors:
            actors = ', '.join(threat_model.threat_actors[:3])
            summary_parts.append(
                f" The identified vulnerabilities are attractive targets for: {actors}."
            )

        # Recommendation
        if risk_level in ['Critical', 'High']:
            summary_parts.append(
                " Immediate action is strongly recommended to address these security issues."
            )
        else:
            summary_parts.append(
                " While not immediately critical, addressing these issues will improve "
                "the overall security posture of the application."
            )

        return ''.join(summary_parts)
