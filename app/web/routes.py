"""
VulnHawk Web Routes

Secure web interface routes with comprehensive security controls.
"""

from flask import render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from urllib.parse import urlparse, urljoin
from datetime import datetime
import logging

from app.web import web_bp
from app import db, limiter
from app.models import User, Scan, ScanStatus, Vulnerability

# Security logger
security_logger = logging.getLogger('security')


def is_safe_url(target):
    """
    SECURITY: Validate redirect URL to prevent Open Redirect attacks.
    Only allows relative URLs or URLs to the same host.
    """
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


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
    if current_user.is_authenticated and current_user.is_admin:
        return True
    return False


# ==================== Forms ====================

class LoginForm(FlaskForm):
    """Login form with CSRF protection."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')


class RegisterForm(FlaskForm):
    """Registration form with validation."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.lower()).first():
            raise ValidationError('Username already exists')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email already registered')


class ScanForm(FlaskForm):
    """Scan configuration form."""
    # Using StringField instead of URLField to allow localhost for testing
    target_url = StringField('Target URL', validators=[DataRequired(), Length(min=5, max=2048)])
    scan_modules = SelectMultipleField('Scan Modules', choices=[
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'CSRF Detection'),
        ('headers', 'Security Headers'),
        ('ssl', 'SSL/TLS Analysis'),
        ('info_disclosure', 'Information Disclosure'),
        ('lfi', 'Local File Inclusion'),
        ('open_redirect', 'Open Redirect'),
    ])


# ==================== Routes ====================

@web_bp.route('/')
def index():
    """Home page."""
    # Get recent scans
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()

    # Get stats
    stats = {
        'total_scans': Scan.query.count(),
        'completed_scans': Scan.query.filter_by(status=ScanStatus.COMPLETED).count(),
        'total_vulnerabilities': Vulnerability.query.count()
    }

    return render_template('index.html', recent_scans=recent_scans, stats=stats)


@web_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Login page with secure session handling."""
    if current_user.is_authenticated:
        return redirect(url_for('web.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()

        if user and user.is_locked():
            security_logger.warning(f"Login attempt on locked account: {form.username.data}")
            flash('Account is temporarily locked. Try again later.', 'danger')
            return render_template('login.html', form=form)

        if user and user.check_password(form.password.data):
            # SECURITY FIX: Regenerate session ID to prevent session fixation
            session.clear()

            user.record_successful_login()
            login_user(user, remember=form.remember.data)

            # Set session permanence based on remember me
            session.permanent = form.remember.data

            security_logger.info(f"Successful login: {user.username}")
            flash('Login successful!', 'success')

            # SECURITY FIX: Validate redirect URL to prevent Open Redirect
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('web.dashboard'))

        if user:
            user.record_failed_login()
            security_logger.warning(f"Failed login attempt for user: {form.username.data}")
        else:
            security_logger.warning(f"Login attempt for non-existent user: {form.username.data}")

        flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@web_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    """Registration page with secure error handling."""
    if current_user.is_authenticated:
        return redirect(url_for('web.dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
            )
            db.session.add(user)
            db.session.commit()

            security_logger.info(f"New user registered: {form.username.data}")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('web.login'))

        except ValueError as e:
            # SECURITY FIX: Only show safe validation messages, not internal errors
            error_msg = str(e)
            if 'password' in error_msg.lower():
                flash('Password must be at least 8 characters with uppercase, lowercase, number, and special character.', 'danger')
            elif 'email' in error_msg.lower():
                flash('Please enter a valid email address.', 'danger')
            elif 'username' in error_msg.lower():
                flash('Username must be 3-80 characters and contain only letters, numbers, and underscores.', 'danger')
            else:
                flash('Invalid input. Please check your information.', 'danger')
            security_logger.warning(f"Registration validation error: {error_msg}")
        except Exception as e:
            db.session.rollback()
            # SECURITY FIX: Log the actual error but show generic message
            security_logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html', form=form)


@web_bp.route('/logout')
@login_required
def logout():
    """Logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('web.index'))


@web_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    # Get user's scans
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.created_at.desc()
    ).limit(10).all()

    return render_template('dashboard.html', scans=user_scans)


def check_url_reachable(url: str, timeout: int = 10) -> tuple:
    """
    Check if a URL is reachable before starting a scan.

    Returns:
        tuple: (is_reachable: bool, error_message: str or None)
    """
    import requests
    from urllib.parse import urlparse

    try:
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)

        if parsed.scheme not in ('http', 'https'):
            return False, f"Invalid URL scheme: {parsed.scheme}. Only HTTP and HTTPS are supported."

        if not parsed.netloc:
            return False, "Invalid URL: No host specified."

        # Try to reach the URL
        response = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)

        # Accept any response (even 4xx/5xx means server is running)
        return True, None

    except requests.exceptions.ConnectionError:
        return False, f"Connection failed: The server at {url} is not reachable. Please check if the server is running."
    except requests.exceptions.Timeout:
        return False, f"Connection timeout: The server at {url} did not respond within {timeout} seconds."
    except requests.exceptions.TooManyRedirects:
        return False, f"Too many redirects: The URL {url} has too many redirects."
    except requests.exceptions.SSLError as e:
        # SSL errors but server is reachable - allow scan
        return True, None
    except requests.exceptions.RequestException as e:
        return False, f"Request failed: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


@web_bp.route('/scan', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def new_scan():
    """Create new scan page."""
    form = ScanForm()

    if form.validate_on_submit():
        try:
            # Validate URL
            url = form.target_url.data.strip()

            # Check if URL is reachable before creating scan
            is_reachable, error_msg = check_url_reachable(url)
            if not is_reachable:
                flash(error_msg, 'danger')
                return render_template('scan.html', form=form)

            # Create scan config
            config = {
                'scan_modules': form.scan_modules.data or [
                    'xss', 'sqli', 'csrf', 'headers', 'info_disclosure'
                ],
                'max_depth': 5,
                'max_pages': 100
            }

            # Create scan
            scan = Scan(
                target_url=url,
                config=config,
                user_id=current_user.id if current_user.is_authenticated else None
            )

            db.session.add(scan)
            db.session.commit()

            flash('Scan created successfully! Target is reachable.', 'success')
            return redirect(url_for('web.scan_detail', scan_id=scan.scan_id))

        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Failed to create scan. Please try again.', 'danger')

    return render_template('scan.html', form=form)


@web_bp.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Scan detail page with IDOR protection."""
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY FIX: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized scan access attempt: {scan_id} by user {current_user.id if current_user.is_authenticated else 'anonymous'}")
        abort(403)

    # Get vulnerabilities
    vulnerabilities = scan.vulnerabilities.all()

    return render_template('scan_detail.html', scan=scan, vulnerabilities=vulnerabilities, now=datetime.utcnow())


@web_bp.route('/scan/<scan_id>/delete', methods=['POST'])
def scan_delete(scan_id):
    """Delete a scan and all associated vulnerabilities."""
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized scan delete attempt: {scan_id} by user {current_user.id if current_user.is_authenticated else 'anonymous'}")
        abort(403)

    try:
        # Delete associated vulnerabilities first
        Vulnerability.query.filter_by(scan_id=scan.id).delete()

        # Delete the scan
        db.session.delete(scan)
        db.session.commit()

        flash('Scan deleted successfully', 'success')
        security_logger.info(f"Scan deleted: {scan_id}")
    except Exception as e:
        db.session.rollback()
        flash('Error deleting scan', 'error')
        security_logger.error(f"Error deleting scan {scan_id}: {e}")

    return redirect(url_for('web.index'))


@web_bp.route('/scan/<scan_id>/report')
def scan_report(scan_id):
    """View scan report with IDOR protection."""
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY FIX: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized report access attempt: {scan_id}")
        abort(403)

    if scan.status != ScanStatus.COMPLETED:
        flash('Scan is not completed yet.', 'warning')
        return redirect(url_for('web.scan_detail', scan_id=scan_id))

    vulnerabilities = scan.vulnerabilities.order_by(Vulnerability.severity.desc()).all()

    return render_template('report.html', scan=scan, vulnerabilities=vulnerabilities)


@web_bp.route('/scan/<scan_id>/ai-analysis')
def ai_analysis(scan_id):
    """AI-powered security analysis page."""
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized AI analysis access attempt: {scan_id}")
        abort(403)

    if scan.status != ScanStatus.COMPLETED:
        flash('Scan must be completed for AI analysis.', 'warning')
        return redirect(url_for('web.scan_detail', scan_id=scan_id))

    vulnerabilities = scan.vulnerabilities.order_by(Vulnerability.severity.desc()).all()

    return render_template('ai_analysis.html', scan=scan, vulnerabilities=vulnerabilities)


@web_bp.route('/scan/<scan_id>/start', methods=['POST'])
@limiter.limit("10 per hour")
def start_scan_action(scan_id):
    """Start a pending scan with IDOR protection."""
    import multiprocessing
    from flask import current_app

    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY FIX: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized scan start attempt: {scan_id}")
        abort(403)

    if scan.status != ScanStatus.PENDING:
        flash(f'Scan is already {scan.status.value}', 'warning')
        return redirect(url_for('web.scan_detail', scan_id=scan_id))

    try:
        # Capture data for subprocess
        target_url = scan.target_url
        scan_db_id = scan.id
        scan_config_data = scan.config

        # Start scan status
        scan.start()

        flash('Scan started successfully! The page will refresh automatically.', 'success')

        # Start background process for scanning
        process = multiprocessing.Process(
            target=_run_scan_process,
            args=(scan_db_id, target_url, scan_config_data),
            name=f"scan-{scan_id}"
        )
        process.daemon = True
        process.start()

        return redirect(url_for('web.scan_detail', scan_id=scan_id))

    except Exception as e:
        scan.fail(str(e))
        flash(f'Scan failed: {str(e)}', 'danger')
        return redirect(url_for('web.scan_detail', scan_id=scan_id))


def _run_scan_process(scan_db_id, target_url, scan_config_data):
    """
    Run TURBO scan in a separate process for 100x speed improvement.

    Uses the TurboScannerEngine with:
    - 50 parallel crawler workers (vs 5)
    - 100 concurrent HTTP connections (vs 10)
    - Zero rate limiting delay (vs 0.5s)
    - Parallel vulnerability testing (20 targets at once)
    - Batch payload processing
    - Real-time progress tracking with EMA time estimation
    """
    import asyncio
    import selectors
    import sys
    import time

    # IMPORTANT: Use SelectSelector to avoid macOS kqueue bug in Python 3.9
    selector = selectors.SelectSelector()
    loop = asyncio.SelectorEventLoop(selector)
    asyncio.set_event_loop(loop)

    # Create fresh Flask app in the subprocess
    from app import create_app, db
    from app.models import Scan, Vulnerability

    app = create_app()

    with app.app_context():
        try:
            start_time = time.time()

            # EMA (Exponential Moving Average) smoothing for rate calculation
            ema_rate = 0.0
            ema_alpha = 0.3  # 30% weight to new value
            last_progress = 0
            last_update_time = start_time

            # Try to use TurboScannerEngine for 100x speedup
            try:
                from app.scanner.core.engine_turbo import TurboScannerEngine, TurboScanConfig

                # Create TURBO config - optimized for maximum speed
                config = TurboScanConfig(
                    max_depth=scan_config_data.get('max_depth', 5),
                    max_pages=scan_config_data.get('max_pages', 200),
                    timeout=10,  # Short timeout
                    delay=0.0,  # NO DELAY - critical for 100x speed
                    concurrent_requests=100,  # 10x more concurrent
                    concurrent_targets=20,  # Test 20 targets in parallel
                    concurrent_payloads=10,  # Test 10 payloads at once
                    crawler_workers=50,  # 10x more workers
                    verify_ssl=False,  # Skip SSL for local testing
                    respect_robots_txt=False,  # Skip robots.txt
                    scan_modules=scan_config_data.get('scan_modules', [
                        'xss', 'sqli', 'csrf', 'headers', 'info_disclosure', 'lfi', 'open_redirect'
                    ]),
                    early_termination=True,  # Stop on first confirmed vuln per param
                )

                print(f"[TURBO MODE] Starting high-performance scan for {target_url}")
                print(f"[TURBO MODE] 50 crawler workers, 100 concurrent connections, 0ms delay")

                # Enhanced progress callback with timing estimation
                def on_progress(data):
                    nonlocal ema_rate, last_progress, last_update_time
                    try:
                        scan_obj = db.session.get(Scan, scan_db_id)
                        if scan_obj:
                            current_progress = data.get('progress', 0)
                            current_time = time.time()

                            # Calculate elapsed and remaining time
                            elapsed = current_time - start_time
                            time_delta = current_time - last_update_time
                            progress_delta = current_progress - last_progress

                            # Update EMA rate (progress per second)
                            if time_delta > 0 and progress_delta > 0:
                                current_rate = progress_delta / time_delta
                                if ema_rate == 0:
                                    ema_rate = current_rate
                                else:
                                    ema_rate = ema_alpha * current_rate + (1 - ema_alpha) * ema_rate

                            # Estimate remaining time
                            remaining_progress = 100 - current_progress
                            remaining_time = 0
                            if ema_rate > 0 and remaining_progress > 0:
                                remaining_time = remaining_progress / ema_rate

                            # Map phase names
                            phase = data.get('phase', 'running')
                            phase_map = {
                                'initializing': 'initializing',
                                'crawling': 'crawling',
                                'passive_analysis': 'passive_analysis',
                                'active_testing': 'active_testing',
                            }
                            current_phase = phase_map.get(phase, phase)

                            # Update scan object with all timing info
                            scan_obj.progress = current_progress
                            scan_obj.current_phase = current_phase
                            scan_obj.elapsed_seconds = elapsed
                            scan_obj.estimated_remaining_seconds = remaining_time
                            scan_obj.items_per_second_rate = ema_rate
                            msg = data.get('message', '')
                            scan_obj.current_task = f"[TURBO] {msg}"[:255] if msg else None

                            # Update stats if available
                            if 'pages_crawled' in data:
                                scan_obj.urls_scanned = data.get('pages_crawled', 0)

                            db.session.commit()

                            # Update tracking variables
                            last_progress = current_progress
                            last_update_time = current_time

                    except Exception as e:
                        print(f"Progress update error: {e}")
                        db.session.rollback()

                # Vulnerability callback
                def on_vulnerability(vuln):
                    try:
                        v = Vulnerability(
                            scan_id=scan_db_id,
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
                        print(f"[TURBO] Vulnerability found: {vuln.get('name')} at {vuln.get('url')}")
                    except Exception as e:
                        print(f"Error saving vulnerability: {e}")
                        db.session.rollback()

                # Create TURBO scanner
                scanner = TurboScannerEngine(
                    config=config,
                    progress_callback=on_progress,
                    vulnerability_callback=on_vulnerability
                )

                # Run the turbo scan
                results = loop.run_until_complete(scanner.scan(target_url))

            except ImportError as e:
                # Fallback to regular scanner if turbo engine not available
                print(f"[WARNING] TurboScannerEngine not available, using standard engine: {e}")
                from app.scanner.core.engine import ScannerEngine, ScanConfig

                config = ScanConfig(
                    max_depth=scan_config_data.get('max_depth', 3),
                    max_pages=scan_config_data.get('max_pages', 50),
                    timeout=scan_config_data.get('timeout', 10),
                    delay=scan_config_data.get('delay', 0.1),
                    concurrent_requests=scan_config_data.get('concurrent_requests', 10),
                    scan_modules=scan_config_data.get('scan_modules', [
                        'xss', 'sqli', 'csrf', 'headers', 'info_disclosure'
                    ])
                )

                def on_progress(data):
                    try:
                        scan_obj = db.session.get(Scan, scan_db_id)
                        if scan_obj:
                            scan_obj.progress = data.get('progress', 0)
                            scan_obj.current_task = data.get('message', '')[:255] if data.get('message') else None
                            db.session.commit()
                    except Exception as e:
                        print(f"Progress update error: {e}")
                        db.session.rollback()

                def on_vulnerability(vuln):
                    try:
                        v = Vulnerability(
                            scan_id=scan_db_id,
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
                        print(f"Vulnerability found: {vuln.get('name')}")
                    except Exception as e:
                        print(f"Error saving vulnerability: {e}")
                        db.session.rollback()

                scanner = ScannerEngine(
                    config=config,
                    progress_callback=on_progress,
                    vulnerability_callback=on_vulnerability
                )

                print(f"Starting standard scan for {target_url}")
                results = loop.run_until_complete(scanner.scan(target_url))

            elapsed = time.time() - start_time
            print(f"Scan completed in {elapsed:.2f}s with status: {results.get('status')}")
            print(f"Total vulnerabilities: {results.get('statistics', {}).get('total_vulnerabilities', 0)}")

            # Update scan status
            scan_obj = db.session.get(Scan, scan_db_id)
            if scan_obj:
                if results.get('status') == 'completed':
                    scan_obj.complete()
                else:
                    scan_obj.fail(results.get('error', 'Unknown error'))

        except Exception as e:
            print(f"Scan process error: {e}")
            import traceback
            traceback.print_exc()
            try:
                scan_obj = db.session.get(Scan, scan_db_id)
                if scan_obj:
                    scan_obj.fail(str(e))
            except Exception:
                pass
        finally:
            loop.close()


@web_bp.route('/scan/<scan_id>/cancel', methods=['POST'])
def cancel_scan_action(scan_id):
    """Cancel a running scan with IDOR protection."""
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()

    # SECURITY FIX: Check if user has access to this scan
    if not check_scan_access(scan):
        security_logger.warning(f"Unauthorized scan cancel attempt: {scan_id}")
        abort(403)

    if scan.status != ScanStatus.RUNNING:
        flash('Scan is not running', 'warning')
        return redirect(url_for('web.scan_detail', scan_id=scan_id))

    scan.cancel()
    security_logger.info(f"Scan cancelled: {scan_id}")
    flash('Scan cancelled successfully', 'info')
    return redirect(url_for('web.scan_detail', scan_id=scan_id))


@web_bp.route('/vulnerabilities')
def vulnerabilities_list():
    """List all vulnerabilities."""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity')

    query = Vulnerability.query.order_by(Vulnerability.discovered_at.desc())

    if severity:
        from app.models.vulnerability import Severity as SevEnum
        try:
            sev = SevEnum(severity.lower())
            query = query.filter_by(severity=sev)
        except ValueError:
            pass

    pagination = query.paginate(page=page, per_page=20, error_out=False)

    return render_template('vulnerabilities.html',
                           vulnerabilities=pagination.items,
                           pagination=pagination)


@web_bp.route('/about')
def about():
    """About page."""
    return render_template('about.html')


# ==================== Error Handlers ====================

@web_bp.errorhandler(404)
def not_found(error):
    """404 error handler."""
    return render_template('errors/404.html'), 404


@web_bp.errorhandler(500)
def internal_error(error):
    """500 error handler."""
    db.session.rollback()
    return render_template('errors/500.html'), 500
