"""
VulnHawk Scanner Engine

The main orchestrator for vulnerability scanning.
Coordinates crawling, testing, and reporting.
"""

import asyncio
import logging
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime
from dataclasses import dataclass
import traceback

from app.scanner.core.requester import AsyncRequester
from app.scanner.core.crawler import AsyncCrawler, CrawlResult
from app.scanner.core.parser import HTMLParser

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Scanner configuration."""
    max_depth: int = 5
    max_pages: int = 100
    timeout: int = 30
    delay: float = 0.5
    concurrent_requests: int = 10
    follow_redirects: bool = True
    respect_robots_txt: bool = True
    verify_ssl: bool = True
    scan_modules: List[str] = None
    authentication: Optional[Dict] = None
    custom_headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    excluded_paths: Optional[List[str]] = None
    included_paths: Optional[List[str]] = None
    proxy: Optional[str] = None

    def __post_init__(self):
        if self.scan_modules is None:
            self.scan_modules = [
                # Basic modules
                'xss', 'sqli', 'csrf', 'headers',
                'ssl', 'info_disclosure', 'open_redirect',
                'lfi', 'ssrf', 'ssti',
                # Advanced modules (hard-to-find vulnerabilities)
                'dom_xss', 'idor', 'jwt', 'mass_assignment'
            ]


class ScannerEngine:
    """
    Main vulnerability scanner engine.

    Orchestrates:
    1. Web crawling to discover pages
    2. Form and parameter extraction
    3. Vulnerability module execution
    4. Result aggregation
    5. Progress reporting

    Features:
    - Modular vulnerability detection
    - Async execution for performance
    - Real-time progress updates
    - Graceful error handling
    - Scan state persistence
    """

    def __init__(
            self,
            config: Optional[ScanConfig] = None,
            progress_callback: Optional[Callable[[Dict], None]] = None,
            vulnerability_callback: Optional[Callable[[Dict], None]] = None
    ):
        """
        Initialize the scanner engine.

        Args:
            config: Scanner configuration
            progress_callback: Called with progress updates
            vulnerability_callback: Called when vulnerability is found
        """
        self.config = config or ScanConfig()
        self.progress_callback = progress_callback
        self.vulnerability_callback = vulnerability_callback

        # Components
        self.requester: Optional[AsyncRequester] = None
        self.crawler: Optional[AsyncCrawler] = None

        # State
        self._is_running = False
        self._is_cancelled = False
        self._current_phase = 'idle'
        self._start_time: Optional[datetime] = None

        # Results
        self.vulnerabilities: List[Dict] = []
        self.crawl_results: List[CrawlResult] = []
        self.scan_stats: Dict[str, Any] = {}

        # Loaded modules
        self._modules: Dict[str, Any] = {}

    async def scan(self, target_url: str) -> Dict:
        """
        Execute a full vulnerability scan.

        Args:
            target_url: Target URL to scan

        Returns:
            Scan results dictionary
        """
        self._is_running = True
        self._is_cancelled = False
        self._start_time = datetime.utcnow()
        self.vulnerabilities = []
        self.crawl_results = []

        try:
            # Initialize components
            await self._initialize()

            # Load scan modules
            self._load_modules()

            # Phase 1: Crawling
            await self._phase_crawl(target_url)

            if self._is_cancelled:
                return self._build_results('cancelled')

            # Phase 2: Passive Analysis
            await self._phase_passive_analysis()

            if self._is_cancelled:
                return self._build_results('cancelled')

            # Phase 3: Active Testing
            await self._phase_active_testing()

            return self._build_results('completed')

        except Exception as e:
            logger.error(f"Scan error: {e}\n{traceback.format_exc()}")
            return self._build_results('failed', str(e))

        finally:
            await self._cleanup()
            self._is_running = False

    async def _initialize(self):
        """Initialize scanner components."""
        self._update_progress('initializing', 0, 'Initializing scanner...')

        # Create requester
        self.requester = AsyncRequester(
            timeout=self.config.timeout,
            max_concurrent=self.config.concurrent_requests,
            delay=self.config.delay,
            verify_ssl=self.config.verify_ssl,
            custom_headers=self.config.custom_headers,
            cookies=self.config.cookies,
            proxy=self.config.proxy
        )

        await self.requester.start()

        # Create crawler
        self.crawler = AsyncCrawler(
            requester=self.requester,
            max_depth=self.config.max_depth,
            max_pages=self.config.max_pages,
            respect_robots=self.config.respect_robots_txt,
            excluded_paths=self.config.excluded_paths,
            included_paths=self.config.included_paths
        )

    def _load_modules(self):
        """Load vulnerability detection modules."""
        self._update_progress('loading_modules', 5, 'Loading scan modules...')

        # Import modules dynamically
        module_mapping = {
            # Basic vulnerability modules
            'xss': 'app.scanner.modules.xss',
            'sqli': 'app.scanner.modules.sqli',
            'csrf': 'app.scanner.modules.csrf',
            'headers': 'app.scanner.modules.headers',
            'ssl': 'app.scanner.modules.ssl_check',
            'info_disclosure': 'app.scanner.modules.info_disclosure',
            'open_redirect': 'app.scanner.modules.open_redirect',
            'lfi': 'app.scanner.modules.lfi',
            'ssrf': 'app.scanner.modules.ssrf',
            'ssti': 'app.scanner.modules.ssti',
            # Advanced vulnerability modules (hard-to-find)
            'dom_xss': 'app.scanner.modules.dom_xss',
            'idor': 'app.scanner.modules.idor',
            'jwt': 'app.scanner.modules.jwt',
            'mass_assignment': 'app.scanner.modules.mass_assignment',
        }

        for module_name in self.config.scan_modules:
            if module_name in module_mapping:
                try:
                    import importlib
                    module_path = module_mapping[module_name]
                    module = importlib.import_module(module_path)
                    self._modules[module_name] = module
                    logger.info(f"Loaded module: {module_name}")
                except ImportError as e:
                    logger.warning(f"Failed to load module {module_name}: {e}")

    async def _phase_crawl(self, target_url: str):
        """Phase 1: Crawl the target website."""
        self._current_phase = 'crawling'
        self._update_progress('crawling', 10, f'Crawling {target_url}...')

        def crawl_progress(current, total, url):
            progress = 10 + int((current / max(total, 1)) * 30)
            self._update_progress('crawling', progress, f'Crawling: {url[:50]}...')

        self.crawler.progress_callback = crawl_progress

        # Execute crawl
        self.crawl_results = await self.crawler.crawl(target_url)

        # Update stats
        self.scan_stats['crawl'] = self.crawler.get_stats()
        self.scan_stats['crawl']['duration'] = (
                datetime.utcnow() - self._start_time
        ).total_seconds()

        self._update_progress(
            'crawling',
            40,
            f'Crawl complete. Found {len(self.crawl_results)} pages.'
        )

    async def _phase_passive_analysis(self):
        """Phase 2: Passive analysis (no active attacks)."""
        self._current_phase = 'passive_analysis'
        self._update_progress('passive_analysis', 45, 'Running passive analysis...')

        total_pages = len(self.crawl_results)

        for i, result in enumerate(self.crawl_results):
            if self._is_cancelled:
                return

            progress = 45 + int((i / max(total_pages, 1)) * 15)
            self._update_progress(
                'passive_analysis',
                progress,
                f'Analyzing: {result.url[:50]}...'
            )

            # Run passive checks
            await self._run_passive_checks(result)

        self._update_progress('passive_analysis', 60, 'Passive analysis complete.')

    async def _run_passive_checks(self, result: CrawlResult):
        """Run passive security checks on a page."""
        # Security Headers Check
        if 'headers' in self._modules:
            try:
                module = self._modules['headers']
                vulns = await module.check(result.response, result.url)
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"Headers check error: {e}")

        # SSL Check (for HTTPS URLs)
        if 'ssl' in self._modules and result.url.startswith('https://'):
            try:
                module = self._modules['ssl']
                vulns = await module.check(result.response, result.url)
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"SSL check error: {e}")

        # Information Disclosure Check
        if 'info_disclosure' in self._modules:
            try:
                module = self._modules['info_disclosure']
                vulns = await module.check(result.response, result.url, result.parsed)
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"Info disclosure check error: {e}")

        # CSRF Check (on forms)
        if 'csrf' in self._modules and result.parsed:
            try:
                module = self._modules['csrf']
                for form in result.parsed.forms:
                    vulns = await module.check(form, result.url)
                    for vuln in vulns:
                        self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"CSRF check error: {e}")

    async def _phase_active_testing(self):
        """Phase 3: Active vulnerability testing."""
        self._current_phase = 'active_testing'
        self._update_progress('active_testing', 65, 'Running active tests...')

        # Collect all test targets
        test_targets = self._collect_test_targets()
        total_targets = len(test_targets)

        self.scan_stats['active_testing'] = {
            'total_targets': total_targets,
            'tested': 0,
            'vulnerabilities_found': 0
        }

        for i, target in enumerate(test_targets):
            if self._is_cancelled:
                return

            progress = 65 + int((i / max(total_targets, 1)) * 30)
            self._update_progress(
                'active_testing',
                progress,
                f'Testing: {target["url"][:40]}...'
            )

            # Run active tests
            await self._run_active_tests(target)
            self.scan_stats['active_testing']['tested'] = i + 1

        self._update_progress('active_testing', 95, 'Active testing complete.')

    def _collect_test_targets(self) -> List[Dict]:
        """Collect all targets for active testing."""
        targets = []

        # URL parameters
        for url, form in self.crawler.all_forms:
            for field in form.injectable_fields:
                targets.append({
                    'type': 'form',
                    'url': form.action,
                    'method': form.method,
                    'parameter': field.name,
                    'value': field.value,
                    'form': form
                })

        # Link parameters
        for url, param, value in self.crawler.all_parameters:
            targets.append({
                'type': 'url',
                'url': url,
                'method': 'GET',
                'parameter': param,
                'value': value
            })

        return targets

    async def _run_active_tests(self, target: Dict):
        """Run active tests on a target."""
        # XSS Testing
        if 'xss' in self._modules:
            try:
                module = self._modules['xss']
                vulns = await module.test(
                    self.requester,
                    target['url'],
                    target['parameter'],
                    target['value'],
                    target['method']
                )
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"XSS test error: {e}")

        # SQL Injection Testing
        if 'sqli' in self._modules:
            try:
                module = self._modules['sqli']
                vulns = await module.test(
                    self.requester,
                    target['url'],
                    target['parameter'],
                    target['value'],
                    target['method']
                )
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"SQLi test error: {e}")

        # LFI Testing
        if 'lfi' in self._modules:
            try:
                module = self._modules['lfi']
                vulns = await module.test(
                    self.requester,
                    target['url'],
                    target['parameter'],
                    target['value'],
                    target['method']
                )
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"LFI test error: {e}")

        # Open Redirect Testing
        if 'open_redirect' in self._modules:
            try:
                module = self._modules['open_redirect']
                vulns = await module.test(
                    self.requester,
                    target['url'],
                    target['parameter'],
                    target['value'],
                    target['method']
                )
                for vuln in vulns:
                    self._add_vulnerability(vuln)
            except Exception as e:
                logger.error(f"Open redirect test error: {e}")

    def _add_vulnerability(self, vuln: Dict):
        """Add a discovered vulnerability."""
        self.vulnerabilities.append(vuln)
        self.scan_stats['active_testing']['vulnerabilities_found'] = len(self.vulnerabilities)

        if self.vulnerability_callback:
            self.vulnerability_callback(vuln)

        logger.info(f"Found vulnerability: {vuln.get('name')} at {vuln.get('url')}")

    def _update_progress(self, phase: str, progress: int, message: str):
        """Update scan progress."""
        self._current_phase = phase

        if self.progress_callback:
            self.progress_callback({
                'phase': phase,
                'progress': progress,
                'message': message,
                'vulnerabilities_count': len(self.vulnerabilities),
                'pages_crawled': len(self.crawl_results)
            })

    def _build_results(self, status: str, error: Optional[str] = None) -> Dict:
        """Build final scan results."""
        end_time = datetime.utcnow()
        duration = (end_time - self._start_time).total_seconds() if self._start_time else 0

        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            'status': status,
            'error': error,
            'duration': duration,
            'start_time': self._start_time.isoformat() if self._start_time else None,
            'end_time': end_time.isoformat(),
            'statistics': {
                'pages_crawled': len(self.crawl_results),
                'forms_found': self.scan_stats.get('crawl', {}).get('forms_found', 0),
                'parameters_tested': self.scan_stats.get('crawl', {}).get('parameters_found', 0),
                'vulnerabilities': severity_counts,
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities,
            'crawl_stats': self.scan_stats.get('crawl', {})
        }

    async def _cleanup(self):
        """Cleanup resources."""
        if self.requester:
            await self.requester.close()

    def cancel(self):
        """Cancel the running scan."""
        self._is_cancelled = True
        if self.crawler:
            self.crawler.cancel()

    @property
    def is_running(self) -> bool:
        """Check if scan is running."""
        return self._is_running

    @property
    def current_phase(self) -> str:
        """Get current scan phase."""
        return self._current_phase
