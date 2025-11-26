"""
Async Web Crawler for VulnHawk

High-performance async crawler with:
- Depth-limited crawling
- Scope restrictions
- URL deduplication
- Robots.txt compliance
- Progress tracking
"""

import asyncio
import re
from typing import Set, List, Dict, Optional, Callable, AsyncGenerator
from urllib.parse import urlparse, urljoin, urldefrag
from dataclasses import dataclass, field
import logging

from app.scanner.core.requester import AsyncRequester, Response
from app.scanner.core.parser import HTMLParser, ParsedPage

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of crawling a single URL."""
    url: str
    response: Response
    parsed: Optional[ParsedPage] = None
    depth: int = 0
    error: Optional[str] = None


@dataclass
class CrawlStats:
    """Crawling statistics."""
    urls_discovered: int = 0
    urls_crawled: int = 0
    urls_skipped: int = 0
    urls_failed: int = 0
    forms_found: int = 0
    parameters_found: int = 0


class AsyncCrawler:
    """
    Async web crawler for vulnerability scanning.

    Features:
    - Async crawling with configurable concurrency
    - Depth-limited traversal
    - Scope restrictions (domain, subdomain, path)
    - URL normalization and deduplication
    - Robots.txt compliance (optional)
    - Progress callbacks
    - Graceful cancellation
    """

    # URL patterns to skip
    SKIP_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.doc', '.docx',
        '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar', '.tar', '.gz',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.xml', '.json', '.rss', '.atom'
    }

    SKIP_PATTERNS = [
        r'logout', r'signout', r'sign-out', r'log-out',
        r'delete', r'remove', r'unsubscribe',
        r'\?.*logout', r'\?.*delete'
    ]

    def __init__(
            self,
            requester: AsyncRequester,
            max_depth: int = 5,
            max_pages: int = 100,
            scope: str = 'domain',  # 'domain', 'subdomain', 'path'
            respect_robots: bool = True,
            excluded_paths: Optional[List[str]] = None,
            included_paths: Optional[List[str]] = None,
            progress_callback: Optional[Callable[[int, int, str], None]] = None
    ):
        """
        Initialize the crawler.

        Args:
            requester: AsyncRequester instance
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            scope: Scope restriction type
            respect_robots: Whether to respect robots.txt
            excluded_paths: Paths to exclude
            included_paths: Paths to include (if set, only these are crawled)
            progress_callback: Callback for progress updates (current, total, url)
        """
        self.requester = requester
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope = scope
        self.respect_robots = respect_robots
        self.excluded_paths = excluded_paths or []
        self.included_paths = included_paths or []
        self.progress_callback = progress_callback

        # State
        self._visited: Set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._robots_rules: Dict[str, List[str]] = {}
        self._cancelled = False
        self._base_url: str = ''
        self._base_domain: str = ''
        self._base_path: str = ''

        # Statistics
        self.stats = CrawlStats()

        # Results storage
        self.results: List[CrawlResult] = []
        self.all_forms = []
        self.all_parameters = []

    async def crawl(self, start_url: str) -> List[CrawlResult]:
        """
        Crawl website starting from the given URL.

        Args:
            start_url: Starting URL

        Returns:
            List of CrawlResult objects
        """
        # Initialize
        self._base_url = start_url
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        self._base_path = parsed.path.rsplit('/', 1)[0] if '/' in parsed.path else ''

        self._visited.clear()
        self.results.clear()
        self.all_forms.clear()
        self.all_parameters.clear()
        self._cancelled = False
        self.stats = CrawlStats()

        # Fetch robots.txt if needed
        if self.respect_robots:
            await self._fetch_robots(start_url)

        # Add start URL to queue
        await self._queue.put((start_url, 0))
        self.stats.urls_discovered = 1

        # Create worker tasks
        workers = [
            asyncio.create_task(self._worker())
            for _ in range(min(5, self.max_pages))
        ]

        # Wait for queue to be processed
        await self._queue.join()

        # Cancel workers
        for worker in workers:
            worker.cancel()

        return self.results

    async def _worker(self):
        """Worker coroutine for processing URLs."""
        while not self._cancelled:
            try:
                url, depth = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                await self._process_url(url, depth)
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
            finally:
                self._queue.task_done()

    async def _process_url(self, url: str, depth: int):
        """Process a single URL."""
        # Check limits
        if len(self.results) >= self.max_pages:
            self._cancelled = True
            return

        # Normalize URL
        url = self._normalize_url(url)

        # Skip if already visited
        if url in self._visited:
            return

        self._visited.add(url)

        # Check if URL should be crawled
        if not self._should_crawl(url):
            self.stats.urls_skipped += 1
            return

        # Progress callback
        if self.progress_callback:
            progress = int((len(self.results) / self.max_pages) * 100)
            self.progress_callback(len(self.results), self.max_pages, url)

        # Fetch URL
        response = await self.requester.get(url)

        if response.error:
            self.stats.urls_failed += 1
            self.results.append(CrawlResult(
                url=url,
                response=response,
                depth=depth,
                error=response.error
            ))
            return

        self.stats.urls_crawled += 1

        # Parse HTML
        parsed = None
        if response.is_html:
            parser = HTMLParser(self._base_url)
            parsed = parser.parse(response.body, url)

            # Collect forms
            for form in parsed.forms:
                self.all_forms.append((url, form))
                self.stats.forms_found += 1

            # Collect parameters from links
            for link in parsed.links:
                if link.has_parameters:
                    for param, value in link.parameters.items():
                        self.all_parameters.append((link.url, param, value))
                        self.stats.parameters_found += 1

            # Add new URLs to queue
            if depth < self.max_depth:
                for link in parsed.links:
                    if link.is_internal and link.url not in self._visited:
                        normalized = self._normalize_url(link.url)
                        if normalized not in self._visited:
                            await self._queue.put((normalized, depth + 1))
                            self.stats.urls_discovered += 1

        # Store result
        self.results.append(CrawlResult(
            url=url,
            response=response,
            parsed=parsed,
            depth=depth
        ))

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        # Remove fragment
        url, _ = urldefrag(url)

        # Parse and reconstruct
        parsed = urlparse(url)

        # Normalize path
        path = parsed.path
        if not path:
            path = '/'
        elif path != '/' and path.endswith('/'):
            path = path.rstrip('/')

        # Sort query parameters for consistency
        if parsed.query:
            from urllib.parse import parse_qsl, urlencode
            params = sorted(parse_qsl(parsed.query))
            query = urlencode(params)
        else:
            query = ''

        # Reconstruct URL
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if query:
            normalized += f"?{query}"

        return normalized

    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled based on scope and rules."""
        parsed = urlparse(url)

        # Must be HTTP(S)
        if parsed.scheme not in ('http', 'https'):
            return False

        # Check scope
        if self.scope == 'domain':
            # Same domain
            if parsed.netloc != self._base_domain:
                return False

        elif self.scope == 'subdomain':
            # Same domain or subdomain
            if not (parsed.netloc == self._base_domain or
                    parsed.netloc.endswith('.' + self._base_domain)):
                return False

        elif self.scope == 'path':
            # Same domain and path prefix
            if parsed.netloc != self._base_domain:
                return False
            if not parsed.path.startswith(self._base_path):
                return False

        # Check excluded paths
        for excluded in self.excluded_paths:
            if excluded in parsed.path:
                return False

        # Check included paths (if set)
        if self.included_paths:
            if not any(included in parsed.path for included in self.included_paths):
                return False

        # Check file extension
        path_lower = parsed.path.lower()
        for ext in self.SKIP_EXTENSIONS:
            if path_lower.endswith(ext):
                return False

        # Check skip patterns
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        # Check robots.txt
        if self.respect_robots:
            if not self._is_allowed_by_robots(url):
                return False

        return True

    async def _fetch_robots(self, base_url: str):
        """Fetch and parse robots.txt."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        response = await self.requester.get(robots_url)

        if response.is_success:
            self._parse_robots(response.body)

    def _parse_robots(self, content: str):
        """Parse robots.txt content."""
        disallow_rules = []
        current_agent = None

        for line in content.split('\n'):
            line = line.strip().lower()

            if line.startswith('user-agent:'):
                agent = line.split(':', 1)[1].strip()
                if agent == '*' or 'vulnhawk' in agent:
                    current_agent = agent

            elif line.startswith('disallow:') and current_agent:
                path = line.split(':', 1)[1].strip()
                if path:
                    disallow_rules.append(path)

        self._robots_rules[self._base_domain] = disallow_rules

    def _is_allowed_by_robots(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        parsed = urlparse(url)
        rules = self._robots_rules.get(parsed.netloc, [])

        for rule in rules:
            if parsed.path.startswith(rule):
                return False

        return True

    def cancel(self):
        """Cancel the crawl."""
        self._cancelled = True

    def get_stats(self) -> Dict:
        """Get crawl statistics."""
        return {
            'urls_discovered': self.stats.urls_discovered,
            'urls_crawled': self.stats.urls_crawled,
            'urls_skipped': self.stats.urls_skipped,
            'urls_failed': self.stats.urls_failed,
            'forms_found': self.stats.forms_found,
            'parameters_found': self.stats.parameters_found
        }

    async def crawl_async_generator(self, start_url: str) -> AsyncGenerator[CrawlResult, None]:
        """
        Crawl website as an async generator.

        Yields CrawlResult objects as they are discovered.
        """
        # Initialize
        self._base_url = start_url
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        self._base_path = parsed.path.rsplit('/', 1)[0] if '/' in parsed.path else ''

        self._visited.clear()
        self._cancelled = False

        # Fetch robots.txt if needed
        if self.respect_robots:
            await self._fetch_robots(start_url)

        # Queue for URLs to process
        queue = [(start_url, 0)]

        while queue and not self._cancelled and len(self.results) < self.max_pages:
            url, depth = queue.pop(0)

            # Normalize and check
            url = self._normalize_url(url)
            if url in self._visited or not self._should_crawl(url):
                continue

            self._visited.add(url)

            # Fetch
            response = await self.requester.get(url)

            if response.error:
                continue

            # Parse
            parsed_page = None
            if response.is_html:
                parser = HTMLParser(self._base_url)
                parsed_page = parser.parse(response.body, url)

                # Add new URLs
                if depth < self.max_depth:
                    for link in parsed_page.links:
                        if link.is_internal:
                            queue.append((link.url, depth + 1))

            result = CrawlResult(
                url=url,
                response=response,
                parsed=parsed_page,
                depth=depth
            )

            self.results.append(result)
            yield result
