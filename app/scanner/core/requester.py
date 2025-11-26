"""
Async HTTP Requester for VulnHawk

High-performance async HTTP client with:
- Connection pooling
- Rate limiting
- Retry logic
- SSL handling
- Response caching
"""

import asyncio
import aiohttp
import hashlib
import time
from typing import Dict, Optional, Any, List, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum
import ssl
import logging

logger = logging.getLogger(__name__)


class RequestMethod(Enum):
    """HTTP request methods."""
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    HEAD = 'HEAD'
    OPTIONS = 'OPTIONS'
    PATCH = 'PATCH'


@dataclass
class Response:
    """
    Represents an HTTP response with security-relevant metadata.
    """
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    redirect_url: Optional[str] = None
    ssl_info: Optional[Dict] = None
    error: Optional[str] = None
    request_method: str = 'GET'
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """Check if request was successful (2xx status)."""
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx status)."""
        return 300 <= self.status < 400

    @property
    def is_error(self) -> bool:
        """Check if response indicates an error (4xx or 5xx)."""
        return self.status >= 400

    @property
    def content_type(self) -> str:
        """Get Content-Type header value."""
        return self.headers.get('Content-Type', '').lower()

    @property
    def is_html(self) -> bool:
        """Check if response is HTML content."""
        return 'text/html' in self.content_type

    @property
    def is_json(self) -> bool:
        """Check if response is JSON content."""
        return 'application/json' in self.content_type

    def get_header(self, name: str, default: str = '') -> str:
        """Get header value (case-insensitive)."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class AsyncRequester:
    """
    Async HTTP requester with security features.

    Features:
    - Async requests with aiohttp
    - Connection pooling
    - Rate limiting with semaphore
    - Automatic retry with backoff
    - SSL certificate handling
    - Request/Response caching
    - Custom headers support
    """

    DEFAULT_HEADERS = {
        'User-Agent': 'VulnHawk/1.0 Security Scanner (+https://github.com/manojgowda/vulnhawk)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'DNT': '1',
    }

    def __init__(
            self,
            timeout: int = 30,
            max_concurrent: int = 10,
            delay: float = 0.5,
            max_retries: int = 3,
            verify_ssl: bool = True,
            custom_headers: Optional[Dict[str, str]] = None,
            cookies: Optional[Dict[str, str]] = None,
            proxy: Optional[str] = None
    ):
        """
        Initialize the async requester.

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            delay: Delay between requests in seconds
            max_retries: Maximum retry attempts
            verify_ssl: Whether to verify SSL certificates
            custom_headers: Custom headers to include in all requests
            cookies: Cookies to include in all requests
            proxy: Proxy URL for all requests
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.delay = delay
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.proxy = proxy

        # Headers
        self.headers = self.DEFAULT_HEADERS.copy()
        if custom_headers:
            self.headers.update(custom_headers)

        # Cookies
        self.cookies = cookies or {}

        # Rate limiting
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._last_request_time: Dict[str, float] = {}

        # Session
        self._session: Optional[aiohttp.ClientSession] = None

        # Cache
        self._response_cache: Dict[str, Response] = {}
        self._cache_enabled = True

        # Statistics
        self.stats = {
            'requests_made': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'total_bytes': 0,
            'cache_hits': 0
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self):
        """Initialize the aiohttp session."""
        if self._session is None or self._session.closed:
            # SSL context
            if self.verify_ssl:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # Create connector with connection pooling
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrent * 2,
                limit_per_host=self.max_concurrent,
                ssl=ssl_context,
                enable_cleanup_closed=True
            )

            # Cookie jar
            cookie_jar = aiohttp.CookieJar(unsafe=True)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=self.headers,
                cookie_jar=cookie_jar
            )

            # Set initial cookies
            for name, value in self.cookies.items():
                self._session.cookie_jar.update_cookies({name: value})

            # Initialize semaphore
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _get_cache_key(self, url: str, method: str, data: Optional[Dict] = None) -> str:
        """Generate cache key for request."""
        key_data = f"{method}:{url}:{str(data)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    async def _rate_limit(self, domain: str):
        """Apply rate limiting for domain."""
        if domain in self._last_request_time:
            elapsed = time.time() - self._last_request_time[domain]
            if elapsed < self.delay:
                await asyncio.sleep(self.delay - elapsed)
        self._last_request_time[domain] = time.time()

    async def request(
            self,
            url: str,
            method: RequestMethod = RequestMethod.GET,
            data: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            allow_redirects: bool = True,
            use_cache: bool = True
    ) -> Response:
        """
        Make an HTTP request.

        Args:
            url: Target URL
            method: HTTP method
            data: Request body data
            headers: Additional headers
            allow_redirects: Follow redirects
            use_cache: Use response cache

        Returns:
            Response object
        """
        if self._session is None:
            await self.start()

        # Check cache
        cache_key = self._get_cache_key(url, method.value, data)
        if use_cache and self._cache_enabled and cache_key in self._response_cache:
            self.stats['cache_hits'] += 1
            return self._response_cache[cache_key]

        # Parse domain for rate limiting
        domain = urlparse(url).netloc

        # Merge headers
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)

        response = None
        last_error = None

        for attempt in range(self.max_retries):
            try:
                async with self._semaphore:
                    # Apply rate limiting
                    await self._rate_limit(domain)

                    start_time = time.time()

                    # Make request
                    async with self._session.request(
                            method.value,
                            url,
                            data=data if method != RequestMethod.GET else None,
                            params=data if method == RequestMethod.GET else None,
                            headers=request_headers,
                            allow_redirects=allow_redirects,
                            proxy=self.proxy,
                            ssl=not self.verify_ssl or None
                    ) as resp:
                        elapsed = time.time() - start_time

                        # Read body with size limit (10MB)
                        body = await resp.text(errors='ignore')
                        if len(body) > 10 * 1024 * 1024:
                            body = body[:10 * 1024 * 1024]

                        # Get headers
                        resp_headers = dict(resp.headers)

                        # Get SSL info if available
                        ssl_info = None
                        if hasattr(resp, 'connection') and resp.connection:
                            transport = resp.connection.transport
                            if hasattr(transport, 'get_extra_info'):
                                ssl_object = transport.get_extra_info('ssl_object')
                                if ssl_object:
                                    ssl_info = {
                                        'version': ssl_object.version(),
                                        'cipher': ssl_object.cipher()
                                    }

                        # Get redirect URL
                        redirect_url = None
                        if resp.history:
                            redirect_url = str(resp.history[-1].url)

                        response = Response(
                            url=str(resp.url),
                            status=resp.status,
                            headers=resp_headers,
                            body=body,
                            elapsed=elapsed,
                            redirect_url=redirect_url,
                            ssl_info=ssl_info,
                            request_method=method.value,
                            request_headers=request_headers,
                            request_body=str(data) if data else None
                        )

                        # Update stats
                        self.stats['requests_made'] += 1
                        self.stats['requests_successful'] += 1
                        self.stats['total_bytes'] += len(body)

                        # Cache response
                        if use_cache and self._cache_enabled and response.is_success:
                            self._response_cache[cache_key] = response

                        return response

            except asyncio.TimeoutError:
                last_error = "Request timed out"
                logger.warning(f"Timeout on {url} (attempt {attempt + 1}/{self.max_retries})")

            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.warning(f"Client error on {url}: {e} (attempt {attempt + 1}/{self.max_retries})")

            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error on {url}: {e}")
                break

            # Exponential backoff
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        # All retries failed
        self.stats['requests_made'] += 1
        self.stats['requests_failed'] += 1

        return Response(
            url=url,
            status=0,
            headers={},
            body='',
            elapsed=0,
            error=last_error,
            request_method=method.value,
            request_headers=request_headers,
            request_body=str(data) if data else None
        )

    async def get(self, url: str, **kwargs) -> Response:
        """Make GET request."""
        return await self.request(url, RequestMethod.GET, **kwargs)

    async def post(self, url: str, data: Dict = None, **kwargs) -> Response:
        """Make POST request."""
        return await self.request(url, RequestMethod.POST, data=data, **kwargs)

    async def head(self, url: str, **kwargs) -> Response:
        """Make HEAD request."""
        return await self.request(url, RequestMethod.HEAD, **kwargs)

    async def multi_request(
            self,
            urls: List[str],
            method: RequestMethod = RequestMethod.GET
    ) -> List[Response]:
        """
        Make multiple requests concurrently.

        Args:
            urls: List of URLs
            method: HTTP method for all requests

        Returns:
            List of Response objects
        """
        tasks = [self.request(url, method) for url in urls]
        return await asyncio.gather(*tasks)

    async def test_payload(
            self,
            url: str,
            parameter: str,
            payload: str,
            method: RequestMethod = RequestMethod.GET,
            original_value: str = ''
    ) -> Tuple[Response, str]:
        """
        Test a payload on a specific parameter.

        Args:
            url: Target URL
            parameter: Parameter name to inject
            payload: Payload to inject
            method: HTTP method
            original_value: Original parameter value

        Returns:
            Tuple of (Response, injected_value)
        """
        injected_value = original_value + payload

        if method == RequestMethod.GET:
            # Inject in URL
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [injected_value]

            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            response = await self.get(new_url, use_cache=False)

        else:
            # Inject in POST data
            data = {parameter: injected_value}
            response = await self.post(url, data=data, use_cache=False)

        return response, injected_value

    def clear_cache(self):
        """Clear response cache."""
        self._response_cache.clear()

    def get_stats(self) -> Dict[str, int]:
        """Get request statistics."""
        return self.stats.copy()
