"""
HTML Parser for VulnHawk

Extracts security-relevant information from HTML responses:
- Forms and input fields
- Links and URLs
- JavaScript sources
- Comments
- Metadata
"""

import re
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup, Comment
import logging

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """Represents an HTML form field."""
    name: str
    field_type: str
    value: str = ''
    required: bool = False
    pattern: Optional[str] = None
    max_length: Optional[int] = None

    @property
    def is_password(self) -> bool:
        return self.field_type == 'password'

    @property
    def is_hidden(self) -> bool:
        return self.field_type == 'hidden'

    @property
    def is_file(self) -> bool:
        return self.field_type == 'file'


@dataclass
class Form:
    """Represents an HTML form."""
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    enctype: str = 'application/x-www-form-urlencoded'
    has_csrf_token: bool = False
    csrf_token_name: Optional[str] = None
    csrf_token_value: Optional[str] = None

    @property
    def is_login_form(self) -> bool:
        """Check if form appears to be a login form."""
        password_fields = [f for f in self.fields if f.is_password]
        if not password_fields:
            return False

        # Check for username/email fields
        user_fields = [f for f in self.fields
                       if f.name.lower() in ('username', 'user', 'email', 'login', 'id')]
        return len(user_fields) > 0

    @property
    def is_search_form(self) -> bool:
        """Check if form appears to be a search form."""
        search_indicators = ['search', 'query', 'q', 'keyword', 'term']
        for f in self.fields:
            if f.name.lower() in search_indicators:
                return True
        return False

    @property
    def injectable_fields(self) -> List[FormField]:
        """Get fields that can be tested for injection."""
        excluded_types = {'hidden', 'submit', 'button', 'image', 'reset', 'file'}
        return [f for f in self.fields
                if f.field_type not in excluded_types and f.name]


@dataclass
class Link:
    """Represents a link extracted from HTML."""
    url: str
    text: str = ''
    is_internal: bool = True
    has_parameters: bool = False
    parameters: Dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedPage:
    """Represents parsed HTML page data."""
    url: str
    title: str = ''
    forms: List[Form] = field(default_factory=list)
    links: List[Link] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    headers_in_html: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)


class HTMLParser:
    """
    HTML Parser for security scanning.

    Extracts:
    - Forms with all input fields
    - Links (internal and external)
    - JavaScript sources
    - HTML comments (often contain sensitive info)
    - Meta tags and headers
    - Technology fingerprints
    - Contact information
    """

    # CSRF token indicators
    CSRF_NAMES = {
        'csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken',
        '_token', 'token', 'authenticity_token', '_csrf',
        'anti-csrf-token', 'anticsrf', '__requestverificationtoken',
        'xsrf', 'xsrf_token', '_xsrf'
    }

    # Technology patterns
    TECH_PATTERNS = {
        'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)?', r'jquery\.min\.js'],
        'Bootstrap': [r'bootstrap[.-](\d+\.\d+\.\d+)?', r'bootstrap\.min\.js'],
        'React': [r'react[.-](\d+\.\d+\.\d+)?', r'react\.production\.min\.js'],
        'Angular': [r'angular[.-](\d+\.\d+\.\d+)?', r'angular\.min\.js'],
        'Vue.js': [r'vue[.-](\d+\.\d+\.\d+)?', r'vue\.min\.js'],
        'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
        'Drupal': [r'drupal\.js', r'/sites/default/'],
        'Joomla': [r'/media/jui/', r'joomla'],
        'Laravel': [r'laravel', r'csrf-token'],
        'Django': [r'csrfmiddlewaretoken', r'django'],
        'ASP.NET': [r'__viewstate', r'__eventvalidation', r'asp\.net'],
        'PHP': [r'\.php', r'phpsessid'],
    }

    # Email regex
    EMAIL_REGEX = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    # Phone regex (simple pattern)
    PHONE_REGEX = re.compile(
        r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}'
    )

    def __init__(self, base_url: str):
        """
        Initialize parser with base URL.

        Args:
            base_url: Base URL for resolving relative links
        """
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc

    def parse(self, html: str, url: Optional[str] = None) -> ParsedPage:
        """
        Parse HTML content and extract security-relevant data.

        Args:
            html: HTML content to parse
            url: URL of the page (defaults to base_url)

        Returns:
            ParsedPage object with extracted data
        """
        page_url = url or self.base_url

        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            # Fallback to html.parser if lxml fails
            soup = BeautifulSoup(html, 'html.parser')

        parsed = ParsedPage(url=page_url)

        # Extract title
        parsed.title = self._extract_title(soup)

        # Extract forms
        parsed.forms = self._extract_forms(soup, page_url)

        # Extract links
        parsed.links = self._extract_links(soup, page_url)

        # Extract scripts
        parsed.scripts = self._extract_scripts(soup, page_url)

        # Extract comments
        parsed.comments = self._extract_comments(soup)

        # Extract meta tags
        parsed.meta_tags = self._extract_meta_tags(soup)

        # Detect technologies
        parsed.technologies = self._detect_technologies(html, soup)

        # Extract contact info
        parsed.emails = self._extract_emails(html)
        parsed.phone_numbers = self._extract_phones(html)

        return parsed

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title."""
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            return title_tag.string.strip()
        return ''

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Form]:
        """Extract all forms with their fields."""
        forms = []

        for form_tag in soup.find_all('form'):
            # Get form action
            action = form_tag.get('action', '')
            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url

            # Get form method
            method = form_tag.get('method', 'GET').upper()

            # Get enctype
            enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')

            # Extract fields
            fields = []
            csrf_token = None
            csrf_name = None

            # Input fields
            for input_tag in form_tag.find_all('input'):
                field = self._parse_input_field(input_tag)
                if field:
                    fields.append(field)

                    # Check for CSRF token
                    if field.name.lower() in self.CSRF_NAMES:
                        csrf_token = field.value
                        csrf_name = field.name

            # Textarea fields
            for textarea in form_tag.find_all('textarea'):
                name = textarea.get('name', '')
                if name:
                    fields.append(FormField(
                        name=name,
                        field_type='textarea',
                        value=textarea.string or '',
                        required=textarea.has_attr('required')
                    ))

            # Select fields
            for select in form_tag.find_all('select'):
                name = select.get('name', '')
                if name:
                    # Get first option value
                    first_option = select.find('option')
                    value = first_option.get('value', '') if first_option else ''
                    fields.append(FormField(
                        name=name,
                        field_type='select',
                        value=value,
                        required=select.has_attr('required')
                    ))

            form = Form(
                action=action,
                method=method,
                fields=fields,
                enctype=enctype,
                has_csrf_token=csrf_token is not None,
                csrf_token_name=csrf_name,
                csrf_token_value=csrf_token
            )

            forms.append(form)

        return forms

    def _parse_input_field(self, input_tag) -> Optional[FormField]:
        """Parse an input tag into FormField."""
        name = input_tag.get('name', '')
        if not name:
            return None

        field_type = input_tag.get('type', 'text').lower()
        value = input_tag.get('value', '')
        required = input_tag.has_attr('required')
        pattern = input_tag.get('pattern')
        max_length = input_tag.get('maxlength')

        if max_length:
            try:
                max_length = int(max_length)
            except ValueError:
                max_length = None

        return FormField(
            name=name,
            field_type=field_type,
            value=value,
            required=required,
            pattern=pattern,
            max_length=max_length
        )

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> List[Link]:
        """Extract all links from the page."""
        links = []
        seen_urls: Set[str] = set()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()

            # Skip empty, javascript, and mailto links
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue

            # Resolve relative URL
            full_url = urljoin(page_url, href)

            # Skip if already seen
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            # Parse URL
            parsed = urlparse(full_url)

            # Check if internal
            is_internal = parsed.netloc == self.base_domain or parsed.netloc == ''

            # Extract parameters
            parameters = {}
            has_parameters = False
            if parsed.query:
                has_parameters = True
                parameters = {k: v[0] if v else '' for k, v in parse_qs(parsed.query).items()}

            # Get link text
            text = a_tag.get_text(strip=True)[:100]

            links.append(Link(
                url=full_url,
                text=text,
                is_internal=is_internal,
                has_parameters=has_parameters,
                parameters=parameters
            ))

        return links

    def _extract_scripts(self, soup: BeautifulSoup, page_url: str) -> List[str]:
        """Extract JavaScript source URLs."""
        scripts = []

        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            full_url = urljoin(page_url, src)
            scripts.append(full_url)

        return scripts

    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:
        """Extract HTML comments (may contain sensitive info)."""
        comments = []

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            if comment_text and len(comment_text) > 3:  # Skip very short comments
                comments.append(comment_text)

        return comments

    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tag information."""
        meta_tags = {}

        for meta in soup.find_all('meta'):
            name = meta.get('name', meta.get('property', ''))
            content = meta.get('content', '')
            if name and content:
                meta_tags[name] = content

        return meta_tags

    def _detect_technologies(self, html: str, soup: BeautifulSoup) -> List[str]:
        """Detect technologies used by the website."""
        technologies = []
        html_lower = html.lower()

        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)
                    break

        return technologies

    def _extract_emails(self, html: str) -> List[str]:
        """Extract email addresses from HTML."""
        emails = set(self.EMAIL_REGEX.findall(html))
        return list(emails)[:20]  # Limit to 20

    def _extract_phones(self, html: str) -> List[str]:
        """Extract phone numbers from HTML."""
        phones = set(self.PHONE_REGEX.findall(html))
        # Filter out likely false positives
        valid_phones = [p for p in phones if len(p) >= 10]
        return list(valid_phones)[:10]  # Limit to 10

    def get_injectable_urls(self, parsed: ParsedPage) -> List[Tuple[str, str, str]]:
        """
        Get URLs with parameters that can be tested for injection.

        Returns:
            List of tuples (url, parameter_name, original_value)
        """
        injectable = []

        for link in parsed.links:
            if link.has_parameters and link.is_internal:
                for param, value in link.parameters.items():
                    injectable.append((link.url, param, value))

        return injectable

    def get_injectable_forms(self, parsed: ParsedPage) -> List[Tuple[Form, FormField]]:
        """
        Get form fields that can be tested for injection.

        Returns:
            List of tuples (form, field)
        """
        injectable = []

        for form in parsed.forms:
            for field in form.injectable_fields:
                injectable.append((form, field))

        return injectable
