"""
Turbo SQL Injection Detection Module - 100x Faster

Detects SQLi vulnerabilities using parallel payload testing:
- Tests multiple payloads concurrently
- Early termination on confirmed SQLi
- Optimized error pattern matching
"""

import re
import asyncio
from typing import List, Dict, Optional
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# Fast SQLi Payloads - Most effective first
SQLI_PAYLOADS_FAST = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "1 OR 1=1",
    "admin'--",
]

# Compiled SQL error patterns for speed
SQL_ERROR_PATTERNS_COMPILED = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*mysql_", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"Driver.*SQL Server", re.IGNORECASE),
    re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.IGNORECASE),
    re.compile(r"SQLite.*error", re.IGNORECASE),
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"SQL error", re.IGNORECASE),
    re.compile(r"SQLSTATE", re.IGNORECASE),
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
]


class SQLiTurboModule(BaseModule):
    """
    High-speed SQL Injection detection with parallel payload testing.
    """

    name = "SQLi Turbo Scanner"
    description = "Ultra-fast SQL Injection detection"
    vulnerability_type = "sqli"
    cwe_id = "CWE-89"
    owasp_category = "A03:2021"

    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    CVSS_SCORE = 9.8

    def __init__(self, concurrent_payloads: int = 5):
        super().__init__()
        self.concurrent_payloads = concurrent_payloads

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """Passive SQLi check."""
        return []

    async def test(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: str = 'GET'
    ) -> List[VulnerabilityResult]:
        """
        Turbo SQLi testing with parallel payload injection.
        """
        results = []
        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        # Get baseline for comparison
        baseline = await requester.get(url, use_cache=True)
        if baseline.error:
            return results

        baseline_length = len(baseline.body)

        # Semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.concurrent_payloads)
        found_confirmed = asyncio.Event()

        async def test_error_based(payload):
            if found_confirmed.is_set():
                return None

            async with semaphore:
                try:
                    response, _ = await requester.test_payload(
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        method=request_method,
                        original_value=original_value
                    )

                    if response.error:
                        return None

                    # Check for SQL errors
                    error_found = self._check_sql_errors(response.body)
                    if error_found:
                        found_confirmed.set()
                        return self.create_vulnerability(
                            name="SQL Injection (Error-Based)",
                            severity=Severity.CRITICAL,
                            url=url,
                            description=f"Parameter '{parameter}' is vulnerable to SQL injection. "
                                        f"SQL error messages detected.",
                            confidence=Confidence.CONFIRMED,
                            parameter=parameter,
                            method=method,
                            payload=payload,
                            evidence=f"SQL Error: {error_found}",
                            response_snippet=self.truncate(response.body, 300),
                            cvss_vector=self.CVSS_VECTOR,
                            cvss_score=self.CVSS_SCORE,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection"
                            ]
                        )
                except Exception as e:
                    logger.debug(f"SQLi test error: {e}")
                return None

        # Run all error-based tests in parallel
        tasks = [test_error_based(p) for p in SQLI_PAYLOADS_FAST]
        payload_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful detections
        for result in payload_results:
            if result and not isinstance(result, Exception):
                results.append(result.to_dict())
                break  # One critical SQLi is enough

        # If no error-based found, try boolean-based (quick check)
        if not results:
            bool_result = await self._test_boolean_based_fast(
                requester, url, parameter, original_value, request_method, baseline_length
            )
            if bool_result:
                results.append(bool_result.to_dict())

        return results

    async def _test_boolean_based_fast(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: RequestMethod,
            baseline_length: int
    ) -> Optional[VulnerabilityResult]:
        """Fast boolean-based blind SQLi test."""
        try:
            # True condition
            true_response, _ = await requester.test_payload(
                url=url,
                parameter=parameter,
                payload="' AND '1'='1",
                method=method,
                original_value=original_value
            )

            # False condition
            false_response, _ = await requester.test_payload(
                url=url,
                parameter=parameter,
                payload="' AND '1'='2",
                method=method,
                original_value=original_value
            )

            if true_response.error or false_response.error:
                return None

            true_len = len(true_response.body)
            false_len = len(false_response.body)

            # Significant difference indicates boolean-based SQLi
            if abs(true_len - baseline_length) < 50 and abs(false_len - baseline_length) > 100:
                return self.create_vulnerability(
                    name="SQL Injection (Boolean-Based Blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    description=f"Parameter '{parameter}' is vulnerable to boolean-based SQLi. "
                                f"Different responses for true/false conditions.",
                    confidence=Confidence.HIGH,
                    parameter=parameter,
                    method=method.value,
                    payload="TRUE: ' AND '1'='1 | FALSE: ' AND '1'='2",
                    evidence=f"Response lengths: TRUE={true_len}, FALSE={false_len}, BASELINE={baseline_length}",
                    cvss_vector=self.CVSS_VECTOR,
                    cvss_score=self.CVSS_SCORE,
                    remediation=self._get_remediation(),
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                    ]
                )
        except Exception as e:
            logger.debug(f"Boolean SQLi test error: {e}")
        return None

    def _check_sql_errors(self, body: str) -> Optional[str]:
        """Fast SQL error checking with compiled patterns."""
        for pattern in SQL_ERROR_PATTERNS_COMPILED:
            match = pattern.search(body)
            if match:
                return match.group(0)[:80]
        return None

    def _get_remediation(self) -> str:
        return """
1. **Use Parameterized Queries**: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
2. **Use ORM**: SQLAlchemy, Django ORM handle parameterization automatically
3. **Input Validation**: Validate type, length, format
4. **Least Privilege**: Use minimal database permissions
5. **WAF**: Deploy Web Application Firewall
"""


# Module interface
async def check(*args, **kwargs) -> List[Dict]:
    module = SQLiTurboModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    module = SQLiTurboModule()
    return await module.test(requester, url, parameter, value, method)
