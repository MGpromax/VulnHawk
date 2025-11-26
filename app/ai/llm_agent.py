"""
VulnHawk Advanced LLM Security Agent

A truly intelligent AI security assistant powered by Claude/OpenAI that thinks
like a human security expert using:
- Chain-of-Thought reasoning
- ReAct (Reasoning + Acting) patterns
- Self-reflection and critique
- Dynamic context-aware analysis

Author: VulnHawk Team
"""

import os
import json
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Generator
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

# Try to import LLM libraries
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class LLMProvider(Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    FALLBACK = "fallback"  # Rule-based fallback


@dataclass
class ThinkingStep:
    """Represents a step in the AI's reasoning process."""
    step_type: str  # "thought", "action", "observation", "reflection"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0


@dataclass
class AnalysisContext:
    """Context for vulnerability analysis."""
    vulnerability_type: str
    severity: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    method: Optional[str] = None
    technology_stack: Optional[List[str]] = None
    organization_context: Optional[str] = None
    previous_findings: Optional[List[Dict]] = None


@dataclass
class IntelligentAnalysis:
    """Result of intelligent AI analysis."""
    vulnerability_id: str
    thinking_process: List[ThinkingStep]
    executive_summary: str
    technical_analysis: str
    attack_narrative: str
    business_impact: str
    remediation_plan: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    confidence_score: float
    model_used: str
    tokens_used: int = 0
    analysis_time: float = 0.0


class PromptCache:
    """Simple in-memory cache for prompts to reduce API costs."""

    def __init__(self, max_size: int = 100, ttl_minutes: int = 60):
        self._cache: Dict[str, tuple] = {}
        self._max_size = max_size
        self._ttl = timedelta(minutes=ttl_minutes)

    def _hash_key(self, prompt: str, context: str) -> str:
        """Generate cache key from prompt and context."""
        content = f"{prompt}:{context}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get(self, prompt: str, context: str) -> Optional[str]:
        """Get cached response if available and not expired."""
        key = self._hash_key(prompt, context)
        if key in self._cache:
            response, timestamp = self._cache[key]
            if datetime.now() - timestamp < self._ttl:
                return response
            else:
                del self._cache[key]
        return None

    def set(self, prompt: str, context: str, response: str):
        """Cache a response."""
        if len(self._cache) >= self._max_size:
            # Remove oldest entry
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        key = self._hash_key(prompt, context)
        self._cache[key] = (response, datetime.now())


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str,
                 temperature: float = 0.7, max_tokens: int = 4000) -> str:
        """Generate a response from the LLM."""
        pass

    @abstractmethod
    def generate_stream(self, system_prompt: str, user_prompt: str,
                        temperature: float = 0.7, max_tokens: int = 4000) -> Generator[str, None, None]:
        """Generate a streaming response from the LLM."""
        pass


class AnthropicClient(BaseLLMClient):
    """Claude API client for Anthropic models."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.client = None
        if self.api_key and ANTHROPIC_AVAILABLE:
            self.client = anthropic.Anthropic(api_key=self.api_key)

    def is_available(self) -> bool:
        return self.client is not None

    def generate(self, system_prompt: str, user_prompt: str,
                 temperature: float = 0.7, max_tokens: int = 4000) -> str:
        if not self.is_available():
            raise RuntimeError("Anthropic client not available")

        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return message.content[0].text

    def generate_stream(self, system_prompt: str, user_prompt: str,
                        temperature: float = 0.7, max_tokens: int = 4000) -> Generator[str, None, None]:
        if not self.is_available():
            raise RuntimeError("Anthropic client not available")

        with self.client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        ) as stream:
            for text in stream.text_stream:
                yield text


class OpenAIClient(BaseLLMClient):
    """OpenAI API client for GPT models."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.client = None
        if self.api_key and OPENAI_AVAILABLE:
            self.client = openai.OpenAI(api_key=self.api_key)

    def is_available(self) -> bool:
        return self.client is not None

    def generate(self, system_prompt: str, user_prompt: str,
                 temperature: float = 0.7, max_tokens: int = 4000) -> str:
        if not self.is_available():
            raise RuntimeError("OpenAI client not available")

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content

    def generate_stream(self, system_prompt: str, user_prompt: str,
                        temperature: float = 0.7, max_tokens: int = 4000) -> Generator[str, None, None]:
        if not self.is_available():
            raise RuntimeError("OpenAI client not available")

        stream = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            stream=True
        )
        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


class IntelligentSecurityAgent:
    """
    Advanced AI Security Agent that thinks like a human expert.

    Uses Chain-of-Thought reasoning, ReAct patterns, and self-reflection
    to provide truly intelligent security analysis.
    """

    # System prompt that makes the AI think like a security expert
    SECURITY_EXPERT_PROMPT = """You are an elite cybersecurity expert and penetration tester with 15+ years of experience. You think deeply about security vulnerabilities, considering attack vectors that others might miss.

Your analysis style:
- You reason step-by-step, showing your thinking process
- You consider the attacker's perspective and motivations
- You understand business context and real-world impact
- You provide actionable, specific remediation advice
- You explain complex concepts clearly without being condescending
- You acknowledge uncertainty when appropriate
- You think creatively about edge cases and bypass techniques

When analyzing vulnerabilities:
1. First, understand the full context of the vulnerability
2. Think through how an attacker would discover and exploit this
3. Consider the blast radius - what else could be compromised?
4. Evaluate the business impact in concrete terms
5. Provide remediation that's practical for the development team
6. Suggest detection mechanisms to catch future attempts

You communicate like a trusted security advisor - professional but approachable, thorough but concise, technical but understandable."""

    CHAIN_OF_THOUGHT_TEMPLATE = """Let me analyze this vulnerability step by step.

**Vulnerability Details:**
- Type: {vuln_type}
- Severity: {severity}
- Location: {url}
- Parameter: {parameter}
- Method: {method}
- Payload: {payload}
- Evidence: {evidence}

**My Analysis Process:**

**Step 1: Understanding the Vulnerability**
Let me first understand exactly what we're dealing with here...

**Step 2: Attacker's Perspective**
If I were an attacker who discovered this, here's how I would think about exploiting it...

**Step 3: Impact Assessment**
Now let me consider what damage could actually be done...

**Step 4: Root Cause Analysis**
Why does this vulnerability exist in the first place?

**Step 5: Remediation Strategy**
Here's how to fix this properly, not just patch it...

**Step 6: Detection & Prevention**
How can we detect if this has been exploited and prevent similar issues?

Please provide a comprehensive analysis following this thinking process. Be specific, be practical, and think like a real attacker would."""

    REACT_ANALYSIS_TEMPLATE = """I need to analyze a {vuln_type} vulnerability. Let me use a systematic approach.

**THOUGHT 1:** First, I need to understand what kind of {vuln_type} this is and how severe it really is.
Looking at the evidence: {evidence}
The payload used was: {payload}

**OBSERVATION 1:** Based on this evidence, I can see that...

**THOUGHT 2:** Now I should consider what an attacker could actually do with this...

**OBSERVATION 2:** The potential attack scenarios include...

**THOUGHT 3:** Let me think about the business impact...

**OBSERVATION 3:** In a real-world scenario, this could lead to...

**THOUGHT 4:** What's the best way to fix this?

**OBSERVATION 4:** The remediation should include...

**REFLECTION:** Let me review my analysis for completeness and accuracy...

Please complete this analysis with detailed, expert-level insights."""

    SELF_REFLECTION_PROMPT = """Review your previous analysis and ask yourself:

1. Did I miss any attack vectors or exploitation techniques?
2. Is my severity assessment accurate given the full context?
3. Are my remediation suggestions practical and complete?
4. Would a senior security engineer find this analysis valuable?
5. Have I explained the "why" behind each recommendation?

If you find gaps, add them to your analysis. Be your own harshest critic."""

    def __init__(self, provider: LLMProvider = LLMProvider.ANTHROPIC,
                 api_key: Optional[str] = None,
                 enable_cache: bool = True):
        """
        Initialize the Intelligent Security Agent.

        Args:
            provider: Which LLM provider to use (ANTHROPIC, OPENAI, or FALLBACK)
            api_key: API key for the chosen provider
            enable_cache: Whether to cache responses for cost optimization
        """
        self.provider = provider
        self.cache = PromptCache() if enable_cache else None
        self.thinking_steps: List[ThinkingStep] = []

        # Initialize the appropriate client
        self.client: Optional[BaseLLMClient] = None

        if provider == LLMProvider.ANTHROPIC:
            client = AnthropicClient(api_key)
            if client.is_available():
                self.client = client
            else:
                print("[WARNING] Anthropic API not available, falling back to rule-based system")
                self.provider = LLMProvider.FALLBACK

        elif provider == LLMProvider.OPENAI:
            client = OpenAIClient(api_key)
            if client.is_available():
                self.client = client
            else:
                print("[WARNING] OpenAI API not available, falling back to rule-based system")
                self.provider = LLMProvider.FALLBACK

    def _add_thinking_step(self, step_type: str, content: str, confidence: float = 1.0):
        """Record a step in the AI's thinking process."""
        self.thinking_steps.append(ThinkingStep(
            step_type=step_type,
            content=content,
            confidence=confidence
        ))

    def _build_analysis_prompt(self, context: AnalysisContext) -> str:
        """Build a detailed prompt for vulnerability analysis."""

        prompt = self.CHAIN_OF_THOUGHT_TEMPLATE.format(
            vuln_type=context.vulnerability_type,
            severity=context.severity,
            url=context.url,
            parameter=context.parameter or "N/A",
            method=context.method or "GET",
            payload=context.payload or "N/A",
            evidence=context.evidence or "Vulnerability confirmed through testing"
        )

        # Add technology context if available
        if context.technology_stack:
            prompt += f"\n\n**Technology Stack:** {', '.join(context.technology_stack)}"
            prompt += "\nPlease tailor your remediation advice to these specific technologies."

        # Add organization context if available
        if context.organization_context:
            prompt += f"\n\n**Organization Context:** {context.organization_context}"
            prompt += "\nConsider this context when assessing business impact."

        # Add previous findings for pattern analysis
        if context.previous_findings:
            prompt += f"\n\n**Related Findings:** {len(context.previous_findings)} similar vulnerabilities found"
            prompt += "\nConsider if this is part of a systemic issue."

        return prompt

    def analyze_vulnerability(self, context: AnalysisContext,
                              use_streaming: bool = False) -> IntelligentAnalysis:
        """
        Perform intelligent analysis of a vulnerability.

        This method uses Chain-of-Thought reasoning and self-reflection
        to provide human-like, contextual analysis.
        """
        import time
        start_time = time.time()
        self.thinking_steps = []

        self._add_thinking_step("thought", f"Beginning analysis of {context.vulnerability_type} vulnerability")

        # Check cache first
        cache_key = f"{context.vulnerability_type}:{context.url}:{context.parameter}"
        if self.cache:
            cached = self.cache.get(self.SECURITY_EXPERT_PROMPT, cache_key)
            if cached:
                self._add_thinking_step("observation", "Found cached analysis, using previous results")
                # Parse cached response (simplified)
                return self._parse_cached_response(cached, context, start_time)

        # Generate analysis based on provider
        if self.provider == LLMProvider.FALLBACK or self.client is None:
            return self._fallback_analysis(context, start_time)

        try:
            # Build the analysis prompt
            analysis_prompt = self._build_analysis_prompt(context)
            self._add_thinking_step("action", "Generating initial analysis with LLM")

            # Generate initial analysis
            initial_analysis = self.client.generate(
                system_prompt=self.SECURITY_EXPERT_PROMPT,
                user_prompt=analysis_prompt,
                temperature=0.7,
                max_tokens=4000
            )

            self._add_thinking_step("observation", "Initial analysis complete, performing self-reflection")

            # Self-reflection pass for quality improvement
            reflection_prompt = f"""Here is my initial analysis:

{initial_analysis}

{self.SELF_REFLECTION_PROMPT}

Please provide your final, refined analysis incorporating any improvements."""

            final_analysis = self.client.generate(
                system_prompt=self.SECURITY_EXPERT_PROMPT,
                user_prompt=reflection_prompt,
                temperature=0.5,  # Lower temperature for reflection
                max_tokens=4000
            )

            self._add_thinking_step("reflection", "Self-reflection complete, finalizing analysis")

            # Cache the result
            if self.cache:
                self.cache.set(self.SECURITY_EXPERT_PROMPT, cache_key, final_analysis)

            # Parse and structure the response
            return self._parse_llm_response(final_analysis, context, start_time)

        except Exception as e:
            self._add_thinking_step("observation", f"LLM analysis failed: {str(e)}, using fallback")
            return self._fallback_analysis(context, start_time)

    def analyze_vulnerability_stream(self, context: AnalysisContext) -> Generator[str, None, None]:
        """
        Stream vulnerability analysis for better UX.

        Yields chunks of the analysis as they're generated.
        """
        if self.provider == LLMProvider.FALLBACK or self.client is None:
            # For fallback, yield the complete analysis at once
            analysis = self._fallback_analysis(context, 0)
            yield analysis.executive_summary
            yield "\n\n"
            yield analysis.technical_analysis
            yield "\n\n"
            yield analysis.attack_narrative
            return

        try:
            analysis_prompt = self._build_analysis_prompt(context)

            yield "## Security Analysis\n\n"
            yield "*Analyzing vulnerability with AI-powered reasoning...*\n\n"

            for chunk in self.client.generate_stream(
                system_prompt=self.SECURITY_EXPERT_PROMPT,
                user_prompt=analysis_prompt,
                temperature=0.7,
                max_tokens=4000
            ):
                yield chunk

        except Exception as e:
            yield f"\n\n*Analysis encountered an error: {str(e)}*\n"
            yield "\n\n## Fallback Analysis\n\n"
            analysis = self._fallback_analysis(context, 0)
            yield analysis.executive_summary

    def _parse_llm_response(self, response: str, context: AnalysisContext,
                            start_time: float) -> IntelligentAnalysis:
        """Parse LLM response into structured analysis."""
        import time

        # Extract sections from the response (flexible parsing)
        sections = self._extract_sections(response)

        return IntelligentAnalysis(
            vulnerability_id=f"{context.vulnerability_type}_{hash(context.url) % 10000}",
            thinking_process=self.thinking_steps,
            executive_summary=sections.get("summary", response[:500]),
            technical_analysis=sections.get("technical", response),
            attack_narrative=sections.get("attack", "See technical analysis"),
            business_impact=sections.get("impact", "See executive summary"),
            remediation_plan=self._extract_remediation(response),
            risk_assessment={
                "severity": context.severity,
                "exploitability": "High" if context.payload else "Medium",
                "impact": self._assess_impact(context),
                "confidence": 0.9
            },
            confidence_score=0.9,
            model_used=self.provider.value,
            analysis_time=time.time() - start_time
        )

    def _extract_sections(self, response: str) -> Dict[str, str]:
        """Extract sections from LLM response."""
        sections = {}

        # Look for common section headers
        section_markers = [
            ("summary", ["executive summary", "summary", "overview"]),
            ("technical", ["technical", "analysis", "details"]),
            ("attack", ["attack", "exploitation", "attacker"]),
            ("impact", ["impact", "business", "risk"]),
            ("remediation", ["remediation", "fix", "mitigation", "recommendation"])
        ]

        response_lower = response.lower()

        for section_name, markers in section_markers:
            for marker in markers:
                if marker in response_lower:
                    # Find the section content (simplified extraction)
                    idx = response_lower.find(marker)
                    # Get text until next section or end
                    end_idx = len(response)
                    for _, other_markers in section_markers:
                        for other_marker in other_markers:
                            other_idx = response_lower.find(other_marker, idx + len(marker) + 50)
                            if other_idx > idx and other_idx < end_idx:
                                end_idx = other_idx

                    sections[section_name] = response[idx:end_idx].strip()
                    break

        return sections

    def _extract_remediation(self, response: str) -> List[Dict[str, Any]]:
        """Extract remediation steps from response."""
        remediation = []

        # Look for numbered steps or bullet points
        lines = response.split('\n')
        current_step = None

        for line in lines:
            line = line.strip()
            # Check for numbered items
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                if current_step:
                    remediation.append(current_step)
                current_step = {
                    "step": len(remediation) + 1,
                    "title": line.lstrip('0123456789.-* '),
                    "description": "",
                    "priority": "high" if len(remediation) < 2 else "medium"
                }
            elif current_step and line:
                current_step["description"] += " " + line

        if current_step:
            remediation.append(current_step)

        # If no structured remediation found, create a general one
        if not remediation:
            remediation = [{
                "step": 1,
                "title": "Review and remediate the vulnerability",
                "description": "Please review the full analysis above for detailed remediation guidance.",
                "priority": "high"
            }]

        return remediation[:5]  # Limit to 5 steps

    def _assess_impact(self, context: AnalysisContext) -> str:
        """Assess the impact level based on context."""
        high_impact_types = ['sqli', 'rce', 'ssrf', 'auth_bypass', 'idor']
        medium_impact_types = ['xss', 'csrf', 'lfi', 'open_redirect']

        vuln_type = context.vulnerability_type.lower()

        if any(t in vuln_type for t in high_impact_types):
            return "High"
        elif any(t in vuln_type for t in medium_impact_types):
            return "Medium"
        else:
            return "Low"

    def _parse_cached_response(self, cached: str, context: AnalysisContext,
                               start_time: float) -> IntelligentAnalysis:
        """Parse a cached response."""
        return self._parse_llm_response(cached, context, start_time)

    def _fallback_analysis(self, context: AnalysisContext, start_time: float) -> IntelligentAnalysis:
        """
        Fallback rule-based analysis when LLM is not available.
        Still provides intelligent-sounding analysis using templates.
        """
        import time

        self._add_thinking_step("thought", "Using enhanced rule-based analysis")

        vuln_type = context.vulnerability_type.lower()

        # Enhanced knowledge base for fallback
        knowledge = self._get_fallback_knowledge(vuln_type)

        executive_summary = f"""A {context.severity.upper()} severity {context.vulnerability_type} vulnerability has been identified at {context.url}.

{knowledge['description']}

This vulnerability could allow an attacker to {knowledge['attacker_goal']}. Given the severity level and the nature of the vulnerability, immediate remediation is recommended."""

        technical_analysis = f"""**Technical Details:**

The vulnerability was confirmed through testing with the following details:
- **Endpoint:** {context.url}
- **Parameter:** {context.parameter or 'N/A'}
- **Method:** {context.method or 'GET'}
- **Payload:** `{context.payload or 'N/A'}`

**Evidence:**
{context.evidence or 'Vulnerability confirmed through automated testing.'}

**Root Cause:**
{knowledge['root_cause']}

**Attack Vector:**
{knowledge['attack_vector']}"""

        attack_narrative = f"""**Attack Scenario:**

An attacker discovering this vulnerability would likely proceed as follows:

1. **Reconnaissance:** The attacker identifies the vulnerable endpoint through automated scanning or manual testing.

2. **Exploitation:** {knowledge['exploitation_steps']}

3. **Impact:** Once exploited, the attacker could {knowledge['attacker_goal']}.

4. **Persistence:** {knowledge['persistence']}

This represents a realistic attack path that has been observed in real-world incidents."""

        business_impact = f"""**Business Impact Assessment:**

{knowledge['business_impact']}

**Compliance Implications:**
- OWASP Category: {knowledge['owasp']}
- CWE: {knowledge['cwe']}
- Potential regulatory violations if exploited (GDPR, PCI-DSS, etc.)"""

        return IntelligentAnalysis(
            vulnerability_id=f"{vuln_type}_{hash(context.url) % 10000}",
            thinking_process=self.thinking_steps,
            executive_summary=executive_summary,
            technical_analysis=technical_analysis,
            attack_narrative=attack_narrative,
            business_impact=business_impact,
            remediation_plan=knowledge['remediation'],
            risk_assessment={
                "severity": context.severity,
                "exploitability": knowledge['exploitability'],
                "impact": self._assess_impact(context),
                "confidence": 0.85
            },
            confidence_score=0.85,
            model_used="fallback_enhanced",
            analysis_time=time.time() - start_time
        )

    def _get_fallback_knowledge(self, vuln_type: str) -> Dict[str, Any]:
        """Get enhanced fallback knowledge for a vulnerability type."""

        knowledge_base = {
            "xss": {
                "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
                "attacker_goal": "steal session cookies, capture keystrokes, redirect users to malicious sites, or perform actions on behalf of the victim",
                "root_cause": "The application fails to properly validate, sanitize, or encode user-supplied input before including it in the response.",
                "attack_vector": "User input is reflected in the page without proper encoding, allowing JavaScript execution in the victim's browser context.",
                "exploitation_steps": "Using the identified injection point, the attacker crafts a malicious URL or form submission containing JavaScript code. When a victim interacts with this, the script executes in their browser.",
                "persistence": "For stored XSS, the malicious payload persists in the application database, affecting all users who view the affected content.",
                "business_impact": "XSS can lead to account takeover, data theft, reputation damage, and potential compliance violations. In severe cases, it can be chained with other vulnerabilities for complete system compromise.",
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-79",
                "exploitability": "High",
                "remediation": [
                    {"step": 1, "title": "Implement Output Encoding", "description": "Encode all user-supplied data before rendering in HTML, JavaScript, CSS, or URL contexts. Use context-appropriate encoding functions.", "priority": "critical"},
                    {"step": 2, "title": "Deploy Content Security Policy", "description": "Implement a strict CSP header to prevent inline script execution and restrict resource loading to trusted sources.", "priority": "high"},
                    {"step": 3, "title": "Validate Input", "description": "Implement server-side input validation using allowlists where possible. Reject or sanitize unexpected input.", "priority": "high"},
                    {"step": 4, "title": "Use Security Headers", "description": "Enable X-XSS-Protection, X-Content-Type-Options, and other security headers as defense in depth.", "priority": "medium"}
                ]
            },
            "sqli": {
                "description": "SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data.",
                "attacker_goal": "extract sensitive data from the database, bypass authentication, modify or delete data, or potentially execute system commands",
                "root_cause": "User input is concatenated directly into SQL queries without proper parameterization or escaping.",
                "attack_vector": "Malicious SQL syntax injected through user input modifies the intended query logic.",
                "exploitation_steps": "The attacker crafts input containing SQL syntax that, when concatenated into the query, changes its behavior. This can be used to extract data, bypass authentication, or modify records.",
                "persistence": "The attacker may create backdoor accounts, modify stored data, or exfiltrate the entire database for offline analysis.",
                "business_impact": "SQL injection can result in complete database compromise, including theft of customer data, financial information, and credentials. This typically triggers mandatory breach notifications and can result in significant fines.",
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-89",
                "exploitability": "High",
                "remediation": [
                    {"step": 1, "title": "Use Parameterized Queries", "description": "Replace all dynamic SQL with parameterized queries or prepared statements. Never concatenate user input into SQL.", "priority": "critical"},
                    {"step": 2, "title": "Implement ORM Properly", "description": "If using an ORM, ensure you're using its query builder correctly and not bypassing it with raw SQL.", "priority": "high"},
                    {"step": 3, "title": "Apply Least Privilege", "description": "Database accounts used by the application should have minimal necessary permissions. No admin access.", "priority": "high"},
                    {"step": 4, "title": "Enable WAF Rules", "description": "Deploy Web Application Firewall rules to detect and block common SQL injection patterns.", "priority": "medium"}
                ]
            },
            "csrf": {
                "description": "Cross-Site Request Forgery tricks authenticated users into performing unintended actions on a web application.",
                "attacker_goal": "perform actions on behalf of authenticated users, such as changing passwords, transferring funds, or modifying account settings",
                "root_cause": "The application does not verify that requests originate from the legitimate user interface rather than a malicious third-party site.",
                "attack_vector": "A malicious website or email contains a crafted request that, when loaded by an authenticated user, performs an action on the target application.",
                "exploitation_steps": "The attacker creates a malicious page containing a form or image tag that submits a request to the target application. When an authenticated user visits this page, their browser automatically includes session cookies, making the forged request appear legitimate.",
                "persistence": "The effects of CSRF attacks are typically persistent (changed passwords, modified settings), but the attack itself is one-time per victim visit.",
                "business_impact": "CSRF can lead to unauthorized transactions, account compromise, and data modification. While typically requiring user interaction, it can be highly damaging in financial or administrative contexts.",
                "owasp": "A01:2021 - Broken Access Control",
                "cwe": "CWE-352",
                "exploitability": "Medium",
                "remediation": [
                    {"step": 1, "title": "Implement Anti-CSRF Tokens", "description": "Include unique, unpredictable tokens in all state-changing requests. Validate tokens server-side.", "priority": "critical"},
                    {"step": 2, "title": "Use SameSite Cookies", "description": "Set SameSite=Strict or SameSite=Lax on session cookies to prevent cross-site cookie transmission.", "priority": "high"},
                    {"step": 3, "title": "Verify Origin/Referer", "description": "Check Origin and Referer headers for sensitive operations as an additional defense layer.", "priority": "medium"},
                    {"step": 4, "title": "Require Re-authentication", "description": "For highly sensitive operations, require the user to re-enter their password.", "priority": "medium"}
                ]
            },
            "ssrf": {
                "description": "Server-Side Request Forgery allows attackers to induce the server to make requests to unintended locations.",
                "attacker_goal": "access internal services, read local files, scan internal networks, or interact with cloud metadata services",
                "root_cause": "The application makes HTTP requests to URLs controlled by user input without proper validation.",
                "attack_vector": "User-supplied URLs or hostnames are used by the server to make outbound requests, allowing access to internal resources.",
                "exploitation_steps": "The attacker provides URLs pointing to internal services (like http://localhost, http://169.254.169.254 for cloud metadata, or internal IP ranges). The server makes requests to these targets, potentially exposing sensitive information.",
                "persistence": "SSRF is often used for reconnaissance and credential theft. Stolen cloud credentials can provide persistent access to infrastructure.",
                "business_impact": "SSRF can expose internal services, cloud credentials (AWS keys, etc.), and sensitive configuration. In cloud environments, this often leads to complete infrastructure compromise.",
                "owasp": "A10:2021 - Server-Side Request Forgery",
                "cwe": "CWE-918",
                "exploitability": "High",
                "remediation": [
                    {"step": 1, "title": "Implement URL Allowlisting", "description": "Only allow requests to pre-approved, known-safe destinations. Deny by default.", "priority": "critical"},
                    {"step": 2, "title": "Block Internal Ranges", "description": "Explicitly block requests to localhost, private IP ranges, and cloud metadata endpoints.", "priority": "critical"},
                    {"step": 3, "title": "Disable URL Redirects", "description": "Don't follow HTTP redirects automatically, or re-validate the redirect target.", "priority": "high"},
                    {"step": 4, "title": "Use Network Segmentation", "description": "Ensure the application server cannot reach sensitive internal services.", "priority": "medium"}
                ]
            }
        }

        # Default fallback for unknown vulnerability types
        default = {
            "description": f"A security vulnerability of type '{vuln_type}' has been identified.",
            "attacker_goal": "compromise the application security in ways specific to this vulnerability type",
            "root_cause": "Insufficient security controls or input validation.",
            "attack_vector": "The specific attack vector depends on the vulnerability type and application context.",
            "exploitation_steps": "The attacker would leverage the identified weakness to compromise the application.",
            "persistence": "The persistence mechanism depends on the specific vulnerability type.",
            "business_impact": "Security vulnerabilities can lead to data breaches, service disruption, and compliance violations.",
            "owasp": "Various",
            "cwe": "Various",
            "exploitability": "Medium",
            "remediation": [
                {"step": 1, "title": "Investigate the Vulnerability", "description": "Review the evidence and understand the full scope of the issue.", "priority": "high"},
                {"step": 2, "title": "Apply Security Patches", "description": "Update affected components and implement proper security controls.", "priority": "high"},
                {"step": 3, "title": "Review Similar Code", "description": "Check for similar patterns elsewhere in the codebase.", "priority": "medium"}
            ]
        }

        return knowledge_base.get(vuln_type, default)


def create_intelligent_agent(provider: str = "auto",
                              api_key: Optional[str] = None) -> IntelligentSecurityAgent:
    """
    Factory function to create an intelligent security agent.

    Args:
        provider: "anthropic", "openai", "auto" (tries anthropic first), or "fallback"
        api_key: API key for the chosen provider

    Returns:
        Configured IntelligentSecurityAgent instance
    """
    if provider == "auto":
        # Try Anthropic first, then OpenAI, then fallback
        if ANTHROPIC_AVAILABLE and (api_key or os.environ.get("ANTHROPIC_API_KEY")):
            return IntelligentSecurityAgent(LLMProvider.ANTHROPIC, api_key)
        elif OPENAI_AVAILABLE and (api_key or os.environ.get("OPENAI_API_KEY")):
            return IntelligentSecurityAgent(LLMProvider.OPENAI, api_key)
        else:
            return IntelligentSecurityAgent(LLMProvider.FALLBACK)

    elif provider == "anthropic":
        return IntelligentSecurityAgent(LLMProvider.ANTHROPIC, api_key)

    elif provider == "openai":
        return IntelligentSecurityAgent(LLMProvider.OPENAI, api_key)

    else:
        return IntelligentSecurityAgent(LLMProvider.FALLBACK)
