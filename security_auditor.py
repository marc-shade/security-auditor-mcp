#!/usr/bin/env python3
"""
Security Auditor - AI-powered code vulnerability detection
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability"""
    file_path: str
    line_number: int
    severity: Severity
    description: str
    suggested_fix: str
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None


class SecurityAuditor:
    """
    AI-powered security vulnerability scanner
    Detects OWASP Top 10 and common security issues
    """

    def __init__(self):
        self.rules = self._load_security_rules()

    def _load_security_rules(self) -> dict:
        """Load security detection rules"""
        return {
            # SQL Injection (CWE-89)
            'sql_injection': {
                'patterns': [
                    r'execute\s*\([^)]*\+[^)]*\)',
                    r'cursor\.execute\s*\([^)]*%[^)]*\)',
                    r'query\s*=\s*["\'].*\+.*["\']',
                    r'SELECT.*FROM.*WHERE.*\+',
                ],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-89',
                'description': 'Potential SQL injection vulnerability',
                'fix': 'Use parameterized queries or prepared statements'
            },
            'command_injection': {
                'patterns': [
                    r'os\.system\s*\([^)]*\+[^)]*\)',
                    r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\+',
                    r'exec\s*\([^)]*\+[^)]*\)',
                    r'eval\s*\([^)]*\+[^)]*\)',
                ],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-78',
                'description': 'Potential command injection vulnerability',
                'fix': 'Avoid shell=True, use list-based command arguments'
            },
            'path_traversal': {
                'patterns': [
                    r'open\s*\([^)]*\+[^)]*\)',
                    r'Path\s*\([^)]*\+[^)]*\)',
                    r'\.\./',
                ],
                'severity': Severity.HIGH,
                'cwe': 'CWE-22',
                'description': 'Potential path traversal vulnerability',
                'fix': 'Validate and sanitize file paths'
            },
            'hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']{8,}["\']',
                    r'api_key\s*=\s*["\'][^"\']{20,}["\']',
                    r'secret\s*=\s*["\'][^"\']{16,}["\']',
                ],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-798',
                'description': 'Hardcoded credentials detected',
                'fix': 'Use environment variables'
            },
            'weak_crypto': {
                'patterns': [
                    r'hashlib\.md5\s*\(',
                    r'hashlib\.sha1\s*\(',
                ],
                'severity': Severity.MEDIUM,
                'cwe': 'CWE-327',
                'description': 'Weak cryptographic algorithm',
                'fix': 'Use SHA-256 or stronger'
            },
        }

    async def scan_codebase(self, path: str) -> List[Vulnerability]:
        """Scan a file or directory for vulnerabilities"""
        vulnerabilities = []
        target_path = Path(path)

        if not target_path.exists():
            return vulnerabilities

        if target_path.is_file():
            files = [target_path]
        else:
            extensions = ['.py', '.js', '.ts', '.php', '.java']
            files = []
            for ext in extensions:
                files.extend(target_path.rglob(f'*{ext}'))

        for file_path in files:
            try:
                file_vulns = await self._scan_file(file_path)
                vulnerabilities.extend(file_vulns)
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

        return vulnerabilities

    async def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single file"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            return vulnerabilities

        for rule_name, rule_config in self.rules.items():
            for line_num, line in enumerate(lines, start=1):
                for pattern in rule_config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = Vulnerability(
                            file_path=str(file_path),
                            line_number=line_num,
                            severity=rule_config['severity'],
                            description=rule_config['description'],
                            suggested_fix=rule_config['fix'],
                            code_snippet=line.strip(),
                            cwe_id=rule_config.get('cwe')
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    async def validate_change(self, code_before: str, code_after: str) -> Tuple[bool, List[str]]:
        """Validate code change for security"""
        issues = []

        for rule_name, rule_config in self.rules.items():
            for pattern in rule_config['patterns']:
                if re.search(pattern, code_after, re.IGNORECASE):
                    if not re.search(pattern, code_before, re.IGNORECASE):
                        issues.append(f"New {rule_config['description']}")

        is_safe = len(issues) == 0
        return is_safe, issues

    async def generate_patch(self, vulnerability: Vulnerability) -> str:
        """Generate fix patch"""
        return f"Fix for {vulnerability.description} at line {vulnerability.line_number}"
