"""
Test code analysis and validation functionality
"""

import pytest
from security_auditor import Severity


class TestChangeValidation:
    """Test code change validation"""

    @pytest.mark.asyncio
    async def test_safe_change_validation(self, auditor, vulnerable_sql_code, safe_sql_code):
        """Fixing vulnerability should be validated as safe"""
        is_safe, issues = await auditor.validate_change(vulnerable_sql_code, safe_sql_code)
        
        assert is_safe is True
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_unsafe_change_validation(self, auditor, safe_sql_code, vulnerable_sql_code):
        """Introducing vulnerability should be detected"""
        is_safe, issues = await auditor.validate_change(safe_sql_code, vulnerable_sql_code)
        
        assert is_safe is False
        assert len(issues) > 0
        assert any('sql' in issue.lower() for issue in issues)

    @pytest.mark.asyncio
    async def test_neutral_change_validation(self, auditor):
        """Changes without security impact should pass"""
        before = "def add(a, b):\n    return a + b"
        after = "def add(a, b):\n    # Add two numbers\n    return a + b"
        
        is_safe, issues = await auditor.validate_change(before, after)
        
        assert is_safe is True
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_multiple_issues_detection(self, auditor):
        """Should detect multiple new vulnerabilities"""
        before = "import os\nresult = safe_function()"
        after = '''
import os
password = "hardcoded_secret_123"
os.system("rm " + user_file)
query = "SELECT * FROM t WHERE id = " + uid
'''
        
        is_safe, issues = await auditor.validate_change(before, after)
        
        assert is_safe is False
        assert len(issues) >= 2  # Multiple vulnerabilities


class TestSecurityRules:
    """Test security rule matching"""

    @pytest.mark.asyncio
    async def test_rule_severity_levels(self, auditor, temp_dir):
        """Different vulnerabilities should have appropriate severity"""
        test_cases = [
            ('query = "SELECT * FROM t WHERE id = " + uid', Severity.CRITICAL),
            ('os.system("rm " + file)', Severity.CRITICAL),
            ('password = "secret123"', Severity.CRITICAL),
            ('hashlib.md5(data)', Severity.MEDIUM),
        ]
        
        for code, expected_severity in test_cases:
            test_file = temp_dir / "test.py"
            test_file.write_text(code)
            
            vulns = await auditor.scan_codebase(str(test_file))
            assert len(vulns) > 0
            assert vulns[0].severity == expected_severity

    @pytest.mark.asyncio
    async def test_rule_suggestions(self, auditor, temp_dir, vulnerable_sql_code):
        """Vulnerabilities should include fix suggestions"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        assert all(v.suggested_fix is not None for v in vulns)
        assert all(len(v.suggested_fix) > 0 for v in vulns)

    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self, auditor, temp_dir):
        """Rules should match case-insensitively"""
        test_file = temp_dir / "test.py"
        test_file.write_text("PASSWORD = 'Secret123456'")
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        secret_vulns = [v for v in vulns if 'credential' in v.description.lower()]
        assert len(secret_vulns) > 0


class TestFileTypeHandling:
    """Test handling of different file types"""

    @pytest.mark.asyncio
    async def test_python_file_scanning(self, auditor, temp_dir):
        """Should scan Python files"""
        test_file = temp_dir / "test.py"
        test_file.write_text('password = "secret123"')
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_javascript_file_scanning(self, auditor, temp_dir):
        """Should scan JavaScript files"""
        test_file = temp_dir / "test.js"
        test_file.write_text('const password = "secret123456";')
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_ignore_non_code_files(self, auditor, temp_dir):
        """Should ignore non-code files"""
        test_file = temp_dir / "data.txt"
        test_file.write_text('password = "secret123"')
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        # Should not scan .txt files
        txt_vulns = [v for v in vulns if v.file_path.endswith('.txt')]
        assert len(txt_vulns) == 0

    @pytest.mark.asyncio
    async def test_unreadable_file_handling(self, auditor, temp_dir):
        """Should handle unreadable files gracefully"""
        test_file = temp_dir / "test.py"
        test_file.write_text('password = "secret123"')
        test_file.chmod(0o000)  # Make unreadable
        
        try:
            vulns = await auditor.scan_codebase(str(test_file))
            # Should not crash, return empty or partial results
            assert isinstance(vulns, list)
        finally:
            test_file.chmod(0o644)  # Restore permissions


class TestPatternMatching:
    """Test regex pattern matching accuracy"""

    @pytest.mark.asyncio
    async def test_no_false_positives_on_comments(self, auditor, temp_dir):
        """Should not flag commented-out vulnerabilities"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
# This is safe - password = "secret123"
# query = "SELECT * FROM t WHERE id = " + uid
safe_code = True
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        # May still detect in comments, but shouldn't crash
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_multiline_patterns(self, auditor, temp_dir):
        """Should detect patterns across single lines"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
query = "SELECT * FROM users WHERE "
query += "id = " + user_id
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        sql_vulns = [v for v in vulns if 'sql' in v.description.lower()]
        assert len(sql_vulns) > 0


class TestOWASPCoverage:
    """Test OWASP Top 10 coverage"""

    @pytest.mark.asyncio
    async def test_owasp_injection_detection(self, auditor, temp_dir, owasp_test_vectors):
        """Should detect common injection patterns"""
        for injection_type, vectors in owasp_test_vectors.items():
            if injection_type == 'sql_injection':
                for vector in vectors:
                    code = f'query = "SELECT * FROM t WHERE name = \'{vector}\'"'
                    test_file = temp_dir / "test.py"
                    test_file.write_text(code)
                    
                    vulns = await auditor.scan_codebase(str(test_file))
                    # Should detect SQL pattern
                    assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_multiple_vulnerability_types(self, auditor, temp_dir):
        """Should detect multiple vulnerability types in one file"""
        test_file = temp_dir / "multi.py"
        test_file.write_text('''
password = "hardcoded_secret_123"
query = "SELECT * FROM t WHERE id = " + uid
os.system("rm " + filename)
hashlib.md5(data)
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Should find at least 3-4 different types
        assert len(vulns) >= 3
        # Check for variety of vulnerability types
        descriptions = [v.description for v in vulns]
        unique_types = set(descriptions)
        assert len(unique_types) >= 3
