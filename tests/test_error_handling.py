"""
Test error handling and edge cases
"""

import pytest
from pathlib import Path
import tempfile
from security_auditor import Vulnerability, Severity


class TestFileSystemErrors:
    """Test filesystem error handling"""

    @pytest.mark.asyncio
    async def test_nonexistent_directory(self, auditor):
        """Should handle non-existent directory"""
        vulns = await auditor.scan_codebase("/this/does/not/exist")
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_permission_denied(self, auditor, temp_dir):
        """Should handle permission denied errors"""
        test_file = temp_dir / "protected.py"
        test_file.write_text('password = "secret123"')
        test_file.chmod(0o000)
        
        try:
            vulns = await auditor.scan_codebase(str(test_file))
            assert isinstance(vulns, list)
        finally:
            test_file.chmod(0o644)

    @pytest.mark.asyncio
    async def test_empty_directory(self, auditor, temp_dir):
        """Should handle empty directory"""
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()
        
        vulns = await auditor.scan_codebase(str(empty_dir))
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_symlink_handling(self, auditor, temp_dir):
        """Should handle symlinks appropriately"""
        target = temp_dir / "target.py"
        target.write_text('password = "secret123"')
        
        link = temp_dir / "link.py"
        link.symlink_to(target)
        
        vulns = await auditor.scan_codebase(str(link))
        assert isinstance(vulns, list)


class TestInputValidation:
    """Test input validation and sanitization"""

    @pytest.mark.asyncio
    async def test_null_path(self, auditor):
        """Should handle null/None path"""
        try:
            vulns = await auditor.scan_codebase(None)
        except (TypeError, AttributeError):
            pass  # Expected to fail

    @pytest.mark.asyncio
    async def test_empty_string_path(self, auditor):
        """Should handle empty string path"""
        vulns = await auditor.scan_codebase("")
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_whitespace_only_path(self, auditor):
        """Should handle whitespace-only path"""
        vulns = await auditor.scan_codebase("   ")
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_special_characters_in_path(self, auditor, temp_dir):
        """Should handle special characters in path"""
        special_dir = temp_dir / "test (1) [2]"
        special_dir.mkdir()
        test_file = special_dir / "test.py"
        test_file.write_text('password = "secret123"')
        
        vulns = await auditor.scan_codebase(str(special_dir))
        assert isinstance(vulns, list)


class TestFileContentErrors:
    """Test handling of problematic file content"""

    @pytest.mark.asyncio
    async def test_empty_file(self, auditor, temp_dir):
        """Should handle empty files"""
        test_file = temp_dir / "empty.py"
        test_file.write_text("")
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_binary_file(self, auditor, temp_dir):
        """Should handle binary files gracefully"""
        test_file = temp_dir / "binary.py"
        with open(test_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_very_long_lines(self, auditor, temp_dir):
        """Should handle very long lines"""
        test_file = temp_dir / "long.py"
        long_line = "x = " + "a" * 100000 + ' + "secret123"'
        test_file.write_text(long_line)
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_mixed_line_endings(self, auditor, temp_dir):
        """Should handle mixed line endings"""
        test_file = temp_dir / "mixed.py"
        content = "line1\nline2\r\npassword = 'secret123'\rline4"
        test_file.write_text(content)
        
        vulns = await auditor.scan_codebase(str(test_file))
        assert isinstance(vulns, list)


class TestValidationEdgeCases:
    """Test edge cases in change validation"""

    @pytest.mark.asyncio
    async def test_validate_identical_code(self, auditor):
        """Validating identical code should be safe"""
        code = "def foo():\n    return 42"
        is_safe, issues = await auditor.validate_change(code, code)
        
        assert is_safe is True
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_validate_empty_to_code(self, auditor):
        """Adding code to empty file should be validated"""
        before = ""
        after = 'password = "secret123"'
        
        is_safe, issues = await auditor.validate_change(before, after)
        
        # Should detect new vulnerability
        assert isinstance(is_safe, bool)
        assert isinstance(issues, list)

    @pytest.mark.asyncio
    async def test_validate_code_to_empty(self, auditor):
        """Removing all code should be safe"""
        before = 'password = "secret123"'
        after = ""
        
        is_safe, issues = await auditor.validate_change(before, after)
        
        assert is_safe is True
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_validate_very_large_change(self, auditor):
        """Should handle very large code changes"""
        before = "x = 1\n" * 10000
        after = "y = 2\n" * 10000
        
        is_safe, issues = await auditor.validate_change(before, after)
        
        assert isinstance(is_safe, bool)
        assert isinstance(issues, list)


class TestPatchGeneration:
    """Test patch generation edge cases"""

    @pytest.mark.asyncio
    async def test_patch_for_all_severity_levels(self, auditor):
        """Should generate patches for all severity levels"""
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            vuln = Vulnerability(
                file_path="test.py",
                line_number=1,
                severity=severity,
                description=f"{severity.value} vulnerability",
                suggested_fix="Fix it"
            )
            
            patch = await auditor.generate_patch(vuln)
            assert isinstance(patch, str)
            assert len(patch) > 0

    @pytest.mark.asyncio
    async def test_patch_without_suggested_fix(self, auditor):
        """Should generate patch even without suggested fix"""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            severity=Severity.HIGH,
            description="SQL injection",
            suggested_fix=""
        )
        
        patch = await auditor.generate_patch(vuln)
        assert isinstance(patch, str)
        assert len(patch) > 0

    @pytest.mark.asyncio
    async def test_patch_with_special_characters(self, auditor):
        """Should handle special characters in vulnerability details"""
        vuln = Vulnerability(
            file_path="test's file (1).py",
            line_number=1,
            severity=Severity.HIGH,
            description="SQL injection with 'quotes' and \"double quotes\"",
            suggested_fix="Use params: ?, $1, etc."
        )
        
        patch = await auditor.generate_patch(vuln)
        assert isinstance(patch, str)


class TestConcurrentScanning:
    """Test concurrent operations"""

    @pytest.mark.asyncio
    async def test_scan_multiple_files_concurrently(self, auditor, temp_dir):
        """Should handle scanning multiple files"""
        for i in range(5):
            test_file = temp_dir / f"test{i}.py"
            test_file.write_text(f'password{i} = "secret123"')
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        
        assert len(vulns) >= 5  # At least one per file


class TestRuleEngine:
    """Test security rule engine behavior"""

    @pytest.mark.asyncio
    async def test_multiple_patterns_same_rule(self, auditor, temp_dir):
        """Should detect multiple patterns for same rule"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
query1 = "SELECT * FROM t WHERE id = " + uid
cursor.execute("DELETE FROM t WHERE name = " + name)
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        sql_vulns = [v for v in vulns if 'sql' in v.description.lower()]
        assert len(sql_vulns) >= 2  # Both patterns detected

    @pytest.mark.asyncio
    async def test_overlapping_patterns(self, auditor, temp_dir):
        """Should handle overlapping pattern matches"""
        test_file = temp_dir / "test.py"
        test_file.write_text('execute("SELECT * FROM t WHERE id = " + uid)')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Should detect vulnerability once per line, not duplicate
        assert isinstance(vulns, list)


class TestMemoryAndPerformance:
    """Test memory and performance characteristics"""

    @pytest.mark.asyncio
    async def test_scan_many_small_files(self, auditor, temp_dir):
        """Should handle many small files efficiently"""
        for i in range(100):
            test_file = temp_dir / f"file{i}.py"
            test_file.write_text(f"x{i} = 1")
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scan_large_codebase(self, auditor, temp_dir):
        """Should handle large codebase"""
        for i in range(10):
            test_file = temp_dir / f"large{i}.py"
            code = "\n".join([f"line{j} = {j}" for j in range(1000)])
            test_file.write_text(code)
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        assert isinstance(vulns, list)
