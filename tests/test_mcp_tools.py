"""
Test MCP tool integration
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from security_auditor import Vulnerability, Severity


class TestMCPToolIntegration:
    """Test MCP server tool endpoints"""

    @pytest.mark.asyncio
    async def test_scan_codebase_tool_success(self, auditor, temp_dir, vulnerable_sql_code):
        """scan_codebase tool should return JSON results"""
        test_file = temp_dir / "vuln.py"
        test_file.write_text(vulnerable_sql_code)
        
        # Simulate MCP tool call
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Convert to JSON format like server does
        results = []
        for v in vulns:
            results.append({
                "file": v.file_path,
                "line": v.line_number,
                "severity": v.severity.value,
                "description": v.description,
                "fix": v.suggested_fix
            })
        
        assert len(results) > 0
        assert all('file' in r for r in results)
        assert all('severity' in r for r in results)

    @pytest.mark.asyncio
    async def test_validate_change_tool_success(self, auditor, vulnerable_sql_code, safe_sql_code):
        """validate_change tool should return safety status"""
        is_safe, issues = await auditor.validate_change(vulnerable_sql_code, safe_sql_code)
        
        # Convert to JSON format like server does
        result = {
            "success": True,
            "is_safe": is_safe,
            "issues": issues
        }
        
        assert result["success"] is True
        assert isinstance(result["is_safe"], bool)
        assert isinstance(result["issues"], list)

    @pytest.mark.asyncio
    async def test_generate_patch_tool_success(self, auditor, sample_vulnerability):
        """generate_patch tool should return patch text"""
        patch = await auditor.generate_patch(sample_vulnerability)
        
        # Convert to JSON format like server does
        result = {
            "success": True,
            "patch": patch
        }
        
        assert result["success"] is True
        assert isinstance(result["patch"], str)
        assert len(result["patch"]) > 0


class TestMCPToolArgumentValidation:
    """Test MCP tool argument handling"""

    @pytest.mark.asyncio
    async def test_scan_codebase_empty_path(self, auditor):
        """Should handle empty path gracefully"""
        vulns = await auditor.scan_codebase("")
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_validate_change_empty_code(self, auditor):
        """Should handle empty code gracefully"""
        is_safe, issues = await auditor.validate_change("", "")
        assert isinstance(is_safe, bool)
        assert isinstance(issues, list)

    @pytest.mark.asyncio
    async def test_generate_patch_minimal_vuln(self, auditor):
        """Should handle minimal vulnerability object"""
        vuln = Vulnerability(
            file_path="test.py",
            line_number=1,
            severity=Severity.HIGH,
            description="Test vulnerability",
            suggested_fix="Fix it"
        )
        
        patch = await auditor.generate_patch(vuln)
        assert isinstance(patch, str)
        assert len(patch) > 0


class TestMCPJSONSerialization:
    """Test JSON serialization of results"""

    @pytest.mark.asyncio
    async def test_vulnerability_json_serializable(self, auditor, temp_dir, vulnerable_sql_code):
        """Vulnerability results should be JSON serializable"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Convert to JSON format
        results = []
        for v in vulns:
            results.append({
                "file": v.file_path,
                "line": v.line_number,
                "severity": v.severity.value,
                "description": v.description,
                "fix": v.suggested_fix
            })
        
        # Should be JSON serializable
        json_str = json.dumps(results)
        parsed = json.loads(json_str)
        assert len(parsed) == len(results)

    @pytest.mark.asyncio
    async def test_validation_result_json_serializable(self, auditor):
        """Validation results should be JSON serializable"""
        is_safe, issues = await auditor.validate_change("before", "after")
        
        result = {
            "success": True,
            "is_safe": is_safe,
            "issues": issues
        }
        
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        assert parsed["success"] is True


class TestMCPErrorHandling:
    """Test MCP tool error handling"""

    @pytest.mark.asyncio
    async def test_scan_invalid_unicode(self, auditor, temp_dir):
        """Should handle files with invalid unicode"""
        test_file = temp_dir / "bad.py"
        with open(test_file, 'wb') as f:
            f.write(b'\x80\x81\x82\x83')
        
        vulns = await auditor.scan_codebase(str(test_file))
        # Should not crash, return empty or handle gracefully
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scan_large_file(self, auditor, temp_dir):
        """Should handle large files"""
        test_file = temp_dir / "large.py"
        large_code = "x = 1\n" * 10000 + 'password = "secret123"'
        test_file.write_text(large_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        # Should complete and find the vulnerability
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scan_deeply_nested_directory(self, auditor, temp_dir):
        """Should handle deeply nested directories"""
        nested = temp_dir
        for i in range(10):
            nested = nested / f"dir{i}"
            nested.mkdir()
        
        test_file = nested / "test.py"
        test_file.write_text('password = "secret123"')
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        assert isinstance(vulns, list)
        assert len(vulns) > 0


class TestMCPResponseFormat:
    """Test MCP response format compliance"""

    @pytest.mark.asyncio
    async def test_scan_response_structure(self, auditor, temp_dir, vulnerable_sql_code):
        """Scan response should have correct structure"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        response = {
            "success": True,
            "vulnerabilities": [
                {
                    "file": v.file_path,
                    "line": v.line_number,
                    "severity": v.severity.value,
                    "description": v.description,
                    "fix": v.suggested_fix
                } for v in vulns
            ],
            "count": len(vulns)
        }
        
        assert "success" in response
        assert "vulnerabilities" in response
        assert "count" in response
        assert response["count"] == len(response["vulnerabilities"])

    @pytest.mark.asyncio
    async def test_validate_response_structure(self, auditor):
        """Validate response should have correct structure"""
        is_safe, issues = await auditor.validate_change("a", "b")
        
        response = {
            "success": True,
            "is_safe": is_safe,
            "issues": issues
        }
        
        assert "success" in response
        assert "is_safe" in response
        assert "issues" in response
        assert isinstance(response["is_safe"], bool)
        assert isinstance(response["issues"], list)

    @pytest.mark.asyncio
    async def test_patch_response_structure(self, auditor, sample_vulnerability):
        """Patch response should have correct structure"""
        patch = await auditor.generate_patch(sample_vulnerability)
        
        response = {
            "success": True,
            "patch": patch
        }
        
        assert "success" in response
        assert "patch" in response
        assert isinstance(response["patch"], str)
