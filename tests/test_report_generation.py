"""
Test audit report generation
"""

import pytest
from security_auditor import Severity


class TestReportGeneration:
    """Test vulnerability report formatting"""

    @pytest.mark.asyncio
    async def test_report_contains_all_fields(self, auditor, temp_dir, vulnerable_sql_code):
        """Report should contain all vulnerability fields"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        for v in vulns:
            assert hasattr(v, 'file_path')
            assert hasattr(v, 'line_number')
            assert hasattr(v, 'severity')
            assert hasattr(v, 'description')
            assert hasattr(v, 'suggested_fix')
            assert hasattr(v, 'code_snippet')
            assert hasattr(v, 'cwe_id')

    @pytest.mark.asyncio
    async def test_report_severity_distribution(self, auditor, temp_dir):
        """Report should show severity distribution"""
        test_file = temp_dir / "mixed.py"
        test_file.write_text('''
password = "secret123"  # CRITICAL
query = "SELECT * FROM t WHERE id = " + uid  # CRITICAL
hashlib.md5(data)  # MEDIUM
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        critical = [v for v in vulns if v.severity == Severity.CRITICAL]
        medium = [v for v in vulns if v.severity == Severity.MEDIUM]
        
        assert len(critical) >= 2
        assert len(medium) >= 1

    @pytest.mark.asyncio
    async def test_report_file_grouping(self, auditor, temp_dir):
        """Report should group vulnerabilities by file"""
        for i in range(3):
            test_file = temp_dir / f"file{i}.py"
            test_file.write_text(f'password{i} = "secret123"')
        
        vulns = await auditor.scan_codebase(str(temp_dir))
        
        # Group by file
        files = {}
        for v in vulns:
            if v.file_path not in files:
                files[v.file_path] = []
            files[v.file_path].append(v)
        
        assert len(files) >= 3


class TestReportFormatting:
    """Test report output formatting"""

    @pytest.mark.asyncio
    async def test_json_report_format(self, auditor, temp_dir, vulnerable_sql_code):
        """Should format report as JSON"""
        import json
        
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        report = {
            "total_vulnerabilities": len(vulns),
            "by_severity": {},
            "vulnerabilities": [
                {
                    "file": v.file_path,
                    "line": v.line_number,
                    "severity": v.severity.value,
                    "description": v.description,
                    "cwe": v.cwe_id
                } for v in vulns
            ]
        }
        
        # Should be JSON serializable
        json_str = json.dumps(report, indent=2)
        assert len(json_str) > 0

    @pytest.mark.asyncio
    async def test_report_summary_stats(self, auditor, temp_dir):
        """Report should include summary statistics"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
password = "secret123"
api_key = "TESTKEY_1234567890123456789012"
query = "SELECT * FROM t WHERE id = " + uid
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Calculate summary stats
        total = len(vulns)
        by_severity = {}
        for v in vulns:
            sev = v.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        assert total >= 3
        assert len(by_severity) > 0


class TestCWEMapping:
    """Test CWE (Common Weakness Enumeration) mapping"""

    @pytest.mark.asyncio
    async def test_sql_injection_cwe(self, auditor, temp_dir, vulnerable_sql_code):
        """SQL injection should map to CWE-89"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        sql_vulns = [v for v in vulns if 'sql' in v.description.lower()]
        assert len(sql_vulns) > 0
        assert sql_vulns[0].cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_command_injection_cwe(self, auditor, temp_dir, vulnerable_command_code):
        """Command injection should map to CWE-78"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_command_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        cmd_vulns = [v for v in vulns if 'command' in v.description.lower()]
        assert len(cmd_vulns) > 0
        assert cmd_vulns[0].cwe_id == "CWE-78"

    @pytest.mark.asyncio
    async def test_hardcoded_secrets_cwe(self, auditor, temp_dir, hardcoded_secrets):
        """Hardcoded secrets should map to CWE-798"""
        test_file = temp_dir / "test.py"
        test_file.write_text(hardcoded_secrets)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        secret_vulns = [v for v in vulns if 'credential' in v.description.lower()]
        assert len(secret_vulns) > 0
        assert all(v.cwe_id == "CWE-798" for v in secret_vulns)


class TestReportFiltering:
    """Test report filtering capabilities"""

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, auditor, temp_dir):
        """Should filter vulnerabilities by severity"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
password = "secret123"  # CRITICAL
hashlib.md5(data)  # MEDIUM
''')
        
        all_vulns = await auditor.scan_codebase(str(test_file))
        
        critical_only = [v for v in all_vulns if v.severity == Severity.CRITICAL]
        medium_only = [v for v in all_vulns if v.severity == Severity.MEDIUM]
        
        assert len(critical_only) > 0
        assert len(medium_only) > 0

    @pytest.mark.asyncio
    async def test_filter_by_file(self, auditor, temp_dir):
        """Should filter vulnerabilities by file"""
        file1 = temp_dir / "file1.py"
        file1.write_text('password = "secret123"')
        
        file2 = temp_dir / "file2.py"
        file2.write_text('api_key = "TESTKEY_1234567890123456789012"')
        
        all_vulns = await auditor.scan_codebase(str(temp_dir))
        
        file1_vulns = [v for v in all_vulns if 'file1' in v.file_path]
        file2_vulns = [v for v in all_vulns if 'file2' in v.file_path]
        
        assert len(file1_vulns) > 0
        assert len(file2_vulns) > 0


class TestReportMetrics:
    """Test report metrics and analytics"""

    @pytest.mark.asyncio
    async def test_vulnerability_density(self, auditor, temp_dir):
        """Should calculate vulnerability density"""
        test_file = temp_dir / "test.py"
        code_lines = [
            'import os',
            'password = "secret123"',  # vuln
            'def foo():',
            '    query = "SELECT * FROM t WHERE id = " + uid',  # vuln
            '    return True',
        ]
        test_file.write_text('\n'.join(code_lines))
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Calculate density
        total_lines = len(code_lines)
        vuln_count = len(vulns)
        density = vuln_count / total_lines if total_lines > 0 else 0
        
        assert vuln_count >= 2
        assert density > 0

    @pytest.mark.asyncio
    async def test_cwe_distribution(self, auditor, temp_dir):
        """Should show CWE distribution"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
password = "secret123"  # CWE-798
query = "SELECT * FROM t WHERE id = " + uid  # CWE-89
os.system("rm " + file)  # CWE-78
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        cwe_counts = {}
        for v in vulns:
            cwe = v.cwe_id
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        assert len(cwe_counts) >= 2  # Multiple CWE types


class TestReportExport:
    """Test report export functionality"""

    @pytest.mark.asyncio
    async def test_export_to_dict(self, auditor, temp_dir, vulnerable_sql_code):
        """Should export vulnerabilities to dict"""
        test_file = temp_dir / "test.py"
        test_file.write_text(vulnerable_sql_code)
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        # Convert to dict
        vuln_dicts = [
            {
                "file": v.file_path,
                "line": v.line_number,
                "severity": v.severity.value,
                "description": v.description,
                "fix": v.suggested_fix,
                "cwe": v.cwe_id,
                "snippet": v.code_snippet
            } for v in vulns
        ]
        
        assert len(vuln_dicts) > 0
        assert all(isinstance(d, dict) for d in vuln_dicts)

    @pytest.mark.asyncio
    async def test_export_summary_only(self, auditor, temp_dir):
        """Should export summary without full details"""
        test_file = temp_dir / "test.py"
        test_file.write_text('''
password = "secret123"
query = "SELECT * FROM t WHERE id = " + uid
''')
        
        vulns = await auditor.scan_codebase(str(test_file))
        
        summary = {
            "total": len(vulns),
            "critical": len([v for v in vulns if v.severity == Severity.CRITICAL]),
            "high": len([v for v in vulns if v.severity == Severity.HIGH]),
            "medium": len([v for v in vulns if v.severity == Severity.MEDIUM]),
            "low": len([v for v in vulns if v.severity == Severity.LOW]),
        }
        
        assert summary["total"] >= 2
        assert summary["critical"] >= 2
