"""
tests/test_monitor.py - Integration tests for FileIntegrityMonitor
"""

import json
import os
import pytest
from fim.monitor import FileIntegrityMonitor
from fim.config import Config


@pytest.fixture
def fim():
    return FileIntegrityMonitor(Config())


@pytest.fixture
def sample_dir(tmp_path):
    """Create a sample directory with files."""
    (tmp_path / "file1.txt").write_text("original content 1")
    (tmp_path / "file2.txt").write_text("original content 2")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "file3.txt").write_text("original content 3")
    return tmp_path


class TestCreateBaseline:
    def test_creates_baseline_file(self, fim, sample_dir, tmp_path):
        output = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=output)
        assert os.path.exists(output)

    def test_baseline_contains_metadata(self, fim, sample_dir, tmp_path):
        output = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=output, algo="sha256")
        with open(output) as f:
            data = json.load(f)
        assert data["meta"]["algorithm"] == "sha256"
        assert data["meta"]["total_files"] == 3
        assert "files" in data

    def test_baseline_all_files_hashed(self, fim, sample_dir, tmp_path):
        output = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=output)
        with open(output) as f:
            data = json.load(f)
        assert len(data["files"]) == 3
        for fp, info in data["files"].items():
            assert "hash" in info
            assert len(info["hash"]) == 64  # SHA-256


class TestScan:
    def test_no_changes_detected(self, fim, sample_dir, tmp_path):
        baseline = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=baseline)
        results = fim.scan(baseline_path=baseline)
        assert results["summary"]["modified"] == 0
        assert results["summary"]["deleted"] == 0
        assert results["summary"]["added"] == 0
        assert len(results["findings"]) == 0

    def test_detects_modified_file(self, fim, sample_dir, tmp_path):
        baseline = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=baseline)
        # Modify a file
        (sample_dir / "file1.txt").write_text("TAMPERED CONTENT")
        results = fim.scan(baseline_path=baseline)
        assert results["summary"]["modified"] == 1
        modified = [f for f in results["findings"] if f["type"] == "MODIFIED"]
        assert len(modified) == 1

    def test_detects_deleted_file(self, fim, sample_dir, tmp_path):
        baseline = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=baseline)
        # Delete a file
        (sample_dir / "file2.txt").unlink()
        results = fim.scan(baseline_path=baseline)
        assert results["summary"]["deleted"] == 1

    def test_detects_new_file(self, fim, sample_dir, tmp_path):
        baseline = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=baseline)
        # Add a new file
        (sample_dir / "new_file.txt").write_text("new content")
        results = fim.scan(baseline_path=baseline)
        assert results["summary"]["added"] == 1

    def test_missing_baseline_returns_empty(self, fim):
        results = fim.scan(baseline_path="/nonexistent/baseline.json")
        assert results == {}

    def test_multiple_changes(self, fim, sample_dir, tmp_path):
        baseline = str(tmp_path / "baseline.json")
        fim.create_baseline([str(sample_dir)], output=baseline)
        (sample_dir / "file1.txt").write_text("modified")
        (sample_dir / "file2.txt").unlink()
        (sample_dir / "new.txt").write_text("new")
        results = fim.scan(baseline_path=baseline)
        assert results["summary"]["modified"] == 1
        assert results["summary"]["deleted"] == 1
        assert results["summary"]["added"] == 1
        assert len(results["findings"]) == 3
