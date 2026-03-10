"""
tests/test_hasher.py - Unit tests for GuardianFIM hashing module
"""

import os
import tempfile
import pytest
from fim.hasher import hash_file, hash_string, get_file_metadata, collect_files


class TestHashFile:
    def test_sha256_basic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Hello, GuardianFIM!")
        digest = hash_file(str(f), "sha256")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_sha512_basic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Hello, GuardianFIM!")
        digest = hash_file(str(f), "sha512")
        assert len(digest) == 128

    def test_md5_basic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Hello, GuardianFIM!")
        digest = hash_file(str(f), "md5")
        assert len(digest) == 32

    def test_hash_changes_on_content_change(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Original content")
        h1 = hash_file(str(f), "sha256")
        f.write_text("Modified content")
        h2 = hash_file(str(f), "sha256")
        assert h1 != h2

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("same content")
        f2.write_text("same content")
        assert hash_file(str(f1)) == hash_file(str(f2))

    def test_nonexistent_file_returns_none(self):
        result = hash_file("/nonexistent/path/file.txt")
        assert result is None

    def test_invalid_algorithm_raises(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("data")
        with pytest.raises(ValueError):
            hash_file(str(f), "fakealgo")

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        digest = hash_file(str(f))
        assert digest is not None
        assert len(digest) == 64


class TestHashString:
    def test_basic(self):
        h = hash_string("hello")
        assert len(h) == 64

    def test_deterministic(self):
        assert hash_string("test") == hash_string("test")


class TestGetFileMetadata:
    def test_returns_dict(self, tmp_path):
        f = tmp_path / "meta.txt"
        f.write_text("data")
        meta = get_file_metadata(str(f))
        assert "size" in meta
        assert "permissions" in meta
        assert "modified" in meta

    def test_size_correct(self, tmp_path):
        f = tmp_path / "size.txt"
        content = "Hello World"
        f.write_text(content)
        meta = get_file_metadata(str(f))
        assert meta["size"] == len(content.encode())

    def test_nonexistent_returns_empty(self):
        meta = get_file_metadata("/nonexistent/path.txt")
        assert meta == {}


class TestCollectFiles:
    def test_collects_files_from_dir(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "c.txt").write_text("c")
        files = collect_files([str(tmp_path)])
        assert len(files) == 3

    def test_exclusion_patterns(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.log").write_text("b")
        (tmp_path / "c.tmp").write_text("c")
        files = collect_files([str(tmp_path)], exclude_patterns=["*.log", "*.tmp"])
        assert len(files) == 1
        assert all(f.endswith(".txt") for f in files)

    def test_nonexistent_path_warns(self, capsys):
        files = collect_files(["/nonexistent/path"])
        assert files == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_single_file(self, tmp_path):
        f = tmp_path / "solo.txt"
        f.write_text("solo")
        files = collect_files([str(f)])
        assert len(files) == 1
