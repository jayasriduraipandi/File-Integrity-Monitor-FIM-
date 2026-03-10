"""
fim/hasher.py - Cryptographic hashing utilities for GuardianFIM
"""

import hashlib
import os
from pathlib import Path
from typing import Optional


SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "md5": hashlib.md5,
}

CHUNK_SIZE = 65536  # 64KB chunks for large file support


def hash_file(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Compute the cryptographic hash of a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm ('sha256', 'sha512', 'md5')

    Returns:
        Hex digest string, or None if file is unreadable
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from {list(SUPPORTED_ALGORITHMS.keys())}")

    hasher = SUPPORTED_ALGORITHMS[algorithm]()

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def hash_string(content: str, algorithm: str = "sha256") -> str:
    """Hash a string value."""
    hasher = SUPPORTED_ALGORITHMS[algorithm](content.encode())
    return hasher.hexdigest()


def get_file_metadata(filepath: str) -> dict:
    """
    Collect file metadata: size, permissions, owner, timestamps.

    Args:
        filepath: Path to the file

    Returns:
        Dictionary with metadata fields
    """
    try:
        stat = os.stat(filepath)
        return {
            "size": stat.st_size,
            "permissions": oct(stat.st_mode),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "modified": stat.st_mtime,
            "created": stat.st_ctime,
        }
    except (PermissionError, FileNotFoundError, OSError):
        return {}


def collect_files(paths: list, exclude_patterns: list = None) -> list:
    """
    Recursively collect all files from given paths, applying exclusion patterns.

    Args:
        paths: List of file/directory paths to scan
        exclude_patterns: List of glob-style patterns to exclude (e.g. ['*.log', '*.tmp'])

    Returns:
        Sorted list of absolute file paths
    """
    import fnmatch

    exclude_patterns = exclude_patterns or []
    collected = set()

    for path_str in paths:
        path = Path(path_str).resolve()

        if not path.exists():
            print(f"  [WARNING] Path does not exist: {path_str}")
            continue

        if path.is_file():
            collected.add(str(path))
        elif path.is_dir():
            for fp in path.rglob("*"):
                if fp.is_file():
                    collected.add(str(fp))

    # Apply exclusion patterns
    filtered = []
    for fp in collected:
        filename = os.path.basename(fp)
        excluded = any(fnmatch.fnmatch(filename, pat) for pat in exclude_patterns)
        if not excluded:
            filtered.append(fp)

    return sorted(filtered)
