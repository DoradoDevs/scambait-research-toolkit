"""
Scambait Research Suite - File Hasher

Generates cryptographic hashes for file identification and analysis.
All processing done locally.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO

from core.models import HashResult


# =============================================================================
# Hash Generation
# =============================================================================

def hash_file(file_path: Path) -> HashResult:
    """
    Generate multiple hashes for a file.

    Args:
        file_path: Path to the file

    Returns:
        HashResult with MD5, SHA1, and SHA256 hashes
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    file_size = 0

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            file_size += len(chunk)

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        file_size=file_size
    )


def hash_bytes(data: bytes) -> HashResult:
    """
    Generate hashes for byte data.

    Args:
        data: Bytes to hash

    Returns:
        HashResult with MD5, SHA1, and SHA256 hashes
    """
    return HashResult(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data)
    )


def hash_stream(stream: BinaryIO) -> HashResult:
    """
    Generate hashes from a file stream.

    Args:
        stream: File-like object

    Returns:
        HashResult with MD5, SHA1, and SHA256 hashes
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    file_size = 0

    while chunk := stream.read(8192):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        file_size += len(chunk)

    return HashResult(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        file_size=file_size
    )


def quick_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Generate a single hash quickly.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hex digest string
    """
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256
    }

    hasher = algorithms.get(algorithm.lower(), hashlib.sha256)()

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)

    return hasher.hexdigest()


# =============================================================================
# Hash Comparison and Lookup
# =============================================================================

def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Securely compare two hashes.

    Args:
        hash1: First hash
        hash2: Second hash

    Returns:
        True if hashes match
    """
    import hmac
    return hmac.compare_digest(hash1.lower(), hash2.lower())


def format_hash_for_display(hash_value: str, truncate: int = 0) -> str:
    """
    Format hash for display.

    Args:
        hash_value: Hash string
        truncate: If > 0, truncate to this many characters

    Returns:
        Formatted hash string
    """
    formatted = hash_value.lower()

    if truncate > 0 and len(formatted) > truncate:
        return f"{formatted[:truncate//2]}...{formatted[-truncate//2:]}"

    return formatted


# =============================================================================
# Known Hash Database (Local)
# =============================================================================

# Common malware hashes for educational/research purposes
# These are well-known test file hashes, not actual malware
KNOWN_HASHES = {
    # EICAR test file (antivirus test)
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR Test File",
        "type": "test_file",
        "description": "Standard antivirus test file",
        "malicious": False
    },
    # Empty file hash
    "d41d8cd98f00b204e9800998ecf8427e": {
        "name": "Empty File",
        "type": "empty",
        "description": "Zero-byte file",
        "malicious": False
    }
}


def lookup_hash(hash_value: str) -> dict:
    """
    Look up a hash in the local known hash database.

    Args:
        hash_value: Hash to look up

    Returns:
        Match info or empty dict
    """
    hash_lower = hash_value.lower()

    if hash_lower in KNOWN_HASHES:
        return KNOWN_HASHES[hash_lower]

    return {}


def is_known_malicious(hash_result: HashResult) -> bool:
    """
    Check if file matches known malicious hash.

    Args:
        hash_result: HashResult to check

    Returns:
        True if matches known malicious hash
    """
    for hash_value in [hash_result.md5, hash_result.sha1, hash_result.sha256]:
        info = lookup_hash(hash_value)
        if info.get("malicious", False):
            return True

    return False


# =============================================================================
# Fuzzy Hashing (for similarity detection)
# =============================================================================

def calculate_ssdeep(file_path: Path) -> str:
    """
    Calculate ssdeep fuzzy hash for similarity detection.
    Requires ssdeep library (optional).

    Args:
        file_path: Path to file

    Returns:
        ssdeep hash string or empty if unavailable
    """
    try:
        import ssdeep
        return ssdeep.hash_from_file(str(file_path))
    except ImportError:
        return ""
    except Exception:
        return ""


def compare_ssdeep(hash1: str, hash2: str) -> int:
    """
    Compare two ssdeep hashes for similarity.

    Args:
        hash1: First ssdeep hash
        hash2: Second ssdeep hash

    Returns:
        Similarity score (0-100) or -1 if unavailable
    """
    if not hash1 or not hash2:
        return -1

    try:
        import ssdeep
        return ssdeep.compare(hash1, hash2)
    except ImportError:
        return -1
    except Exception:
        return -1
