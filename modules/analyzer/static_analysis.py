"""
Scambait Research Suite - Static File Analysis

Performs static analysis on uploaded files without execution.
All analysis is local and safe.
"""

import os
import re
import json
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from core.models import AnalysisResult

# Try to import optional analysis libraries
try:
    import filetype
    HAS_FILETYPE = True
except ImportError:
    HAS_FILETYPE = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


# =============================================================================
# File Type Detection
# =============================================================================

def detect_file_type(file_path: Path) -> Dict[str, Any]:
    """
    Detect file type using multiple methods.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary with file type information
    """
    result = {
        "extension": file_path.suffix.lower(),
        "detected_type": None,
        "mime_type": None,
        "magic_signature": None,
        "confidence": "low"
    }

    # Method 1: filetype library (based on magic bytes)
    if HAS_FILETYPE:
        try:
            kind = filetype.guess(str(file_path))
            if kind:
                result["detected_type"] = kind.extension
                result["mime_type"] = kind.mime
                result["confidence"] = "high"
        except Exception:
            pass

    # Method 2: python-magic (libmagic wrapper)
    if HAS_MAGIC and not result["detected_type"]:
        try:
            mime = magic.Magic(mime=True)
            result["mime_type"] = mime.from_file(str(file_path))

            desc = magic.Magic()
            result["magic_signature"] = desc.from_file(str(file_path))
            result["confidence"] = "high"
        except Exception:
            pass

    # Method 3: Read magic bytes directly
    if not result["detected_type"]:
        magic_info = read_magic_bytes(file_path)
        if magic_info:
            result["detected_type"] = magic_info.get("type")
            result["magic_signature"] = magic_info.get("signature")
            result["confidence"] = "medium"

    # Fallback to extension
    if not result["detected_type"]:
        result["detected_type"] = result["extension"].lstrip(".")
        result["confidence"] = "low"

    return result


def read_magic_bytes(file_path: Path, num_bytes: int = 16) -> Dict[str, Any]:
    """
    Read and analyze magic bytes from file header.

    Args:
        file_path: Path to file
        num_bytes: Number of bytes to read

    Returns:
        Magic byte analysis
    """
    MAGIC_SIGNATURES = {
        b'\x50\x4B\x03\x04': {"type": "zip", "signature": "ZIP archive"},
        b'\x50\x4B\x05\x06': {"type": "zip", "signature": "ZIP archive (empty)"},
        b'\x50\x4B\x07\x08': {"type": "zip", "signature": "ZIP archive (spanned)"},
        b'\x52\x61\x72\x21': {"type": "rar", "signature": "RAR archive"},
        b'\x37\x7A\xBC\xAF': {"type": "7z", "signature": "7-Zip archive"},
        b'\x1F\x8B': {"type": "gz", "signature": "GZIP compressed"},
        b'\x25\x50\x44\x46': {"type": "pdf", "signature": "PDF document"},
        b'\xD0\xCF\x11\xE0': {"type": "ole", "signature": "MS Office (OLE)"},
        b'\x4D\x5A': {"type": "exe", "signature": "Windows executable"},
        b'\x7F\x45\x4C\x46': {"type": "elf", "signature": "Linux executable"},
        b'\x89\x50\x4E\x47': {"type": "png", "signature": "PNG image"},
        b'\xFF\xD8\xFF': {"type": "jpg", "signature": "JPEG image"},
        b'\x47\x49\x46\x38': {"type": "gif", "signature": "GIF image"},
        b'\x42\x4D': {"type": "bmp", "signature": "BMP image"},
        b'\x3C\x3F\x78\x6D': {"type": "xml", "signature": "XML document"},
        b'\x3C\x21\x44\x4F': {"type": "html", "signature": "HTML document"},
        b'\x3C\x68\x74\x6D': {"type": "html", "signature": "HTML document"},
        b'\x7B': {"type": "json", "signature": "JSON data"},
    }

    try:
        with open(file_path, 'rb') as f:
            header = f.read(num_bytes)

        for magic, info in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                return info

        # Check for text files
        try:
            header.decode('utf-8')
            return {"type": "text", "signature": "Text/UTF-8"}
        except UnicodeDecodeError:
            pass

        return {"type": "binary", "signature": f"Unknown ({header[:8].hex()})"}

    except Exception:
        return {}


# =============================================================================
# Main Analysis Function
# =============================================================================

def analyze_file(file_path: Path) -> AnalysisResult:
    """
    Perform comprehensive static analysis on a file.

    Args:
        file_path: Path to the file

    Returns:
        AnalysisResult with findings
    """
    type_info = detect_file_type(file_path)

    suspicious_indicators = []
    metadata_extracted = {}

    # Check for extension mismatch
    if type_info["detected_type"] and type_info["extension"]:
        expected_ext = f".{type_info['detected_type']}"
        if type_info["extension"] != expected_ext:
            suspicious_indicators.append(
                f"Extension mismatch: {type_info['extension']} vs detected {expected_ext}"
            )

    # Analyze based on file type
    file_type = type_info.get("detected_type", "").lower()

    if file_type in ["exe", "dll", "bat", "ps1", "vbs", "cmd", "msi"]:
        suspicious_indicators.append(f"Executable file type: {file_type}")
        if file_type == "exe":
            pe_analysis = analyze_pe_file(file_path)
            metadata_extracted["pe_analysis"] = pe_analysis
            suspicious_indicators.extend(pe_analysis.get("suspicious", []))

    elif file_type in ["zip", "rar", "7z", "gz"]:
        archive_analysis = analyze_archive(file_path)
        metadata_extracted["archive_analysis"] = archive_analysis
        suspicious_indicators.extend(archive_analysis.get("suspicious", []))

    elif file_type in ["pdf"]:
        pdf_analysis = analyze_pdf(file_path)
        metadata_extracted["pdf_analysis"] = pdf_analysis
        suspicious_indicators.extend(pdf_analysis.get("suspicious", []))

    elif file_type in ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "ole"]:
        office_analysis = analyze_office(file_path)
        metadata_extracted["office_analysis"] = office_analysis
        suspicious_indicators.extend(office_analysis.get("suspicious", []))

    elif file_type in ["html", "htm"]:
        html_analysis = analyze_html(file_path)
        metadata_extracted["html_analysis"] = html_analysis
        suspicious_indicators.extend(html_analysis.get("suspicious", []))

    # Get basic file metadata
    try:
        stat = file_path.stat()
        metadata_extracted["file_stats"] = {
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        }
    except Exception:
        pass

    return AnalysisResult(
        file_type=file_type or "unknown",
        mime_type=type_info.get("mime_type") or "application/octet-stream",
        magic_signature=type_info.get("magic_signature"),
        is_suspicious=len(suspicious_indicators) > 0,
        suspicious_indicators=suspicious_indicators,
        metadata_extracted=metadata_extracted
    )


# =============================================================================
# Specialized Analyzers
# =============================================================================

def analyze_pe_file(file_path: Path) -> Dict[str, Any]:
    """
    Analyze Windows PE executable.

    Args:
        file_path: Path to PE file

    Returns:
        PE analysis results
    """
    result = {
        "type": "pe",
        "suspicious": [],
        "imports": [],
        "sections": []
    }

    try:
        with open(file_path, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                return result

            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(pe_offset)

            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                result["suspicious"].append("Invalid PE signature")
                return result

            # Read COFF header
            coff_header = f.read(20)
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            timestamp = struct.unpack('<I', coff_header[4:8])[0]

            result["machine"] = hex(machine)
            result["num_sections"] = num_sections
            result["compile_time"] = datetime.fromtimestamp(timestamp).isoformat()

            # Check for suspicious characteristics
            if timestamp == 0:
                result["suspicious"].append("Zero timestamp (possibly packed)")

            if num_sections > 10:
                result["suspicious"].append(f"High section count ({num_sections})")

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_archive(file_path: Path) -> Dict[str, Any]:
    """
    Analyze archive file.

    Args:
        file_path: Path to archive

    Returns:
        Archive analysis results
    """
    result = {
        "type": "archive",
        "suspicious": [],
        "contents": []
    }

    try:
        import zipfile
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    entry = {
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size
                    }
                    result["contents"].append(entry)

                    # Check for suspicious files in archive
                    name_lower = info.filename.lower()
                    if any(ext in name_lower for ext in ['.exe', '.bat', '.ps1', '.vbs', '.scr']):
                        result["suspicious"].append(f"Executable in archive: {info.filename}")

                    # Check for path traversal
                    if '..' in info.filename or info.filename.startswith('/'):
                        result["suspicious"].append(f"Path traversal attempt: {info.filename}")

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_pdf(file_path: Path) -> Dict[str, Any]:
    """
    Analyze PDF file for suspicious content.

    Args:
        file_path: Path to PDF

    Returns:
        PDF analysis results
    """
    result = {
        "type": "pdf",
        "suspicious": [],
        "objects": {}
    }

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        content_str = content.decode('latin-1', errors='ignore')

        # Count suspicious objects
        suspicious_keywords = [
            (b'/JavaScript', "Contains JavaScript"),
            (b'/JS', "Contains JavaScript"),
            (b'/OpenAction', "Auto-executes on open"),
            (b'/AA', "Additional actions"),
            (b'/Launch', "Can launch external programs"),
            (b'/EmbeddedFile', "Contains embedded files"),
            (b'/URI', "Contains URLs"),
            (b'/SubmitForm', "Form submission"),
            (b'/ImportData', "Data import"),
            (b'/RichMedia', "Rich media content"),
            (b'/XFA', "XFA forms (can contain scripts)")
        ]

        for keyword, description in suspicious_keywords:
            count = content.count(keyword)
            if count > 0:
                result["objects"][keyword.decode()] = count
                if keyword in [b'/JavaScript', b'/JS', b'/Launch', b'/OpenAction']:
                    result["suspicious"].append(f"{description} ({count} instances)")

        # Check for obfuscation patterns
        if content.count(b'/Filter') > 5:
            result["suspicious"].append("Heavy use of filters (possible obfuscation)")

        if b'/Encrypt' in content:
            result["suspicious"].append("Encrypted content")

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_office(file_path: Path) -> Dict[str, Any]:
    """
    Analyze Microsoft Office file.

    Args:
        file_path: Path to Office file

    Returns:
        Office analysis results
    """
    result = {
        "type": "office",
        "suspicious": [],
        "macros_detected": False
    }

    try:
        # Check if it's a newer XML-based format
        import zipfile
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                file_list = zf.namelist()

                # Check for macros
                macro_indicators = [
                    'word/vbaProject.bin',
                    'xl/vbaProject.bin',
                    'ppt/vbaProject.bin',
                    'vbaProject.bin'
                ]

                for indicator in macro_indicators:
                    if indicator in file_list:
                        result["macros_detected"] = True
                        result["suspicious"].append("Contains VBA macros")
                        break

                # Check for external links
                for name in file_list:
                    if 'external' in name.lower():
                        result["suspicious"].append(f"External reference: {name}")

        else:
            # Older OLE format
            with open(file_path, 'rb') as f:
                content = f.read(10000)  # Read first 10KB

            if b'VBA' in content or b'vbaProject' in content:
                result["macros_detected"] = True
                result["suspicious"].append("Contains VBA macros")

            if b'DDEAUTO' in content or b'DDE' in content:
                result["suspicious"].append("Contains DDE links (potential code execution)")

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_html(file_path: Path) -> Dict[str, Any]:
    """
    Analyze HTML file for suspicious content.

    Args:
        file_path: Path to HTML file

    Returns:
        HTML analysis results
    """
    result = {
        "type": "html",
        "suspicious": [],
        "scripts": 0,
        "iframes": 0,
        "forms": 0,
        "links": []
    }

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        content_lower = content.lower()

        # Count elements
        result["scripts"] = content_lower.count('<script')
        result["iframes"] = content_lower.count('<iframe')
        result["forms"] = content_lower.count('<form')

        # Check for suspicious patterns
        if result["scripts"] > 5:
            result["suspicious"].append(f"High script count ({result['scripts']})")

        if 'eval(' in content_lower or 'eval (' in content_lower:
            result["suspicious"].append("Contains eval() - potential obfuscation")

        if 'document.write' in content_lower:
            result["suspicious"].append("Uses document.write - dynamic content injection")

        if 'fromcharcode' in content_lower:
            result["suspicious"].append("Uses fromCharCode - possible obfuscation")

        if result["iframes"] > 0:
            result["suspicious"].append(f"Contains {result['iframes']} iframe(s)")

        # Check for data URIs
        if 'data:text/html' in content_lower or 'data:application' in content_lower:
            result["suspicious"].append("Contains data URI - embedded content")

        # Extract links
        import re
        links = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        result["links"] = links[:20]  # Limit to 20

    except Exception as e:
        result["error"] = str(e)

    return result


# =============================================================================
# String Analysis
# =============================================================================

def extract_strings(file_path: Path, min_length: int = 4) -> List[str]:
    """
    Extract printable strings from a file.

    Args:
        file_path: Path to file
        min_length: Minimum string length

    Returns:
        List of extracted strings
    """
    strings = []

    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{%d,}' % min_length
        ascii_strings = re.findall(ascii_pattern, content)
        strings.extend(s.decode('ascii') for s in ascii_strings)

        # Unicode strings (UTF-16LE)
        unicode_strings = []
        for i in range(0, len(content) - min_length * 2, 2):
            try:
                chunk = content[i:i+200]  # Limit chunk size
                if all(chunk[j+1:j+2] == b'\x00' for j in range(0, min(len(chunk)-1, 40), 2)):
                    decoded = chunk.decode('utf-16-le').split('\x00')[0]
                    if len(decoded) >= min_length and decoded.isprintable():
                        unicode_strings.append(decoded)
            except Exception:
                continue

        strings.extend(unicode_strings[:100])  # Limit unicode strings

    except Exception:
        pass

    # Remove duplicates while preserving order
    seen = set()
    unique_strings = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append(s)

    return unique_strings[:500]  # Limit total strings


def find_suspicious_strings(strings: List[str]) -> List[Dict[str, str]]:
    """
    Find suspicious strings in extracted string list.

    Args:
        strings: List of extracted strings

    Returns:
        List of suspicious string findings
    """
    suspicious = []

    patterns = {
        "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
        "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "registry_key": r'HKEY_[A-Z_]+\\[^\s]+',
        "file_path": r'[A-Z]:\\[^\s<>"|?*]+',
        "powershell": r'powershell|invoke-expression|iex\s|downloadstring',
        "cmd": r'cmd\.exe|command\.com',
        "crypto_wallet": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b'
    }

    for s in strings:
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, s, re.IGNORECASE):
                suspicious.append({
                    "type": pattern_name,
                    "value": s[:200]  # Truncate long strings
                })
                break

    return suspicious[:100]  # Limit findings
