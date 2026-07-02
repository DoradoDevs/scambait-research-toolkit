"""
Scambait Research Suite - Link/URL Analyzer

Analyzes URLs and links for suspicious patterns.
All analysis is local - no external requests made.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List, Optional
import base64

from core.models import LinkAnalysis


# =============================================================================
# URL Defanging
# =============================================================================

def defang_url(url: str) -> str:
    """
    Defang a URL for safe display/sharing.

    Args:
        url: Original URL

    Returns:
        Defanged URL
    """
    defanged = url

    # Replace protocol
    defanged = defanged.replace("http://", "hxxp://")
    defanged = defanged.replace("https://", "hxxps://")
    defanged = defanged.replace("ftp://", "fxp://")

    # Replace dots in domain
    defanged = re.sub(r'\.(?=[a-zA-Z])', '[.]', defanged)

    return defanged


def refang_url(url: str) -> str:
    """
    Convert defanged URL back to normal.

    Args:
        url: Defanged URL

    Returns:
        Original URL
    """
    refanged = url

    refanged = refanged.replace("hxxp://", "http://")
    refanged = refanged.replace("hxxps://", "https://")
    refanged = refanged.replace("fxp://", "ftp://")
    refanged = refanged.replace("[.]", ".")

    return refanged


def defang_ip(ip: str) -> str:
    """
    Defang an IP address for safe display.

    Args:
        ip: IP address

    Returns:
        Defanged IP
    """
    return ip.replace(".", "[.]")


# =============================================================================
# URL Analysis
# =============================================================================

def analyze_link(url: str) -> LinkAnalysis:
    """
    Perform comprehensive link analysis.

    Args:
        url: URL to analyze

    Returns:
        LinkAnalysis with findings
    """
    # Handle defanged URLs
    working_url = refang_url(url)

    suspicious_indicators = []
    pattern_matches = []

    try:
        parsed = urlparse(working_url)
    except Exception:
        return LinkAnalysis(
            original_url=url,
            defanged_url=defang_url(url),
            domain="parse_error",
            is_suspicious=True,
            suspicious_indicators=["Failed to parse URL"],
            pattern_matches=[]
        )

    domain = parsed.netloc.lower()

    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]

    # Check for IP address instead of domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        suspicious_indicators.append("Uses IP address instead of domain")
        pattern_matches.append("ip_address_url")

    # Check for suspicious TLDs
    suspicious_tlds = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often abused
        '.xyz', '.top', '.club', '.work', '.click',
        '.link', '.info', '.biz', '.pw', '.cc'
    ]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            suspicious_indicators.append(f"Suspicious TLD: {tld}")
            pattern_matches.append("suspicious_tld")
            break

    # Check for typosquatting patterns
    typosquat_targets = [
        'google', 'facebook', 'microsoft', 'apple', 'amazon',
        'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
        'bank', 'secure', 'account', 'login', 'signin', 'verify'
    ]
    for target in typosquat_targets:
        if target in domain and not domain.endswith(f'{target}.com'):
            suspicious_indicators.append(f"Possible typosquatting: contains '{target}'")
            pattern_matches.append("typosquatting")
            break

    # Check URL length
    if len(working_url) > 200:
        suspicious_indicators.append(f"Unusually long URL ({len(working_url)} chars)")
        pattern_matches.append("long_url")

    # Check for encoded characters
    if '%' in working_url:
        decoded = unquote(working_url)
        if decoded != working_url:
            suspicious_indicators.append("Contains URL-encoded characters")
            pattern_matches.append("url_encoding")

    # Check for multiple subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        suspicious_indicators.append(f"Multiple subdomains ({subdomain_count})")
        pattern_matches.append("many_subdomains")

    # Check path for suspicious patterns
    path = parsed.path.lower()
    suspicious_paths = [
        '/wp-admin/', '/wp-includes/', '/wp-content/',  # WordPress exploitation
        '/administrator/', '/admin/', '/login/',
        '.php?', '.asp?', '.aspx?',
        '/index.php/', '/mail/', '/webmail/',
        '/secure/', '/account/', '/verify/', '/update/',
        '/signin/', '/auth/', '/oauth/'
    ]
    for sus_path in suspicious_paths:
        if sus_path in path:
            suspicious_indicators.append(f"Suspicious path pattern: {sus_path}")
            pattern_matches.append("suspicious_path")
            break

    # Check query parameters
    if parsed.query:
        params = parse_qs(parsed.query)
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'return', 'next', 'target']
        for param in suspicious_params:
            if param in params:
                suspicious_indicators.append(f"Redirect parameter: {param}")
                pattern_matches.append("redirect_param")
                break

        # Check for base64 in parameters
        for key, values in params.items():
            for value in values:
                if looks_like_base64(value):
                    suspicious_indicators.append(f"Base64-encoded parameter: {key}")
                    pattern_matches.append("base64_param")

    # Check for homograph attacks (mixed scripts)
    if has_mixed_scripts(domain):
        suspicious_indicators.append("Possible homograph attack (mixed character sets)")
        pattern_matches.append("homograph")

    # Check for data URI
    if working_url.lower().startswith('data:'):
        suspicious_indicators.append("Data URI - embedded content")
        pattern_matches.append("data_uri")

    # Check for javascript URI
    if working_url.lower().startswith('javascript:'):
        suspicious_indicators.append("JavaScript URI - potential XSS")
        pattern_matches.append("javascript_uri")

    return LinkAnalysis(
        original_url=url,
        defanged_url=defang_url(working_url),
        domain=domain,
        is_suspicious=len(suspicious_indicators) > 0,
        suspicious_indicators=suspicious_indicators,
        pattern_matches=list(set(pattern_matches))  # Remove duplicates
    )


# =============================================================================
# Helper Functions
# =============================================================================

def looks_like_base64(s: str) -> bool:
    """
    Check if string looks like base64 encoded data.

    Args:
        s: String to check

    Returns:
        True if likely base64
    """
    if len(s) < 20:
        return False

    # Base64 character set
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False

    # Check if length is roughly correct (base64 length is ~4/3 original)
    if len(s) % 4 != 0:
        return False

    # Try to decode
    try:
        decoded = base64.b64decode(s)
        # Check if decoded content looks meaningful
        return len(decoded) > 10
    except Exception:
        return False


def has_mixed_scripts(domain: str) -> bool:
    """
    Check for mixed Unicode scripts (homograph attack).

    Args:
        domain: Domain to check

    Returns:
        True if mixed scripts detected
    """
    # Simplified check - look for non-ASCII characters
    has_ascii = any(ord(c) < 128 and c.isalpha() for c in domain)
    has_non_ascii = any(ord(c) >= 128 for c in domain)

    return has_ascii and has_non_ascii


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text content.

    Args:
        text: Text to search

    Returns:
        List of found URLs
    """
    # URL pattern
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

    urls = re.findall(url_pattern, text, re.IGNORECASE)

    # Also check for defanged URLs
    defanged_pattern = r'hxxps?://[^\s<>"{}|\\^`\[\]]+'
    defanged_urls = re.findall(defanged_pattern, text, re.IGNORECASE)
    urls.extend(refang_url(u) for u in defanged_urls)

    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    return unique_urls


def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from text.

    Args:
        text: Text to search

    Returns:
        List of found domains
    """
    # Domain pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    domains = re.findall(domain_pattern, text)

    # Remove common false positives
    false_positives = ['example.com', 'localhost.local', 'test.test']
    domains = [d for d in domains if d.lower() not in false_positives]

    return list(set(domains))


# =============================================================================
# Bulk Analysis
# =============================================================================

def analyze_multiple_links(urls: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple URLs and provide summary.

    Args:
        urls: List of URLs to analyze

    Returns:
        Summary analysis
    """
    results = []
    suspicious_count = 0
    domains_seen = set()
    all_patterns = []

    for url in urls:
        analysis = analyze_link(url)
        results.append(analysis.model_dump())

        if analysis.is_suspicious:
            suspicious_count += 1

        domains_seen.add(analysis.domain)
        all_patterns.extend(analysis.pattern_matches)

    # Pattern frequency
    pattern_frequency = {}
    for pattern in all_patterns:
        pattern_frequency[pattern] = pattern_frequency.get(pattern, 0) + 1

    return {
        "total_urls": len(urls),
        "suspicious_urls": suspicious_count,
        "unique_domains": len(domains_seen),
        "domains": list(domains_seen),
        "pattern_frequency": pattern_frequency,
        "results": results
    }


# =============================================================================
# Known Malicious Patterns
# =============================================================================

# Patterns commonly seen in phishing/scam URLs
KNOWN_MALICIOUS_PATTERNS = {
    "crypto_scam": [
        r'claim.*reward', r'airdrop.*free', r'connect.*wallet',
        r'verify.*account', r'metamask', r'trust.*wallet'
    ],
    "tech_support_scam": [
        r'microsoft.*support', r'apple.*support', r'virus.*detected',
        r'computer.*infected', r'call.*now'
    ],
    "phishing": [
        r'verify.*identity', r'suspended.*account', r'unusual.*activity',
        r'confirm.*details', r'update.*payment'
    ],
    "investment_scam": [
        r'guaranteed.*return', r'double.*money', r'risk.*free',
        r'limited.*offer', r'exclusive.*opportunity'
    ]
}


def check_known_patterns(url: str) -> List[Dict[str, str]]:
    """
    Check URL against known malicious patterns.

    Args:
        url: URL to check

    Returns:
        List of pattern matches
    """
    matches = []
    url_lower = url.lower()

    for category, patterns in KNOWN_MALICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, url_lower):
                matches.append({
                    "category": category,
                    "pattern": pattern,
                    "match": re.search(pattern, url_lower).group()
                })

    return matches
