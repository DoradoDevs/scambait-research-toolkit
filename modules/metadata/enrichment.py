"""
Scambait Research Suite - Metadata Enrichment

Enriches captured metadata with additional information.
Uses local databases only - no external API calls.
"""

import re
import json
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from user_agents import parse as parse_ua

import config


# =============================================================================
# User Agent Parsing
# =============================================================================

def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parse user agent string into structured data.

    Args:
        user_agent: User agent string

    Returns:
        Parsed user agent information
    """
    if not user_agent:
        return {"raw": None, "parsed": False}

    try:
        ua = parse_ua(user_agent)

        return {
            "raw": user_agent,
            "parsed": True,
            "browser": {
                "family": ua.browser.family,
                "version": ua.browser.version_string
            },
            "os": {
                "family": ua.os.family,
                "version": ua.os.version_string
            },
            "device": {
                "family": ua.device.family,
                "brand": ua.device.brand,
                "model": ua.device.model,
                "is_mobile": ua.is_mobile,
                "is_tablet": ua.is_tablet,
                "is_pc": ua.is_pc,
                "is_bot": ua.is_bot
            }
        }
    except Exception as e:
        return {
            "raw": user_agent,
            "parsed": False,
            "error": str(e)
        }


# =============================================================================
# GeoIP Lookup (Local Database)
# =============================================================================

class LocalGeoIP:
    """
    Local GeoIP lookup using offline database.
    Requires GeoLite2 database to be downloaded to data/geoip/
    """

    _instance = None
    _reader = None

    @classmethod
    def get_instance(cls):
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        """Initialize GeoIP reader."""
        self._reader = None
        self._load_database()

    def _load_database(self):
        """Load GeoIP database if available."""
        db_path = config.GEOIP_DIR / "GeoLite2-City.mmdb"

        if not db_path.exists():
            # Database not available - this is optional
            return

        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(db_path))
        except ImportError:
            # geoip2 not installed
            pass
        except Exception:
            # Database corrupted or other error
            pass

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Look up IP address in local GeoIP database.

        Args:
            ip_address: IP address to look up

        Returns:
            GeoIP data or empty dict if not available
        """
        if not self._reader:
            return self._fallback_lookup(ip_address)

        try:
            response = self._reader.city(ip_address)

            return {
                "ip": ip_address,
                "country": {
                    "code": response.country.iso_code,
                    "name": response.country.name
                },
                "city": response.city.name,
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "postal_code": response.postal.code,
                "location": {
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone
                },
                "source": "geoip2_local"
            }
        except Exception:
            return self._fallback_lookup(ip_address)

    def _fallback_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Fallback when GeoIP database is not available.
        Provides basic IP classification only.
        """
        result = {
            "ip": ip_address,
            "source": "basic_classification"
        }

        # Check for private/local IPs
        if self._is_private_ip(ip_address):
            result["classification"] = "private"
            result["note"] = "Private/local IP address"
        elif self._is_loopback(ip_address):
            result["classification"] = "loopback"
            result["note"] = "Loopback address"
        else:
            result["classification"] = "public"
            result["note"] = "GeoIP database not available for detailed lookup"

        return result

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
            r"^169\.254\."
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)

    @staticmethod
    def _is_loopback(ip: str) -> bool:
        """Check if IP is loopback."""
        return ip.startswith("127.") or ip == "::1"


def enrich_with_geoip(ip_address: str) -> Dict[str, Any]:
    """
    Enrich IP address with GeoIP data.

    Args:
        ip_address: IP address to enrich

    Returns:
        GeoIP data
    """
    geoip = LocalGeoIP.get_instance()
    return geoip.lookup(ip_address)


# =============================================================================
# Header Analysis
# =============================================================================

def analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyze HTTP headers for useful information.

    Args:
        headers: Dictionary of HTTP headers

    Returns:
        Header analysis results
    """
    analysis = {
        "language_preferences": [],
        "encoding_support": [],
        "connection_info": {},
        "client_hints": {},
        "suspicious_headers": []
    }

    # Parse Accept-Language
    accept_lang = headers.get("accept-language", "")
    if accept_lang:
        # Parse language preferences
        langs = []
        for part in accept_lang.split(","):
            part = part.strip()
            if ";q=" in part:
                lang, quality = part.split(";q=")
                langs.append({"lang": lang.strip(), "quality": float(quality)})
            else:
                langs.append({"lang": part, "quality": 1.0})
        analysis["language_preferences"] = sorted(
            langs, key=lambda x: x["quality"], reverse=True
        )

    # Parse Accept-Encoding
    accept_enc = headers.get("accept-encoding", "")
    if accept_enc:
        analysis["encoding_support"] = [
            e.strip() for e in accept_enc.split(",")
        ]

    # Connection info
    analysis["connection_info"] = {
        "keep_alive": "keep-alive" in headers.get("connection", "").lower(),
        "upgrade_insecure": headers.get("upgrade-insecure-requests") == "1"
    }

    # Client hints (if present)
    client_hint_headers = [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-ch-ua-arch",
        "sec-ch-ua-bitness"
    ]
    for hint in client_hint_headers:
        if hint in headers:
            analysis["client_hints"][hint] = headers[hint]

    # Check for suspicious/interesting headers
    suspicious_patterns = [
        ("x-forwarded-for", "Proxy detected"),
        ("via", "Proxy detected"),
        ("x-real-ip", "Load balancer detected"),
        ("cf-connecting-ip", "Cloudflare detected"),
        ("x-original-url", "URL rewriting detected")
    ]
    for header, description in suspicious_patterns:
        if header in headers:
            analysis["suspicious_headers"].append({
                "header": header,
                "value": headers[header],
                "note": description
            })

    return analysis


# =============================================================================
# Composite Enrichment
# =============================================================================

def enrich_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform full metadata enrichment.

    Args:
        metadata: Raw metadata dictionary

    Returns:
        Enriched metadata
    """
    enriched = dict(metadata)

    # Enrich IP
    ip = metadata.get("ip_address")
    if ip:
        enriched["geo_data"] = enrich_with_geoip(ip)

    # Parse user agent
    ua = metadata.get("user_agent")
    if ua:
        enriched["user_agent_parsed"] = parse_user_agent(ua)

    # Analyze headers
    headers = metadata.get("headers", {})
    if headers:
        enriched["header_analysis"] = analyze_headers(headers)

    # Add enrichment timestamp
    enriched["enriched_at"] = datetime.utcnow().isoformat()

    return enriched


# =============================================================================
# Scammer Profile Building
# =============================================================================

def build_scammer_profile(
    sessions: list,
    messages: list,
    metadata_records: list
) -> Dict[str, Any]:
    """
    Build a profile of scammer behavior across sessions.

    Args:
        sessions: List of session records
        messages: List of message records
        metadata_records: List of metadata records

    Returns:
        Scammer profile
    """
    profile = {
        "session_count": len(sessions),
        "total_messages": len(messages),
        "communication_style": {},
        "technical_footprint": {},
        "behavioral_patterns": {},
        "timeline": []
    }

    # Analyze communication style
    inbound_messages = [m for m in messages if m.get("direction") == "inbound"]
    if inbound_messages:
        all_text = " ".join(m.get("content", "") for m in inbound_messages)

        # Word count and average message length
        word_counts = [len(m.get("content", "").split()) for m in inbound_messages]
        profile["communication_style"] = {
            "total_words": sum(word_counts),
            "avg_words_per_message": round(sum(word_counts) / len(word_counts), 1),
            "total_messages": len(inbound_messages)
        }

    # Technical footprint
    ips = set()
    user_agents = set()
    countries = set()

    for meta in metadata_records:
        if meta.get("ip_address"):
            ips.add(meta["ip_address"])
        if meta.get("user_agent"):
            user_agents.add(meta["user_agent"])
        geo = meta.get("geo_data", {})
        if geo.get("country", {}).get("name"):
            countries.add(geo["country"]["name"])

    profile["technical_footprint"] = {
        "unique_ips": list(ips),
        "unique_user_agents": list(user_agents)[:5],  # Limit for readability
        "countries": list(countries)
    }

    # Build timeline
    events = []
    for session in sessions:
        events.append({
            "type": "session_start",
            "timestamp": session.get("created_at"),
            "session_id": session.get("id")
        })

    events.sort(key=lambda x: x.get("timestamp", ""))
    profile["timeline"] = events[:50]  # Limit for readability

    return profile
