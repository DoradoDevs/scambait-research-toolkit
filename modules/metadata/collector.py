"""
Scambait Research Suite - Metadata Collector

Captures and analyzes metadata from interactions.
All data processed and stored locally.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

import config
from core.models import (
    MetadataCapture, MetadataResponse, PatternDetectionResult,
    SessionReport
)


# =============================================================================
# Request Metadata Capture
# =============================================================================

def capture_request_metadata(request) -> MetadataCapture:
    """
    Capture metadata from an incoming request.

    Args:
        request: FastAPI Request object

    Returns:
        MetadataCapture with all captured data
    """
    headers = dict(request.headers)

    # Remove sensitive headers
    sensitive_headers = ['authorization', 'cookie', 'set-cookie']
    for header in sensitive_headers:
        headers.pop(header, None)

    return MetadataCapture(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        headers=headers,
        additional={
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query) if request.url.query else None,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


def generate_fingerprint(metadata: Dict[str, Any]) -> str:
    """
    Generate a fingerprint from metadata.
    Useful for tracking unique visitors/interactions.

    Args:
        metadata: Dictionary of metadata

    Returns:
        SHA256 fingerprint string
    """
    # Combine key identifiers
    fingerprint_data = {
        "ip": metadata.get("ip_address", ""),
        "ua": metadata.get("user_agent", ""),
        "accept": metadata.get("headers", {}).get("accept", ""),
        "accept-language": metadata.get("headers", {}).get("accept-language", ""),
        "accept-encoding": metadata.get("headers", {}).get("accept-encoding", "")
    }

    # Create deterministic string
    fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)

    # Hash it
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


# =============================================================================
# Pattern Detection
# =============================================================================

def detect_patterns(text: str) -> Dict[str, Any]:
    """
    Detect scam patterns in text content.

    Args:
        text: Text to analyze

    Returns:
        PatternDetectionResult as dict
    """
    if not text:
        return {
            "patterns_found": [],
            "total_score": 0.0,
            "risk_level": "low"
        }

    text_lower = text.lower()
    patterns_found = []
    total_score = 0.0

    for pattern_type, keywords in config.SCAM_PATTERNS.items():
        matches = []
        for keyword in keywords:
            if keyword.lower() in text_lower:
                matches.append(keyword)

        if matches:
            confidence = min(len(matches) / 3.0, 1.0)  # Cap at 1.0
            total_score += confidence

            patterns_found.append({
                "type": pattern_type,
                "confidence": round(confidence, 2),
                "evidence": ", ".join(matches[:5]),  # Limit evidence length
                "match_count": len(matches)
            })

    # Determine risk level
    if total_score >= 2.0:
        risk_level = "high"
    elif total_score >= 1.0:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "patterns_found": patterns_found,
        "total_score": round(total_score, 2),
        "risk_level": risk_level
    }


def analyze_language_patterns(text: str) -> Dict[str, Any]:
    """
    Analyze language patterns common in scams.

    Args:
        text: Text to analyze

    Returns:
        Dictionary of language analysis results
    """
    analysis = {
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "caps_ratio": 0.0,
        "urgency_phrases": [],
        "money_mentions": [],
        "suspicious_urls": [],
        "phone_numbers": [],
        "emails": []
    }

    # Calculate caps ratio
    alpha_chars = [c for c in text if c.isalpha()]
    if alpha_chars:
        caps_count = sum(1 for c in alpha_chars if c.isupper())
        analysis["caps_ratio"] = round(caps_count / len(alpha_chars), 2)

    # Find urgency phrases
    urgency_patterns = [
        r"\b(act now|urgent|immediately|asap|limited time|expires? today)\b",
        r"\b(don'?t wait|hurry|last chance|final notice)\b",
        r"\b(within \d+ (hours?|days?|minutes?))\b"
    ]
    for pattern in urgency_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        analysis["urgency_phrases"].extend([m if isinstance(m, str) else m[0] for m in matches])

    # Find money mentions
    money_patterns = [
        r"\$[\d,]+(?:\.\d{2})?",
        r"\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:dollars?|usd|btc|eth|sol)\b",
        r"\b(?:bitcoin|ethereum|solana|crypto)\b"
    ]
    for pattern in money_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        analysis["money_mentions"].extend(matches)

    # Find URLs (defanged for safety)
    url_pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    analysis["suspicious_urls"] = [defang_url(url) for url in urls[:10]]

    # Find phone numbers
    phone_pattern = r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    analysis["phone_numbers"] = re.findall(phone_pattern, text)[:5]

    # Find emails
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    analysis["emails"] = re.findall(email_pattern, text)[:5]

    return analysis


def defang_url(url: str) -> str:
    """
    Defang a URL for safe display.

    Args:
        url: Original URL

    Returns:
        Defanged URL
    """
    defanged = url.replace("http://", "hxxp://")
    defanged = defanged.replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


# =============================================================================
# Session Report Generation
# =============================================================================

async def generate_session_report(session_id: str) -> Dict[str, Any]:
    """
    Generate a comprehensive session report.

    Args:
        session_id: Session ID

    Returns:
        Complete session report as dict
    """
    from core.database import (
        SessionDB, MessageDB, AttachmentDB,
        PatternFlagDB, get_db_context
    )

    # Get session data
    session = await SessionDB.get(session_id)
    if not session:
        return {"error": "Session not found"}

    messages = await MessageDB.get_by_session(session_id)
    attachments = await AttachmentDB.get_by_session(session_id)
    patterns = await PatternFlagDB.get_by_session(session_id)

    # Get metadata
    async with get_db_context() as db:
        cursor = await db.execute(
            "SELECT * FROM metadata WHERE session_id = ?",
            (session_id,)
        )
        metadata_rows = await cursor.fetchall()
        metadata = [dict(row) for row in metadata_rows]

    # Generate summary
    summary = {
        "total_messages": len(messages),
        "inbound_messages": sum(1 for m in messages if m.get("direction") == "inbound"),
        "outbound_messages": sum(1 for m in messages if m.get("direction") == "outbound"),
        "total_attachments": len(attachments),
        "malicious_attachments": sum(1 for a in attachments if a.get("is_malicious")),
        "patterns_detected": len(patterns),
        "pattern_types": list(set(p.get("pattern_type") for p in patterns)),
        "time_wasted_seconds": session.get("total_time_wasted_seconds", 0),
        "time_wasted_formatted": format_duration(session.get("total_time_wasted_seconds", 0)),
        "unique_ips": list(set(m.get("ip_address") for m in metadata if m.get("ip_address")))
    }

    # Aggregate pattern analysis
    if messages:
        all_inbound_text = " ".join(
            m.get("content", "") for m in messages
            if m.get("direction") == "inbound"
        )
        language_analysis = analyze_language_patterns(all_inbound_text)
        summary["language_analysis"] = language_analysis

    report = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.utcnow().isoformat(),
        "session": session,
        "summary": summary,
        "messages": messages,
        "metadata": metadata,
        "attachments": attachments,
        "pattern_flags": patterns,
        "research_metadata": config.RESEARCH_METADATA
    }

    return report


def format_duration(seconds: int) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes} min {secs} sec"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours} hr {minutes} min"


# =============================================================================
# Behavioral Analysis
# =============================================================================

def analyze_timing_patterns(messages: List[Dict]) -> Dict[str, Any]:
    """
    Analyze timing patterns in message exchanges.

    Args:
        messages: List of message dictionaries

    Returns:
        Timing analysis results
    """
    if len(messages) < 2:
        return {"insufficient_data": True}

    # Parse timestamps
    timestamps = []
    for msg in messages:
        ts = msg.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        timestamps.append((ts, msg.get("direction")))

    # Sort by timestamp
    timestamps.sort(key=lambda x: x[0])

    # Calculate response times
    inbound_to_outbound = []
    outbound_to_inbound = []

    for i in range(1, len(timestamps)):
        prev_time, prev_dir = timestamps[i-1]
        curr_time, curr_dir = timestamps[i]

        delta = (curr_time - prev_time).total_seconds()

        if prev_dir == "inbound" and curr_dir == "outbound":
            inbound_to_outbound.append(delta)
        elif prev_dir == "outbound" and curr_dir == "inbound":
            outbound_to_inbound.append(delta)

    analysis = {
        "total_duration_seconds": (timestamps[-1][0] - timestamps[0][0]).total_seconds(),
        "message_count": len(messages),
        "avg_response_time_to_scammer": None,
        "avg_scammer_response_time": None,
        "longest_gap_seconds": 0
    }

    if inbound_to_outbound:
        analysis["avg_response_time_to_scammer"] = round(
            sum(inbound_to_outbound) / len(inbound_to_outbound), 1
        )

    if outbound_to_inbound:
        analysis["avg_scammer_response_time"] = round(
            sum(outbound_to_inbound) / len(outbound_to_inbound), 1
        )

    # Find longest gap
    for i in range(1, len(timestamps)):
        gap = (timestamps[i][0] - timestamps[i-1][0]).total_seconds()
        if gap > analysis["longest_gap_seconds"]:
            analysis["longest_gap_seconds"] = gap

    return analysis


def calculate_engagement_score(session: Dict, messages: List[Dict]) -> float:
    """
    Calculate an engagement score for the session.
    Higher scores indicate more successful baiting.

    Args:
        session: Session dictionary
        messages: List of messages

    Returns:
        Engagement score (0-100)
    """
    score = 0.0

    # Message count factor (more messages = higher engagement)
    msg_count = len(messages)
    score += min(msg_count * 2, 30)  # Cap at 30 points

    # Time wasted factor
    time_wasted = session.get("total_time_wasted_seconds", 0)
    score += min(time_wasted / 60, 30)  # 1 point per minute, cap at 30

    # Back-and-forth factor (alternating messages)
    alternations = 0
    prev_dir = None
    for msg in messages:
        curr_dir = msg.get("direction")
        if prev_dir and curr_dir != prev_dir:
            alternations += 1
        prev_dir = curr_dir
    score += min(alternations * 2, 20)  # Cap at 20 points

    # Scammer persistence factor (inbound messages)
    inbound_count = sum(1 for m in messages if m.get("direction") == "inbound")
    score += min(inbound_count * 2, 20)  # Cap at 20 points

    return min(score, 100)
