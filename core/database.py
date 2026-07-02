"""
Scambait Research Suite - Database Module

SQLite database setup and connection management.
All data stored locally - no external connections.
"""

import aiosqlite
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

import config

# Database schema version for migrations
SCHEMA_VERSION = 1


async def get_db() -> aiosqlite.Connection:
    """Get async database connection."""
    db = await aiosqlite.connect(config.DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    return db


@asynccontextmanager
async def get_db_context():
    """Context manager for database connections."""
    db = await get_db()
    try:
        yield db
    finally:
        await db.close()


async def init_db():
    """Initialize database with schema."""
    async with get_db_context() as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()

        # Insert default scripts if not exist
        await _insert_default_scripts(db)
        await db.commit()

    print(f"Database initialized at: {config.DATABASE_PATH}")


async def _insert_default_scripts(db: aiosqlite.Connection):
    """Insert default baiting scripts."""
    from modules.scripts.engine import DEFAULT_SCRIPTS

    for script in DEFAULT_SCRIPTS:
        existing = await db.execute(
            "SELECT id FROM scripts WHERE id = ?",
            (script["id"],)
        )
        if not await existing.fetchone():
            await db.execute("""
                INSERT INTO scripts (id, name, description, persona, responses, delay_config)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                script["id"],
                script["name"],
                script["description"],
                script["persona"],
                json.dumps(script["responses"]),
                json.dumps(script["delay_config"])
            ))


SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Research sessions with scammers
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK(status IN ('active', 'paused', 'completed', 'archived')) DEFAULT 'active',
    scam_type TEXT,
    source TEXT,
    notes TEXT,
    script_id TEXT,
    total_time_wasted_seconds INTEGER DEFAULT 0,
    title TEXT,
    scammer_identifier TEXT
);

-- Indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_scam_type ON sessions(scam_type);

-- Individual messages/interactions
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    direction TEXT CHECK(direction IN ('inbound', 'outbound')),
    content TEXT,
    content_type TEXT DEFAULT 'text',
    metadata JSON,
    delay_applied_seconds INTEGER DEFAULT 0
);

-- Indexes for messages
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_direction ON messages(direction);

-- Captured metadata
CREATE TABLE IF NOT EXISTS metadata (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT,
    headers JSON,
    geo_data JSON,
    fingerprint TEXT,
    additional JSON
);

-- Indexes for metadata
CREATE INDEX IF NOT EXISTS idx_metadata_session ON metadata(session_id);
CREATE INDEX IF NOT EXISTS idx_metadata_ip ON metadata(ip_address);

-- Attachments and files
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    original_filename TEXT,
    stored_filename TEXT,
    file_size INTEGER,
    mime_type TEXT,
    md5_hash TEXT,
    sha256_hash TEXT,
    sha1_hash TEXT,
    analysis_result JSON,
    is_malicious BOOLEAN DEFAULT FALSE,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for attachments
CREATE INDEX IF NOT EXISTS idx_attachments_session ON attachments(session_id);
CREATE INDEX IF NOT EXISTS idx_attachments_hash ON attachments(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_attachments_malicious ON attachments(is_malicious);

-- Scam pattern flags
CREATE TABLE IF NOT EXISTS pattern_flags (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    pattern_type TEXT,
    confidence REAL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    evidence TEXT
);

-- Indexes for pattern flags
CREATE INDEX IF NOT EXISTS idx_patterns_session ON pattern_flags(session_id);
CREATE INDEX IF NOT EXISTS idx_patterns_type ON pattern_flags(pattern_type);

-- Audit log for compliance
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    details JSON,
    user_id TEXT DEFAULT 'researcher',
    ip_address TEXT
);

-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- Pre-written scripts
CREATE TABLE IF NOT EXISTS scripts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    persona TEXT,
    responses JSON,
    delay_config JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- URL/Link tracking
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    original_url TEXT,
    defanged_url TEXT,
    domain TEXT,
    analysis_result JSON,
    is_malicious BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for links
CREATE INDEX IF NOT EXISTS idx_links_session ON links(session_id);
CREATE INDEX IF NOT EXISTS idx_links_domain ON links(domain);

-- Wallet interaction logs (honeypot)
CREATE TABLE IF NOT EXISTS wallet_interactions (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT,
    details JSON,
    ip_address TEXT
);

-- Insert schema version
INSERT OR IGNORE INTO schema_version (version) VALUES (1);
"""


# =============================================================================
# CRUD Operations
# =============================================================================

class SessionDB:
    """Database operations for sessions."""

    @staticmethod
    async def create(
        session_id: str,
        scam_type: str = None,
        source: str = None,
        title: str = None,
        script_id: str = None,
        notes: str = None
    ) -> Dict[str, Any]:
        """Create a new session."""
        async with get_db_context() as db:
            await db.execute("""
                INSERT INTO sessions (id, scam_type, source, title, script_id, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, scam_type, source, title, script_id, notes))
            await db.commit()

            cursor = await db.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            )
            row = await cursor.fetchone()
            return dict(row)

    @staticmethod
    async def get(session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        async with get_db_context() as db:
            cursor = await db.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    async def list_all(
        status: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List sessions with optional filtering."""
        async with get_db_context() as db:
            if status:
                cursor = await db.execute("""
                    SELECT * FROM sessions
                    WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (status, limit, offset))
            else:
                cursor = await db.execute("""
                    SELECT * FROM sessions
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    @staticmethod
    async def update(session_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Update session fields."""
        if not kwargs:
            return await SessionDB.get(session_id)

        async with get_db_context() as db:
            fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
            values = list(kwargs.values()) + [datetime.utcnow(), session_id]

            await db.execute(f"""
                UPDATE sessions
                SET {fields}, updated_at = ?
                WHERE id = ?
            """, values)
            await db.commit()

            return await SessionDB.get(session_id)

    @staticmethod
    async def delete(session_id: str) -> bool:
        """Delete session and all related data."""
        async with get_db_context() as db:
            await db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            await db.commit()
            return True

    @staticmethod
    async def add_time_wasted(session_id: str, seconds: int):
        """Add to total time wasted counter."""
        async with get_db_context() as db:
            await db.execute("""
                UPDATE sessions
                SET total_time_wasted_seconds = total_time_wasted_seconds + ?,
                    updated_at = ?
                WHERE id = ?
            """, (seconds, datetime.utcnow(), session_id))
            await db.commit()


class MessageDB:
    """Database operations for messages."""

    @staticmethod
    async def create(
        message_id: str,
        session_id: str,
        direction: str,
        content: str,
        content_type: str = "text",
        metadata: dict = None,
        delay_applied_seconds: int = 0
    ) -> Dict[str, Any]:
        """Create a new message."""
        async with get_db_context() as db:
            await db.execute("""
                INSERT INTO messages
                (id, session_id, direction, content, content_type, metadata, delay_applied_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                message_id, session_id, direction, content, content_type,
                json.dumps(metadata) if metadata else None,
                delay_applied_seconds
            ))
            await db.commit()

            cursor = await db.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            )
            row = await cursor.fetchone()
            return dict(row)

    @staticmethod
    async def get_by_session(session_id: str) -> List[Dict[str, Any]]:
        """Get all messages for a session."""
        async with get_db_context() as db:
            cursor = await db.execute("""
                SELECT * FROM messages
                WHERE session_id = ?
                ORDER BY timestamp ASC
            """, (session_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


class AttachmentDB:
    """Database operations for attachments."""

    @staticmethod
    async def create(
        attachment_id: str,
        session_id: str,
        original_filename: str,
        stored_filename: str,
        file_size: int,
        mime_type: str,
        md5_hash: str,
        sha256_hash: str,
        sha1_hash: str,
        message_id: str = None,
        analysis_result: dict = None,
        is_malicious: bool = False
    ) -> Dict[str, Any]:
        """Create attachment record."""
        async with get_db_context() as db:
            await db.execute("""
                INSERT INTO attachments
                (id, session_id, message_id, original_filename, stored_filename,
                 file_size, mime_type, md5_hash, sha256_hash, sha1_hash,
                 analysis_result, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attachment_id, session_id, message_id, original_filename,
                stored_filename, file_size, mime_type, md5_hash, sha256_hash,
                sha1_hash, json.dumps(analysis_result) if analysis_result else None,
                is_malicious
            ))
            await db.commit()

            cursor = await db.execute(
                "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
            )
            row = await cursor.fetchone()
            return dict(row)

    @staticmethod
    async def get_by_session(session_id: str) -> List[Dict[str, Any]]:
        """Get all attachments for a session."""
        async with get_db_context() as db:
            cursor = await db.execute("""
                SELECT * FROM attachments
                WHERE session_id = ?
                ORDER BY uploaded_at ASC
            """, (session_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


class AuditDB:
    """Database operations for audit log."""

    @staticmethod
    async def log(
        action: str,
        details: dict = None,
        user_id: str = "researcher",
        ip_address: str = None
    ):
        """Log an audit event."""
        import uuid
        async with get_db_context() as db:
            await db.execute("""
                INSERT INTO audit_log (id, action, details, user_id, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                action,
                json.dumps(details) if details else None,
                user_id,
                ip_address
            ))
            await db.commit()

    @staticmethod
    async def get_logs(
        limit: int = 100,
        offset: int = 0,
        action_filter: str = None
    ) -> List[Dict[str, Any]]:
        """Get audit logs with optional filtering."""
        async with get_db_context() as db:
            if action_filter:
                cursor = await db.execute("""
                    SELECT * FROM audit_log
                    WHERE action LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """, (f"%{action_filter}%", limit, offset))
            else:
                cursor = await db.execute("""
                    SELECT * FROM audit_log
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


class PatternFlagDB:
    """Database operations for pattern flags."""

    @staticmethod
    async def create(
        flag_id: str,
        session_id: str,
        pattern_type: str,
        confidence: float,
        evidence: str,
        message_id: str = None
    ) -> Dict[str, Any]:
        """Create a pattern flag."""
        async with get_db_context() as db:
            await db.execute("""
                INSERT INTO pattern_flags
                (id, session_id, message_id, pattern_type, confidence, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (flag_id, session_id, message_id, pattern_type, confidence, evidence))
            await db.commit()

            cursor = await db.execute(
                "SELECT * FROM pattern_flags WHERE id = ?", (flag_id,)
            )
            row = await cursor.fetchone()
            return dict(row)

    @staticmethod
    async def get_by_session(session_id: str) -> List[Dict[str, Any]]:
        """Get all pattern flags for a session."""
        async with get_db_context() as db:
            cursor = await db.execute("""
                SELECT * FROM pattern_flags
                WHERE session_id = ?
                ORDER BY detected_at ASC
            """, (session_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


class ScriptDB:
    """Database operations for scripts."""

    @staticmethod
    async def get_all() -> List[Dict[str, Any]]:
        """Get all active scripts."""
        async with get_db_context() as db:
            cursor = await db.execute("""
                SELECT * FROM scripts
                WHERE is_active = TRUE
                ORDER BY name ASC
            """)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    @staticmethod
    async def get(script_id: str) -> Optional[Dict[str, Any]]:
        """Get script by ID."""
        async with get_db_context() as db:
            cursor = await db.execute(
                "SELECT * FROM scripts WHERE id = ?", (script_id,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None


# Initialize on import if running directly
if __name__ == "__main__":
    import asyncio
    asyncio.run(init_db())
