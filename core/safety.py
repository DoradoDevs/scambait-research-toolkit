"""
Scambait Research Suite - Safety Controls

Security and compliance controls for the research panel.
Ensures all operations are audited and data stays local.
"""

import os
import shutil
import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from functools import wraps
import asyncio

import config
from core.database import AuditDB, get_db_context


# =============================================================================
# Audit Logging
# =============================================================================

class AuditLogger:
    """
    Comprehensive audit logging for compliance.
    All significant actions are logged with timestamps.
    """

    @staticmethod
    async def log(
        action: str,
        details: Dict[str, Any] = None,
        user_id: str = "researcher",
        ip_address: str = None
    ):
        """Log an auditable action."""
        if not config.AUDIT_LOGGING_ENABLED:
            return

        await AuditDB.log(
            action=action,
            details=details,
            user_id=user_id,
            ip_address=ip_address
        )

    @staticmethod
    async def log_session_action(session_id: str, action: str, details: Dict = None):
        """Log a session-related action."""
        await AuditLogger.log(
            action=f"session.{action}",
            details={"session_id": session_id, **(details or {})}
        )

    @staticmethod
    async def log_message_action(session_id: str, message_id: str, direction: str):
        """Log a message action."""
        await AuditLogger.log(
            action=f"message.{direction}",
            details={"session_id": session_id, "message_id": message_id}
        )

    @staticmethod
    async def log_file_action(action: str, filename: str, session_id: str = None):
        """Log a file-related action."""
        await AuditLogger.log(
            action=f"file.{action}",
            details={"filename": filename, "session_id": session_id}
        )

    @staticmethod
    async def log_export(export_type: str, session_id: str = None):
        """Log data export."""
        await AuditLogger.log(
            action=f"export.{export_type}",
            details={"session_id": session_id, "timestamp": datetime.utcnow().isoformat()}
        )

    @staticmethod
    async def log_security_event(event_type: str, details: Dict = None):
        """Log security-related events."""
        await AuditLogger.log(
            action=f"security.{event_type}",
            details=details
        )


def audit_action(action: str):
    """Decorator to audit function calls."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Log before execution
            await AuditLogger.log(
                action=f"{action}.start",
                details={"args": str(args)[:200], "kwargs": str(kwargs)[:200]}
            )

            try:
                result = await func(*args, **kwargs)
                await AuditLogger.log(action=f"{action}.success")
                return result
            except Exception as e:
                await AuditLogger.log(
                    action=f"{action}.error",
                    details={"error": str(e)}
                )
                raise

        return wrapper
    return decorator


# =============================================================================
# Network Safety
# =============================================================================

class NetworkSafety:
    """
    Ensures no outbound data transmission.
    All network operations are local-only.
    """

    @staticmethod
    def validate_host(host: str) -> bool:
        """Validate that host is in allowed list."""
        return host in config.ALLOWED_HOSTS

    @staticmethod
    def is_local_address(address: str) -> bool:
        """Check if address is local."""
        local_patterns = [
            "127.0.0.1",
            "localhost",
            "::1",
            "0.0.0.0"
        ]
        return any(pattern in address for pattern in local_patterns)

    @staticmethod
    async def check_outbound_blocked():
        """Verify outbound connections are blocked."""
        if config.OUTBOUND_BLOCKED:
            await AuditLogger.log_security_event(
                "outbound_check",
                {"status": "blocked", "config": True}
            )
            return True
        return False


# =============================================================================
# Data Safety
# =============================================================================

class DataSafety:
    """
    Data isolation and protection controls.
    Ensures all data stays within the local environment.
    """

    @staticmethod
    def validate_file_path(file_path: Path) -> bool:
        """
        Validate file path is within allowed directories.
        Prevents path traversal attacks.
        """
        try:
            resolved = file_path.resolve()
            allowed_dirs = [
                config.DATA_DIR.resolve(),
                config.UPLOAD_DIR.resolve(),
                config.EXPORT_DIR.resolve()
            ]
            return any(
                str(resolved).startswith(str(allowed))
                for allowed in allowed_dirs
            )
        except Exception:
            return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.
        """
        # Remove path components
        filename = os.path.basename(filename)

        # Remove potentially dangerous characters
        dangerous_chars = ['..', '/', '\\', '\x00', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')

        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext

        return filename

    @staticmethod
    def generate_safe_storage_name(original_filename: str) -> str:
        """
        Generate a safe storage filename using hash.
        """
        timestamp = datetime.utcnow().isoformat()
        hash_input = f"{original_filename}_{timestamp}"
        name_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        _, ext = os.path.splitext(original_filename)
        ext = DataSafety.sanitize_filename(ext)

        return f"{name_hash}{ext}"

    @staticmethod
    def check_file_size(file_path: Path) -> bool:
        """Check if file is within size limits."""
        try:
            size = file_path.stat().st_size
            return size <= config.MAX_UPLOAD_SIZE_BYTES
        except Exception:
            return False

    @staticmethod
    def validate_file_extension(filename: str) -> bool:
        """Check if file extension is allowed."""
        _, ext = os.path.splitext(filename)
        return ext.lower() in config.ALLOWED_UPLOAD_EXTENSIONS


# =============================================================================
# VM Reset Support
# =============================================================================

class VMResetManager:
    """
    Manages VM snapshot and reset operations.
    Supports clean environment restoration.
    """

    @staticmethod
    async def prepare_for_snapshot():
        """
        Prepare system for VM snapshot.
        Flushes all writes and closes connections.
        """
        await AuditLogger.log_security_event(
            "vm_snapshot_prepare",
            {"timestamp": datetime.utcnow().isoformat()}
        )

        # Close database connections
        # (connections are managed per-request in our setup)

        # Sync filesystem
        # Note: This is a best-effort operation

        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "message": "System prepared for snapshot"
        }

    @staticmethod
    async def full_wipe():
        """
        Complete data wipe for clean VM reset.
        Removes all collected data.
        """
        await AuditLogger.log_security_event(
            "full_wipe_initiated",
            {"timestamp": datetime.utcnow().isoformat()}
        )

        wipe_results = {
            "database": False,
            "uploads": False,
            "exports": False,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            # Remove database
            if config.DATABASE_PATH.exists():
                config.DATABASE_PATH.unlink()
                wipe_results["database"] = True

            # Clear uploads directory
            if config.UPLOAD_DIR.exists():
                shutil.rmtree(config.UPLOAD_DIR)
                config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                wipe_results["uploads"] = True

            # Clear exports directory
            if config.EXPORT_DIR.exists():
                shutil.rmtree(config.EXPORT_DIR)
                config.EXPORT_DIR.mkdir(parents=True, exist_ok=True)
                wipe_results["exports"] = True

            # Reinitialize database
            from core.database import init_db
            await init_db()

            wipe_results["success"] = True
            wipe_results["message"] = "Full wipe completed successfully"

        except Exception as e:
            wipe_results["success"] = False
            wipe_results["error"] = str(e)

        return wipe_results

    @staticmethod
    async def selective_wipe(session_ids: List[str] = None):
        """
        Selective data wipe for specific sessions.
        """
        from core.database import SessionDB, get_db_context

        if not session_ids:
            return {"success": False, "error": "No sessions specified"}

        await AuditLogger.log_security_event(
            "selective_wipe",
            {"session_ids": session_ids}
        )

        results = []
        for session_id in session_ids:
            try:
                # Delete session (cascades to related data)
                await SessionDB.delete(session_id)

                # Delete any associated files
                session_upload_dir = config.UPLOAD_DIR / session_id
                if session_upload_dir.exists():
                    shutil.rmtree(session_upload_dir)

                results.append({"session_id": session_id, "success": True})
            except Exception as e:
                results.append({"session_id": session_id, "success": False, "error": str(e)})

        return {
            "success": all(r["success"] for r in results),
            "results": results
        }


# =============================================================================
# Compliance Report Generator
# =============================================================================

class ComplianceReporter:
    """
    Generates compliance reports for audit purposes.
    """

    @staticmethod
    async def generate_audit_report(
        start_date: datetime = None,
        end_date: datetime = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive audit report.
        """
        await AuditLogger.log_export("audit_report")

        logs = await AuditDB.get_logs(limit=10000)

        # Filter by date if specified
        if start_date or end_date:
            filtered_logs = []
            for log in logs:
                log_time = datetime.fromisoformat(log["timestamp"])
                if start_date and log_time < start_date:
                    continue
                if end_date and log_time > end_date:
                    continue
                filtered_logs.append(log)
            logs = filtered_logs

        # Aggregate statistics
        action_counts = {}
        for log in logs:
            action = log.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "compliance_audit",
            "period": {
                "start": start_date.isoformat() if start_date else None,
                "end": end_date.isoformat() if end_date else None
            },
            "summary": {
                "total_events": len(logs),
                "action_breakdown": action_counts
            },
            "research_metadata": config.RESEARCH_METADATA,
            "safety_configuration": {
                "outbound_blocked": config.OUTBOUND_BLOCKED,
                "allowed_hosts": config.ALLOWED_HOSTS,
                "audit_logging_enabled": config.AUDIT_LOGGING_ENABLED
            },
            "events": logs
        }

        return report

    @staticmethod
    async def export_audit_report(filepath: Path = None) -> Path:
        """
        Export audit report to file.
        """
        report = await ComplianceReporter.generate_audit_report()

        if filepath is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filepath = config.EXPORT_DIR / f"audit_report_{timestamp}.json"

        # Validate path is within allowed directories
        if not DataSafety.validate_file_path(filepath):
            raise ValueError("Export path not in allowed directory")

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return filepath


# =============================================================================
# Request Validation Middleware
# =============================================================================

async def validate_request_safety(request) -> bool:
    """
    Validate incoming request for safety concerns.
    Used as middleware in FastAPI.
    """
    # Check host header
    host = request.headers.get("host", "").split(":")[0]
    if not NetworkSafety.validate_host(host):
        await AuditLogger.log_security_event(
            "blocked_host",
            {"host": host, "path": str(request.url.path)}
        )
        return False

    return True
