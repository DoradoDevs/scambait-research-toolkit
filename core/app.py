"""
Scambait Research Suite - FastAPI Application

Main application entry point with all routes and middleware.
Designed for local-only operation.
"""

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import config
from core.database import (
    init_db, SessionDB, MessageDB, AttachmentDB,
    AuditDB, PatternFlagDB, ScriptDB, get_db_context
)
from core.models import (
    SessionCreate, SessionUpdate, SessionResponse, SessionWithMessages,
    MessageCreate, MessageResponse, AttachmentResponse,
    PatternFlagCreate, PatternFlagResponse, PatternDetectionResult,
    ScriptResponse, SuggestedResponse, DashboardStats,
    WalletDisplay, WalletInteraction, SessionReport, AuditLogEntry
)
from core.safety import (
    AuditLogger, DataSafety, VMResetManager,
    ComplianceReporter, validate_request_safety
)


# =============================================================================
# Application Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    # Startup
    await init_db()
    await AuditLogger.log("system.startup", {"version": config.RESEARCH_METADATA["version"]})
    print(f"Scambait Research Suite started on http://{config.HOST}:{config.PORT}")

    yield

    # Shutdown
    await AuditLogger.log("system.shutdown")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Scambait Research Suite",
    description="Local scam-interaction research panel for security research",
    version=config.RESEARCH_METADATA["version"],
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# CORS (local only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory=config.BASE_DIR / "dashboard" / "static"), name="static")
templates = Jinja2Templates(directory=config.BASE_DIR / "dashboard" / "templates")


# =============================================================================
# Security Middleware
# =============================================================================

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Validate requests and log for audit."""
    # Validate request safety
    if not await validate_request_safety(request):
        return JSONResponse(
            status_code=403,
            content={"error": "Request blocked by security policy"}
        )

    response = await call_next(request)
    return response


# =============================================================================
# Dashboard Routes (HTML)
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page."""
    await AuditLogger.log("dashboard.view", {"page": "home"})
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/session/{session_id}", response_class=HTMLResponse)
async def session_detail(request: Request, session_id: str):
    """Session detail page."""
    await AuditLogger.log("dashboard.view", {"page": "session", "session_id": session_id})
    return templates.TemplateResponse("session.html", {
        "request": request,
        "session_id": session_id
    })


@app.get("/analysis", response_class=HTMLResponse)
async def analysis_page(request: Request):
    """File analysis page."""
    await AuditLogger.log("dashboard.view", {"page": "analysis"})
    return templates.TemplateResponse("analysis.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Reports page."""
    await AuditLogger.log("dashboard.view", {"page": "reports"})
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/wallet", response_class=HTMLResponse)
async def wallet_honeypot_page(request: Request):
    """Wallet honeypot display page."""
    await AuditLogger.log("wallet.view", {"ip": request.client.host})
    return templates.TemplateResponse(
        "wallet_display.html",
        {"request": request, "wallet": config.HONEYPOT_WALLET}
    )


# =============================================================================
# Session API Routes
# =============================================================================

@app.post("/api/sessions", response_model=SessionResponse)
async def create_session(session: SessionCreate):
    """Create a new research session."""
    session_id = str(uuid.uuid4())

    result = await SessionDB.create(
        session_id=session_id,
        scam_type=session.scam_type.value if session.scam_type else None,
        source=session.source,
        title=session.title,
        script_id=session.script_id,
        notes=session.notes
    )

    await AuditLogger.log_session_action(session_id, "created", {
        "scam_type": session.scam_type.value if session.scam_type else None
    })

    return SessionResponse(**result)


@app.get("/api/sessions", response_model=List[SessionResponse])
async def list_sessions(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """List all sessions."""
    sessions = await SessionDB.list_all(status=status, limit=limit, offset=offset)
    return [SessionResponse(**s) for s in sessions]


@app.get("/api/sessions/{session_id}", response_model=SessionWithMessages)
async def get_session(session_id: str):
    """Get session with all related data."""
    session = await SessionDB.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    messages = await MessageDB.get_by_session(session_id)
    attachments = await AttachmentDB.get_by_session(session_id)
    patterns = await PatternFlagDB.get_by_session(session_id)

    return SessionWithMessages(
        **session,
        messages=[MessageResponse(**m) for m in messages],
        attachments=[AttachmentResponse(**a) for a in attachments],
        pattern_flags=[PatternFlagResponse(**p) for p in patterns]
    )


@app.patch("/api/sessions/{session_id}", response_model=SessionResponse)
async def update_session(session_id: str, update: SessionUpdate):
    """Update session."""
    update_data = update.model_dump(exclude_unset=True)
    if "scam_type" in update_data and update_data["scam_type"]:
        update_data["scam_type"] = update_data["scam_type"].value
    if "status" in update_data and update_data["status"]:
        update_data["status"] = update_data["status"].value

    result = await SessionDB.update(session_id, **update_data)
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")

    await AuditLogger.log_session_action(session_id, "updated", update_data)
    return SessionResponse(**result)


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete session and all related data."""
    await SessionDB.delete(session_id)
    await AuditLogger.log_session_action(session_id, "deleted")
    return {"status": "deleted", "session_id": session_id}


# =============================================================================
# Message API Routes
# =============================================================================

@app.post("/api/messages", response_model=MessageResponse)
async def create_message(message: MessageCreate):
    """Create a new message in a session."""
    from modules.scripts.engine import get_delay_for_message
    from modules.scripts.delays import calculate_delay
    from modules.metadata.collector import detect_patterns

    message_id = str(uuid.uuid4())

    # Calculate delay if requested
    delay = 0
    if message.apply_delay:
        delay = calculate_delay("random")
        await SessionDB.add_time_wasted(message.session_id, delay)

    result = await MessageDB.create(
        message_id=message_id,
        session_id=message.session_id,
        direction=message.direction.value,
        content=message.content,
        content_type=message.content_type,
        metadata=message.metadata,
        delay_applied_seconds=delay
    )

    await AuditLogger.log_message_action(
        message.session_id,
        message_id,
        message.direction.value
    )

    # Auto-detect scam patterns in inbound messages
    if message.direction.value == "inbound":
        patterns = detect_patterns(message.content)
        for pattern in patterns.get("patterns_found", []):
            flag_id = str(uuid.uuid4())
            await PatternFlagDB.create(
                flag_id=flag_id,
                session_id=message.session_id,
                message_id=message_id,
                pattern_type=pattern["type"],
                confidence=pattern["confidence"],
                evidence=pattern["evidence"]
            )

    return MessageResponse(**result)


@app.get("/api/sessions/{session_id}/messages", response_model=List[MessageResponse])
async def get_session_messages(session_id: str):
    """Get all messages for a session."""
    messages = await MessageDB.get_by_session(session_id)
    return [MessageResponse(**m) for m in messages]


# =============================================================================
# Script/Response Suggestion API
# =============================================================================

@app.get("/api/scripts", response_model=List[ScriptResponse])
async def list_scripts():
    """List available baiting scripts."""
    scripts = await ScriptDB.get_all()
    return [ScriptResponse(**s) for s in scripts]


@app.get("/api/scripts/{script_id}", response_model=ScriptResponse)
async def get_script(script_id: str):
    """Get script by ID."""
    script = await ScriptDB.get(script_id)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    return ScriptResponse(**script)


@app.post("/api/suggest-response", response_model=SuggestedResponse)
async def suggest_response(
    session_id: str,
    context: str = "",
    script_id: Optional[str] = None
):
    """Get suggested response based on context and script."""
    from modules.scripts.engine import get_suggested_response

    suggestion = await get_suggested_response(
        session_id=session_id,
        context=context,
        script_id=script_id
    )

    return suggestion


# =============================================================================
# File Upload & Analysis API
# =============================================================================

@app.post("/api/upload", response_model=AttachmentResponse)
async def upload_file(
    file: UploadFile = File(...),
    session_id: str = Form(...)
):
    """Upload and analyze a file."""
    from modules.analyzer.hasher import hash_file
    from modules.analyzer.static_analysis import analyze_file

    # Validate file
    if not DataSafety.validate_file_extension(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed")

    # Generate safe storage name
    stored_filename = DataSafety.generate_safe_storage_name(file.filename)
    storage_path = config.UPLOAD_DIR / session_id
    storage_path.mkdir(parents=True, exist_ok=True)
    file_path = storage_path / stored_filename

    # Save file
    content = await file.read()
    if len(content) > config.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="File too large")

    with open(file_path, "wb") as f:
        f.write(content)

    # Hash and analyze
    hashes = hash_file(file_path)
    analysis = analyze_file(file_path)

    # Create attachment record
    attachment_id = str(uuid.uuid4())
    result = await AttachmentDB.create(
        attachment_id=attachment_id,
        session_id=session_id,
        original_filename=file.filename,
        stored_filename=stored_filename,
        file_size=len(content),
        mime_type=analysis.mime_type,
        md5_hash=hashes.md5,
        sha256_hash=hashes.sha256,
        sha1_hash=hashes.sha1,
        analysis_result=analysis.model_dump(),
        is_malicious=analysis.is_suspicious
    )

    await AuditLogger.log_file_action("uploaded", file.filename, session_id)

    return AttachmentResponse(**result)


@app.get("/api/sessions/{session_id}/attachments", response_model=List[AttachmentResponse])
async def get_session_attachments(session_id: str):
    """Get all attachments for a session."""
    attachments = await AttachmentDB.get_by_session(session_id)
    return [AttachmentResponse(**a) for a in attachments]


@app.post("/api/analyze-url")
async def analyze_url(url: str):
    """Analyze a URL for suspicious patterns."""
    from modules.analyzer.link_analyzer import analyze_link

    result = analyze_link(url)
    await AuditLogger.log("link.analyzed", {"url": result.defanged_url})

    return result


# =============================================================================
# Pattern Detection API
# =============================================================================

@app.post("/api/detect-patterns", response_model=PatternDetectionResult)
async def detect_patterns_api(text: str):
    """Detect scam patterns in text."""
    from modules.metadata.collector import detect_patterns
    return detect_patterns(text)


@app.post("/api/patterns", response_model=PatternFlagResponse)
async def create_pattern_flag(flag: PatternFlagCreate):
    """Manually create a pattern flag."""
    flag_id = str(uuid.uuid4())

    result = await PatternFlagDB.create(
        flag_id=flag_id,
        session_id=flag.session_id,
        message_id=flag.message_id,
        pattern_type=flag.pattern_type.value,
        confidence=flag.confidence,
        evidence=flag.evidence
    )

    return PatternFlagResponse(**result)


# =============================================================================
# Wallet Honeypot API
# =============================================================================

@app.get("/api/wallet", response_model=WalletDisplay)
async def get_wallet_data(request: Request):
    """Get fake wallet data for display."""
    from modules.wallet.honeypot import get_wallet_display

    wallet_data = get_wallet_display()

    # Log the access
    await AuditLogger.log("wallet.api_access", {
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent")
    })

    return wallet_data


@app.post("/api/wallet/interaction")
async def log_wallet_interaction(
    request: Request,
    interaction: WalletInteraction
):
    """Log wallet interaction attempt."""
    from modules.wallet.honeypot import log_interaction

    await log_interaction(
        session_id=interaction.session_id,
        action=interaction.action,
        details=interaction.details,
        ip_address=request.client.host
    )

    return {"status": "logged"}


# =============================================================================
# Dashboard Stats API
# =============================================================================

@app.get("/api/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics."""
    async with get_db_context() as db:
        # Total sessions
        cursor = await db.execute("SELECT COUNT(*) as count FROM sessions")
        total = (await cursor.fetchone())["count"]

        # Active sessions
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE status = 'active'"
        )
        active = (await cursor.fetchone())["count"]

        # Completed sessions
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE status = 'completed'"
        )
        completed = (await cursor.fetchone())["count"]

        # Total messages
        cursor = await db.execute("SELECT COUNT(*) as count FROM messages")
        messages = (await cursor.fetchone())["count"]

        # Total time wasted
        cursor = await db.execute(
            "SELECT COALESCE(SUM(total_time_wasted_seconds), 0) as total FROM sessions"
        )
        time_wasted = (await cursor.fetchone())["total"]

        # Total attachments
        cursor = await db.execute("SELECT COUNT(*) as count FROM attachments")
        attachments = (await cursor.fetchone())["count"]

        # Malicious attachments
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM attachments WHERE is_malicious = TRUE"
        )
        malicious = (await cursor.fetchone())["count"]

        # Scam types breakdown
        cursor = await db.execute("""
            SELECT scam_type, COUNT(*) as count
            FROM sessions
            WHERE scam_type IS NOT NULL
            GROUP BY scam_type
        """)
        scam_types = {row["scam_type"]: row["count"] for row in await cursor.fetchall()}

        # Pattern types breakdown
        cursor = await db.execute("""
            SELECT pattern_type, COUNT(*) as count
            FROM pattern_flags
            GROUP BY pattern_type
        """)
        pattern_types = {row["pattern_type"]: row["count"] for row in await cursor.fetchall()}

    return DashboardStats(
        total_sessions=total,
        active_sessions=active,
        completed_sessions=completed,
        total_messages=messages,
        total_time_wasted_seconds=time_wasted,
        total_attachments=attachments,
        malicious_attachments=malicious,
        scam_types_breakdown=scam_types,
        pattern_types_breakdown=pattern_types
    )


# =============================================================================
# Export API
# =============================================================================

@app.get("/api/export/session/{session_id}")
async def export_session(session_id: str, format: str = "json"):
    """Export session data."""
    from modules.metadata.collector import generate_session_report

    session = await SessionDB.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    report = await generate_session_report(session_id)

    await AuditLogger.log_export("session", session_id)

    if format == "json":
        # Save to file
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"session_{session_id[:8]}_{timestamp}.json"
        filepath = config.EXPORT_DIR / filename

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return FileResponse(
            filepath,
            filename=filename,
            media_type="application/json"
        )

    return report


@app.get("/api/export/audit")
async def export_audit_log():
    """Export audit log for compliance."""
    filepath = await ComplianceReporter.export_audit_report()

    return FileResponse(
        filepath,
        filename=filepath.name,
        media_type="application/json"
    )


# =============================================================================
# Safety Control API
# =============================================================================

@app.post("/api/safety/prepare-snapshot")
async def prepare_snapshot():
    """Prepare system for VM snapshot."""
    return await VMResetManager.prepare_for_snapshot()


@app.post("/api/safety/full-wipe")
async def full_wipe():
    """Perform full data wipe."""
    return await VMResetManager.full_wipe()


@app.post("/api/safety/selective-wipe")
async def selective_wipe(session_ids: List[str]):
    """Wipe specific sessions."""
    return await VMResetManager.selective_wipe(session_ids)


@app.get("/api/audit-log", response_model=List[AuditLogEntry])
async def get_audit_log(limit: int = 100, offset: int = 0):
    """Get audit log entries."""
    logs = await AuditDB.get_logs(limit=limit, offset=offset)
    return [AuditLogEntry(**log) for log in logs]


# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": config.RESEARCH_METADATA["version"],
        "timestamp": datetime.utcnow().isoformat()
    }
