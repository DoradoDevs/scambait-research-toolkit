"""
Scambait Research Suite - Dashboard Routes

Additional route handlers for the dashboard.
Main routes are in core/app.py - this provides helpers.
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

import config

# Templates directory
templates = Jinja2Templates(directory=config.BASE_DIR / "dashboard" / "templates")

# Create router for any additional dashboard routes
dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@dashboard_router.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    """Help and documentation page."""
    return templates.TemplateResponse("help.html", {
        "request": request,
        "active_page": "help"
    })


@dashboard_router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "active_page": "settings",
        "config": {
            "host": config.HOST,
            "port": config.PORT,
            "audit_logging": config.AUDIT_LOGGING_ENABLED,
            "max_upload_size": config.MAX_UPLOAD_SIZE_BYTES,
            "allowed_extensions": config.ALLOWED_UPLOAD_EXTENSIONS
        }
    })


def get_template_context(request: Request, **kwargs):
    """
    Build common template context.

    Args:
        request: FastAPI request
        **kwargs: Additional context variables

    Returns:
        Dictionary with template context
    """
    return {
        "request": request,
        "config": {
            "version": config.RESEARCH_METADATA["version"],
            "tool_name": config.RESEARCH_METADATA["tool_name"]
        },
        **kwargs
    }
