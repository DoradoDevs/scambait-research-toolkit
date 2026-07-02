"""
Scambait Research Suite - Entry Point

Run this file to start the research panel.

Usage:
    python run.py

The dashboard will be available at http://localhost:8000
"""

import uvicorn
import config


def main():
    """Start the Scambait Research Suite."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           SCAMBAIT RESEARCH SUITE v1.0.0                      ║
    ║                                                               ║
    ║   Local scam-interaction research panel                       ║
    ║   For authorized security research only                       ║
    ║                                                               ║
    ║   Dashboard: http://localhost:8000                            ║
    ║   API Docs:  http://localhost:8000/api/docs                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    # Safety notice
    print("SAFETY CONTROLS ACTIVE:")
    print(f"  - Binding to: {config.HOST}:{config.PORT}")
    print(f"  - Outbound blocked: {config.OUTBOUND_BLOCKED}")
    print(f"  - Audit logging: {config.AUDIT_LOGGING_ENABLED}")
    print(f"  - Data directory: {config.DATA_DIR}")
    print()

    uvicorn.run(
        "core.app:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,  # Disable reload for security
        access_log=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
