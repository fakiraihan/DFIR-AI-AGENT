"""Health and root endpoints."""

from datetime import datetime

from fastapi import APIRouter


router = APIRouter()


@router.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "AI Agent DFIR",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    }
