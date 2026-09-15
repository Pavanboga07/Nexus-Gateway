"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Basic health check for monitoring and load balancers."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": "nexus-gateway",
        "version": "0.1.0",
        "port": settings.port,
    }


__all__ = ["router"]
