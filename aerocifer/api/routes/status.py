"""
Status & Metrics Routes
"""
from fastapi import APIRouter, Request

router = APIRouter()

@router.get("/")
async def get_status(request: Request):
    """Get overall firewall status & health metrics."""
    ngfw = request.app.state.ngfw
    return await ngfw.get_status()

@router.get("/flows")
async def get_active_flows(request: Request):
    """Retrieve active network flows tracked by the SessionTracker."""
    ngfw = request.app.state.ngfw
    if ngfw.session_tracker:
        stats = ngfw.session_tracker.get_stats()
        # You could also pull the top 100 actual flows here, simplified for now
        return {"session_tracker_stats": stats, "flows": []}
    return {"error": "SessionTracker offline"}
