"""
Security & Rules Management Routes
"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Block via API"
    duration: int = 3600

@router.post("/block")
async def manual_block_ip(request: Request, body: BlockIPRequest):
    """Manually add an IP to the active blocklist."""
    ngfw = request.app.state.ngfw
    if not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Rule Engine Offline")
        
    await ngfw.rule_engine.block_ip(ip=body.ip, reason=body.reason, duration=body.duration)
    return {"status": "success", "blocked_ip": body.ip, "duration": body.duration}

@router.get("/rules")
async def list_active_rules(request: Request):
    """List current active firewall rules and blocks."""
    ngfw = request.app.state.ngfw
    if not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Rule Engine Offline")
    
    rules = []
    # Peek straight into the in-memory fast matching cache
    for r in ngfw.rule_engine._cache._rules:
        rules.append({
            "id": r.rule_id,
            "action": r.action.value if hasattr(r.action, 'value') else str(r.action),
            "src_ip": r.src_ip or "ANY",
            "dst_ip": r.dst_ip or "ANY",
            "protocol": r.protocol,
            "expires_at": r.expires_at,
        })
        
    return {"status": "success", "rules": rules}
    
@router.delete("/rules/{rule_id}")
async def unblock_rule(request: Request, rule_id: str):
    """Unblock a specific rule by ID directly from the UI."""
    ngfw = request.app.state.ngfw
    if not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Rule Engine Offline")
        
    await ngfw.rule_engine.remove_rule(rule_id=rule_id)
    return {"status": "success", "message": f"Rule {rule_id} removed natively."}
