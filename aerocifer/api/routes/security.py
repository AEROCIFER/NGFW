"""
Security & Rules Management Routes
"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

from aerocifer.db.models import FirewallRule, RuleAction
from aerocifer.utils.validators import validate_protocol

router = APIRouter()

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Block via API"
    duration: int = 3600


class CreateRuleRequest(BaseModel):
    action: str
    direction: str = "inbound"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = "any"
    description: str = "Custom rule via UI"
    priority: int = 100
    enabled: bool = True
    expires_in: Optional[int] = None  # seconds; if provided, becomes temporary

@router.post("/block")
async def manual_block_ip(request: Request, body: BlockIPRequest):
    """Manually add an IP to the active blocklist."""
    ngfw = request.app.state.ngfw
    if not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Rule Engine Offline")
        
    await ngfw.rule_engine.block_ip(ip=body.ip, reason=body.reason, duration=body.duration)
    return {"status": "success", "blocked_ip": body.ip, "duration": body.duration}

@router.post("/rules")
async def create_custom_rule(request: Request, body: CreateRuleRequest):
    """Create a custom firewall rule (UI-driven)."""
    ngfw = request.app.state.ngfw
    if not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Rule Engine Offline")

    try:
        action = RuleAction(body.action.lower())
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid action: {body.action}")

    protocol = validate_protocol(body.protocol)

    expires_at = None
    if body.expires_in is not None:
        import time
        expires_at = time.time() + int(body.expires_in)

    rule = FirewallRule(
        action=action,
        direction=body.direction,
        src_ip=body.src_ip,
        dst_ip=body.dst_ip,
        src_port=str(body.src_port or ""),
        dst_port=str(body.dst_port or ""),
        protocol=protocol,
        description=body.description,
        priority=int(body.priority),
        enabled=bool(body.enabled),
        auto_generated=False,
        expires_at=expires_at,
    )

    await ngfw.rule_engine.add_rule(rule)
    return {"status": "success", "rule": rule.to_dict()}

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
