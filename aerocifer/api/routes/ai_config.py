"""
AI & Zero-Touch Configuration Routes
"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from aerocifer.ai.gemma_engine import GemmaConfigEngine

router = APIRouter()

class AIPromptRequest(BaseModel):
    prompt: str

@router.post("/prompt")
async def execute_ai_prompt(request: Request, body: AIPromptRequest):
    """
    Execute a natural language prompt to immediately configure the firewall.
    e.g. "Create a zone for basic devices and securely assign 10.0.0.8"
    """
    ngfw = request.app.state.ngfw
    
    if not ngfw.zone_manager or not ngfw.rule_engine:
        raise HTTPException(status_code=503, detail="Firewall core engines are offline")

    gemma_cfg = getattr(getattr(ngfw, "config", None), "gemma", None)
    engine = GemmaConfigEngine(
        zone_manager=ngfw.zone_manager,
        rule_engine=ngfw.rule_engine,
        db=getattr(ngfw, "db", None),
        model_name=getattr(gemma_cfg, "model_name", "gemma4:latest"),
        ollama_host=getattr(gemma_cfg, "ollama_host", "http://localhost:11434"),
        temperature=getattr(gemma_cfg, "temperature", 0.1),
        max_tokens=getattr(gemma_cfg, "max_tokens", 1024),
    )
    
    result = await engine.execute_prompt(body.prompt)
    return {
        "success": result.success,
        "message": result.message,
        "action_taken": result.action_taken,
        "details": result.details
    }
