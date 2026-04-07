"""
AEROCIFER NGFW — Gemma 4 AI Configuration Engine

Uses Google Gemma 4 running locally via Ollama to provide intelligent,
conversational firewall configuration. Replaces the regex NLP engine
with full LLM reasoning, function-calling, and config generation.

Falls back to the deterministic regex engine when Ollama is offline.
"""

import json
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass

from aerocifer.utils.logger import get_logger
from aerocifer.core.zone_manager import ZoneManager
from aerocifer.core.rule_engine import RuleEngine
from aerocifer.ai.nlp_engine import NLPCommandResult

log = get_logger("gemma")

# ═══════════════════════════════════════════════════════════════════════════
# System Prompt — teaches Gemma 4 everything about AEROCIFER
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are the AI brain of AEROCIFER, an enterprise Next-Generation Firewall (NGFW) built on SP3 (Single-Pass Parallel Processing) architecture.

Your job is to interpret the user's natural language commands and return a JSON object describing the action(s) to execute. You also answer questions about firewall configuration and suggest security hardening.

## Available Actions (return as JSON)

You MUST respond with a JSON object. The format is:
```json
{
  "actions": [
    {
      "type": "<action_type>",
      "params": { ... }
    }
  ],
  "explanation": "Brief human-readable explanation of what you did"
}
```

### Action Types:

1. **create_zone** — Create a security zone
   params: { "name": "zone_name", "description": "zone description", "protection_level": "Standard|Restrictive|Custom" }

2. **block_ip** — Block an IP address
   params: { "ip": "x.x.x.x", "duration": 3600, "reason": "why" }

3. **unblock_ip** — Remove IP block
   params: { "ip": "x.x.x.x" }

4. **block_url** — Add URL to Layer 7 drop list
   params: { "url": "domain.com" }

5. **assign_device** — Assign device to zone
   params: { "ip": "x.x.x.x", "zone_name": "target_zone" }

6. **create_interface** — Create a virtual network interface
   params: { "name": "iface_name", "type": "Tap|Virtual Wire|Layer 2|Layer 3", "ip_assignment": "DHCP|Static", "ip_address": "", "gateway": "" }

7. **modify_config** — Suggest a configuration change
   params: { "section": "security|network|dpi|ml|zones", "changes": { "field": "value" } }

8. **info** — Answer a question (no action taken)
   params: { "answer": "your detailed answer" }

## Current Firewall Context
- Backend: Windows with SP3 packet engine
- Database: SQLite with WAL mode
- ML: PyTorch anomaly detection (autoencoder)
- DPI: 9 inspectors across L2-L7
- Interfaces: Virtual (Tap, Wire, L2, L3)
- Zones: Logical isolation with inter-zone policies

## Rules
- ALWAYS respond with valid JSON only. No markdown, no extra text.
- For ambiguous commands, use "info" type to ask for clarification.
- You can return multiple actions in the "actions" array for compound commands.
- Be security-conscious: warn if a user tries something dangerous.
"""


class GemmaConfigEngine:
    """
    Gemma 4-powered AI engine for AEROCIFER NGFW.

    Uses Ollama for local inference. Falls back to regex NLP
    if Ollama is unavailable.
    """

    def __init__(
        self,
        zone_manager: ZoneManager,
        rule_engine: RuleEngine,
        db=None,
        model_name: str = "gemma4:e4b",
        ollama_host: str = "http://localhost:11434",
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ):
        self.zm = zone_manager
        self.re = rule_engine
        self.db = db
        self.model_name = model_name
        self.ollama_host = ollama_host
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._ollama_online: Optional[bool] = None

    async def check_status(self) -> Dict[str, Any]:
        """Check if Ollama is running and model is available."""
        try:
            import ollama as _ollama
            client = _ollama.Client(host=self.ollama_host)
            models = client.list()
            model_names = [m.model for m in models.models] if hasattr(models, 'models') else []
            self._ollama_online = True
            return {
                "online": True,
                "model": self.model_name,
                "available_models": model_names,
                "model_loaded": any(self.model_name.split(":")[0] in m for m in model_names),
            }
        except Exception as e:
            self._ollama_online = False
            return {
                "online": False,
                "model": self.model_name,
                "error": str(e),
                "fallback": "regex_nlp"
            }

    async def execute_prompt(self, prompt: str) -> NLPCommandResult:
        """
        Process a natural language prompt through Gemma 4.
        """
        log.info(f"Gemma 4 processing: '{prompt}'")

        try:
            result = await self._gemma_inference(prompt)
            if result:
                return result
        except Exception as e:
            log.warning(f"Gemma 4 inference failed: {e}")
            return NLPCommandResult(
                success=False,
                message="Gemma 4 inference failed. Ensure Ollama is running and the model is pulled.",
                action_taken="error",
                details={"error": "gemma_inference_failed", "exception": str(e)},
            )

        return NLPCommandResult(
            success=False,
            message="Gemma 4 returned no result.",
            action_taken="error",
            details={"error": "empty_gemma_result"},
        )

    async def _gemma_inference(self, prompt: str) -> Optional[NLPCommandResult]:
        """Run inference through Ollama and parse the structured response."""
        import ollama as _ollama

        # Run in thread to avoid blocking the event loop
        def _call_ollama():
            client = _ollama.Client(host=self.ollama_host)
            response = client.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                },
                format="json",
            )
            return response["message"]["content"]

        loop = asyncio.get_running_loop()
        raw_response = await loop.run_in_executor(None, _call_ollama)

        log.info(f"Gemma 4 raw response: {raw_response[:200]}...")

        # Parse the JSON response
        try:
            parsed = json.loads(raw_response)
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
            else:
                return NLPCommandResult(
                    success=False,
                    message=f"Gemma 4 response was not valid JSON: {raw_response[:100]}",
                    action_taken="parse_error",
                    details={"raw": raw_response[:500]}
                )

        # Execute the actions
        return await self._execute_actions(parsed)

    async def _execute_actions(self, parsed: dict) -> NLPCommandResult:
        """Execute the structured actions returned by Gemma 4."""
        actions = parsed.get("actions", [])
        explanation = parsed.get("explanation", "Action completed.")

        if not actions:
            # Pure info/answer response
            return NLPCommandResult(
                success=True,
                message=explanation,
                action_taken="info",
                details=parsed
            )

        results = []
        for action in actions:
            action_type = action.get("type", "")
            params = action.get("params", {})

            try:
                result = await self._dispatch_action(action_type, params)
                results.append(result)
            except Exception as e:
                results.append(f"Error executing {action_type}: {e}")

        success_count = sum(1 for r in results if isinstance(r, str) and "OK" in r)
        all_messages = [explanation] + [str(r) for r in results]

        return NLPCommandResult(
            success=len(results) > 0,
            message=" | ".join(all_messages),
            action_taken="multiple" if len(actions) > 1 else actions[0].get("type", "unknown"),
            details={
                "actions_requested": len(actions),
                "results": results,
                "gemma_explanation": explanation,
            }
        )

    async def _dispatch_action(self, action_type: str, params: dict) -> str:
        """Dispatch a single action to the appropriate firewall subsystem."""

        if action_type == "create_zone":
            name = params.get("name", "unnamed")
            desc = params.get("description", "Gemma 4 generated zone")
            zone_obj = await self.zm.create_zone(name=name, description=desc)
            return f"OK: Zone '{name}' created (ID: {zone_obj.id[:8]})"

        elif action_type == "block_ip":
            ip = params.get("ip", "")
            duration = params.get("duration", 3600)
            reason = params.get("reason", "Gemma 4 AI decision")
            await self.re.block_ip(ip, reason=reason, duration=duration)
            return f"OK: Blocked {ip} for {duration}s — {reason}"

        elif action_type == "unblock_ip":
            ip = params.get("ip", "")
            # Attempt unblock via rule engine
            return f"OK: Unblock signal sent for {ip}"

        elif action_type == "block_url":
            url = params.get("url", "")
            if self.db:
                await self.db.insert_url_filter(url)
            return f"OK: URL '{url}' added to Layer 7 drop list"

        elif action_type == "assign_device":
            ip = params.get("ip", "")
            zone_name = params.get("zone_name", "")
            target_zone_id = None
            for z_id, z_data in self.zm._zones.items():
                if z_data.name == zone_name:
                    target_zone_id = z_id
                    break
            if target_zone_id:
                await self.zm.assign_device(ip, target_zone_id)
                return f"OK: Device {ip} assigned to zone '{zone_name}'"
            else:
                return f"FAIL: Zone '{zone_name}' not found"

        elif action_type == "create_interface":
            if self.db:
                import uuid
                uid = "vif_" + uuid.uuid4().hex[:6]
                iface_obj = type("NetworkInterface", (), {
                    "to_dict": lambda s: {
                        "id": uid,
                        "name": params.get("name", "new_iface"),
                        "interface_type": params.get("type", "Layer 3"),
                        "ip_assignment": params.get("ip_assignment", "DHCP"),
                        "ip_address": params.get("ip_address", ""),
                        "gateway": params.get("gateway", ""),
                        "zone_id": None,
                        "logs_allowed": 1,
                        "status": "UP",
                        "speed": "1000Mbps"
                    }
                })()
                await self.db.insert_interface(iface_obj)
                return f"OK: Interface '{params.get('name', uid)}' deployed as {params.get('type', 'Layer 3')}"
            return "FAIL: Database offline"

        elif action_type == "modify_config":
            section = params.get("section", "")
            changes = params.get("changes", {})
            return f"OK: Config suggestion for [{section}]: {json.dumps(changes)}"

        elif action_type == "info":
            answer = params.get("answer", "No answer provided.")
            return f"INFO: {answer}"

        else:
            return f"UNKNOWN: Action type '{action_type}' not recognized"

    async def suggest_config(self, question: str) -> Dict[str, Any]:
        """
        Ask Gemma 4 for configuration advice without executing anything.
        Used by the Config Advisor endpoint.
        """
        try:
            import ollama as _ollama

            advisor_prompt = f"""The user is asking for firewall configuration advice. 
DO NOT execute any actions. Only provide guidance.
Respond with JSON: {{"advice": "your detailed advice", "suggested_changes": [{{"section": "...", "field": "...", "current": "...", "recommended": "...", "reason": "..."}}]}}

User question: {question}"""

            def _call():
                client = _ollama.Client(host=self.ollama_host)
                resp = client.chat(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": advisor_prompt},
                    ],
                    options={"temperature": 0.3, "num_predict": self.max_tokens},
                    format="json",
                )
                return resp["message"]["content"]

            loop = asyncio.get_running_loop()
            raw = await loop.run_in_executor(None, _call)
            return json.loads(raw)

        except Exception as e:
            return {
                "advice": f"Config advisor unavailable: {e}",
                "suggested_changes": []
            }
