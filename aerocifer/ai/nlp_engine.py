"""
AEROCIFER NGFW — AI NLP Engine

Processes natural language user prompts and translates them into actionable
firewall configurations using the ZoneManager and RuleEngine.
"""

import re
import shlex
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from aerocifer.utils.logger import get_logger
from aerocifer.core.zone_manager import ZoneManager
from aerocifer.core.rule_engine import RuleEngine

log = get_logger("ai")

@dataclass
class NLPCommandResult:
    """Result of processing an NLP command."""
    success: bool
    message: str
    action_taken: str
    details: Dict[str, Any]


class NLPCommandEngine:
    """
    Lightweight, pattern-based NLP engine for zero-touch configuration.
    
    Tries to infer intent (Action, Target, Subject) from human-readable text.
    For production, this would be backed by an LLM like GPT-4, but this is 
    a highly efficient local intent-matcher.
    """
    def __init__(self, zone_manager: ZoneManager, rule_engine: RuleEngine):
        self.zm = zone_manager
        self.re = rule_engine

        # Regex patterns for intent matching
        self.zone_cmd_pat = re.compile(
            r"(?i)\b(?:create|make|add|setup)\s+(?:a\s+)?(?:zone|network)\s+(?:for\s+)?([a-z0-9_-]+)",
        )
        self.device_cmd_pat = re.compile(
            r"(?i)\b(?:add|assign|put|move)\s+(?:a\s+)?(?:device\s+)?(?:with\s+)?(?:ip\s+)?([0-9\.]+)(?:\s+to\s+(?:zone\s+)?([a-z0-9_-]+))?",
        )
        self.block_cmd_pat = re.compile(
            r"(?i)\b(?:block|deny|stop)\s+(?:\bip\b|\btraffic\s+from\b)?\s*([0-9\.]+)",
        )

    async def execute_prompt(self, prompt: str) -> NLPCommandResult:
        """
        Parses a prompt and performs the underlying operations.
        Example: "Create an IoT zone and assign device 192.168.1.50 to it"
        """
        log.info(f"AI Engine processing prompt: '{prompt}'")
        
        # We can handle compound sentences by splitting them crudely by "and"
        sub_prompts = [p.strip() for p in re.split(r'\band\b', prompt, flags=re.IGNORECASE)]
        
        results = []
        for p in sub_prompts:
            res = await self._parse_sub_prompt(p)
            if res:
                results.append(res)
                
        if not results:
            return NLPCommandResult(
                success=False,
                message="I couldn't understand the command. Try 'Create a zone named iot' or 'Block IP 10.0.0.5'",
                action_taken="failed",
                details={}
            )
            
        successes = [r for r in results if r.success]
        msgs = [r.message for r in successes]
        
        if len(successes) == 1:
            return successes[0]
        elif len(successes) > 1:
            return NLPCommandResult(
                success=True,
                message=" | ".join(msgs),
                action_taken="multiple",
                details={"commands_executed": len(successes)}
            )
        else:
            return results[0]

    async def _parse_sub_prompt(self, p: str) -> Optional[NLPCommandResult]:
        """Parses a single clause."""
        # Check for ZONE creation
        zone_match = self.zone_cmd_pat.search(p)
        if zone_match:
            zone_name = zone_match.group(1).lower().replace(" ", "_").strip()
            # Default to some standard values for NLP created zones
            if "iot" in zone_name:
                desc = "AI-Generated IoT Network"
            elif "basic" in zone_name or "guest" in zone_name:
                desc = "AI-Generated Basic Devices Network"
            else:
                desc = "AI-Generated Custom Zone"
                
            zone_obj = await self.zm.create_zone(name=zone_name, description=desc)
            return NLPCommandResult(
                success=True,
                message=f"Created zone '{zone_name}' (ID: {zone_obj.id[:8]})",
                action_taken="create_zone",
                details={"zone": zone_name, "id": zone_obj.id}
            )

        # Check for DEVICE assignment
        dev_match = self.device_cmd_pat.search(p)
        if dev_match:
            ip = dev_match.group(1)
            zone_name = dev_match.group(2)
            if zone_name:
                zone_name = zone_name.lower().replace(" ", "_").strip()
                # Find zone ID
                target_zone_id = None
                for z_id, z_data in self.zm._zones.items():
                    if z_data.name == zone_name:
                        target_zone_id = z_id
                        break
                        
                if target_zone_id:
                    await self.zm.assign_device(ip, target_zone_id)
                    return NLPCommandResult(
                        success=True,
                        message=f"Assigned {ip} to zone '{zone_name}'",
                        action_taken="assign_device",
                        details={"ip": ip, "zone": zone_name}
                    )
                else:
                    return NLPCommandResult(
                        success=False,
                        message=f"Could not find zone '{zone_name}' to assign device",
                        action_taken="error",
                        details={"ip": ip, "zone_not_found": zone_name}
                    )
            else:
                return NLPCommandResult(
                    success=False,
                    message=f"I see you want to add device {ip}, but you didn't specify which zone (e.g. 'to zone iot')",
                    action_taken="error",
                    details={"ip": ip, "error": "missing_zone"}
                )

        # Check for BLOCK rule
        block_match = self.block_cmd_pat.search(p)
        if block_match:
            ip = block_match.group(1)
            await self.re.block_ip(ip, reason="AI Prompt Request", duration=3600)
            return NLPCommandResult(
                success=True,
                message=f"Blocked traffic from {ip} for 1 hour",
                action_taken="block_ip",
                details={"ip": ip}
            )
            
        return None
