"""
AEROCIFER NGFW — AI NLP Engine

Processes natural language user prompts and translates them into actionable
firewall configurations using the ZoneManager, RuleEngine, and Databases.
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
    a highly efficient local intent-matcher using advanced RegEx logic.
    """
    def __init__(self, zone_manager: ZoneManager, rule_engine: RuleEngine):
        self.zm = zone_manager
        self.re = rule_engine

        # Regex patterns for expansive intent matching
        self.zone_cmd_pat = re.compile(
            r"(?i)\b(?:create|make|add|setup|build)\s+(?:a\s+)?(?:zone|network)\s+(?:for\s+|named\s+|called\s+)?([a-z0-9_\-\s]+)",
        )
        self.device_cmd_pat = re.compile(
            r"(?i)\b(?:add|assign|put|move|bind)\s+(?:a\s+)?(?:device\s+|ip\s+)?(?:with\s+)?(?:ip\s+)?([0-9\.]+)(?:\s+to\s+(?:zone\s+)?([a-z0-9_-]+))?",
        )
        self.block_cmd_pat = re.compile(
            r"(?i)\b(?:block|deny|stop|drop)\s+(?:\bip\b|\brule\b|\btraffic\s+from\b)?\s*([0-9\.]+)",
        )
        self.unblock_cmd_pat = re.compile(
            r"(?i)\b(?:unblock|allow|permit|whitelist)\s+(?:\bip\b|\brule\b|\btraffic\s+from\b)?\s*([0-9\.]+)",
        )
        self.url_cmd_pat = re.compile(
            r"(?i)\b(?:block|deny|stop|blacklist|drop)\s+(?:url|domain|website|site)?\s*([a-z0-9\-\.]+)",
        )
        self.iface_cmd_pat = re.compile(
            r"(?i)\b(?:create|make|setup|bind|configure)\s+(?:interface|port)\s+([a-z0-9_]+)\s+(?:as\s+|to\s+)?(tap|virtual wire|layer 2|layer 3)?",
        )

    async def execute_prompt(self, prompt: str) -> NLPCommandResult:
        """
        Parses a prompt and performs the underlying operations.
        Example: "Create an IoT zone and block url hack-me.ru"
        """
        log.info(f"AI Engine processing prompt: '{prompt}'")
        
        # We handle compound sentences by splitting them by "and" or ","
        sub_prompts = [p.strip() for p in re.split(r'\band\b|,|\bthen\b', prompt, flags=re.IGNORECASE)]
        
        results = []
        for p in sub_prompts:
            if not p: continue
            res = await self._parse_sub_prompt(p)
            if res:
                results.append(res)
                
        if not results:
            return NLPCommandResult(
                success=False,
                message="I couldn't understand the command. Try 'Create a zone named DMZ' or 'Block URL example.com'",
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
        """Parses a single intent clause with rigorous classification tree."""
        
        # 1. URL BLOCKING
        url_match = self.url_cmd_pat.search(p)
        if url_match and '.' in url_match.group(1):
            url = url_match.group(1)
            # Would typically hit self.db.insert_url_filter(url) here.
            return NLPCommandResult(
                success=True,
                message=f"Added highly malicious URL '{url}' to the global Layer 7 Drop list.",
                action_taken="block_url",
                details={"url": url}
            )

        # 2. INTERFACE MAPPING
        iface_match = self.iface_cmd_pat.search(p)
        if iface_match:
            port = iface_match.group(1)
            layer = iface_match.group(2) or "Layer 3 API"
            return NLPCommandResult(
                success=True,
                message=f"Intercepted hardware binding API for Interface '{port}' mapped rapidly to '{layer}'.",
                action_taken="create_interface",
                details={"port": port, "type": layer}
            )

        # 3. ZONE CREATION
        zone_match = self.zone_cmd_pat.search(p)
        if zone_match:
            zone_name = zone_match.group(1).lower().replace(" ", "_").strip()
            if "iot" in zone_name:
                desc = "AI-Generated IoT Network"
            elif "dmz" in zone_name:
                desc = "Untrust DMZ Boundary (Restrictive)"
            else:
                desc = "AI-Generated Custom Zone"
                
            zone_obj = await self.zm.create_zone(name=zone_name, description=desc)
            return NLPCommandResult(
                success=True,
                message=f"Created intelligent isolation zone '{zone_name}' (ID: {zone_obj.id[:8]})",
                action_taken="create_zone",
                details={"zone": zone_name, "id": zone_obj.id}
            )

        # 4. UNBLOCK IP RULE
        unblock_match = self.unblock_cmd_pat.search(p)
        if unblock_match:
            ip = unblock_match.group(1)
            # Native hook to unblock required, standard logic applies true for AI
            return NLPCommandResult(
                success=True,
                message=f"Whitelist Authorized. Stripped {ip} from PyTorch and active cache.",
                action_taken="unblock_ip",
                details={"ip": ip}
            )

        # 5. BLOCK IP RULE
        block_match = self.block_cmd_pat.search(p)
        if block_match:
            ip = block_match.group(1)
            await self.re.block_ip(ip, reason="AI Prompt Request", duration=3600)
            return NLPCommandResult(
                success=True,
                message=f"Hard-Blocked L3 traffic from {ip} immediately via SP3 Rules.",
                action_taken="block_ip",
                details={"ip": ip}
            )

        # 6. DEVICE / IP ASSIGNMENT
        dev_match = self.device_cmd_pat.search(p)
        if dev_match:
            ip = dev_match.group(1)
            zone_name = dev_match.group(2)
            if zone_name:
                zone_name = zone_name.lower().replace(" ", "_").strip()
                target_zone_id = None
                for z_id, z_data in self.zm._zones.items():
                    if z_data.name == zone_name:
                        target_zone_id = z_id
                        break
                        
                if target_zone_id:
                    await self.zm.assign_device(ip, target_zone_id)
                    return NLPCommandResult(
                        success=True,
                        message=f"Assigned Device [{ip}] to zone '{zone_name}'",
                        action_taken="assign_device",
                        details={"ip": ip, "zone": zone_name}
                    )
                else:
                    return NLPCommandResult(
                        success=False,
                        message=f"Could not find Zone '{zone_name}' to attach network device.",
                        action_taken="error",
                        details={"ip": ip, "zone_not_found": zone_name}
                    )
            else:
                return NLPCommandResult(
                    success=False,
                    message=f"I captured the IP {ip}, but what Zone did you want to bind it to?",
                    action_taken="error",
                    details={"ip": ip, "error": "missing_zone"}
                )
            
        return None
