import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aerocifer.ai.gemma_engine import GemmaConfigEngine
from tests.test_ml_ai import MockRuleEngine, MockZoneManager


async def main() -> None:
    eng = GemmaConfigEngine(
        zone_manager=MockZoneManager(),
        rule_engine=MockRuleEngine(),
        model_name="gemma4:latest",
        ollama_host="http://localhost:11434",
    )
    status = await eng.check_status()
    print(status)


if __name__ == "__main__":
    asyncio.run(main())

