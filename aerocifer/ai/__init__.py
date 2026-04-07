"""
AEROCIFER NGFW — AI Engine Package

- GemmaConfigEngine: Uses Ollama + Gemma 4 for AI configuration.
"""

from aerocifer.ai.gemma_engine import GemmaConfigEngine
from aerocifer.ai.nlp_engine import NLPCommandResult

__all__ = [
    "GemmaConfigEngine",
    "NLPCommandResult",
]
