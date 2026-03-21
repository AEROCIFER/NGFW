"""
AEROCIFER NGFW — Test Suite

Run tests:
    python -m pytest tests/ -v
    python -m pytest tests/ -v --tb=short
"""

import asyncio
import sys
import os

# Add project root to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
