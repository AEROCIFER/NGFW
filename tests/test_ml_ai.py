"""
Tests for AEROCIFER NGFW — Sprint 3: ML Integration & AI Features

Validates:
- FlowFeatureExtractor converts raw flows into neural-network ready numpy arrays.
- PyTorch Autoencoder does not crash and computes MSE.
- NLP Engine properly parses human prompts into Zone and Rule actions.
"""

import asyncio
import sys
import os
import torch
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def run_async(coro):
    return asyncio.run(coro)

# ═══════════════════════════════════════════════════════════════════════════
# ML Feature Extractor Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_feature_extractor():
    from aerocifer.core.session_tracker import FlowEntry
    from aerocifer.ml.feature_extractor import FlowFeatureExtractor
    
    # Mock a large flow
    flow = FlowEntry(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol="udp",
    )
    flow.fwd_packets = 10
    flow.bwd_packets = 10
    flow.fwd_bytes = 500
    flow.bwd_bytes = 1500
    flow.start_time = 0.0
    flow.last_activity = 1.5
    flow.application = "dns"
    
    vec = FlowFeatureExtractor.extract_features(flow)
    
    # Needs to be a numpy array of 16 float32 dimensions
    assert isinstance(vec, np.ndarray)
    assert vec.dtype == np.float32
    assert vec.shape == (16,)
    
    # Ensure values are normalized (squished to logic range, usually 0-1)
    assert np.all(vec >= 0.0)
    assert np.all(vec <= 1.0)
    
    print("✅ test_feature_extractor PASSED")

# ═══════════════════════════════════════════════════════════════════════════
# PyTorch Autoencoder Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_pytorch_autoencoder():
    from aerocifer.ml.models_pytorch import TrafficAutoencoder
    
    # 16 standard features
    model = TrafficAutoencoder(input_dim=16, hidden_dim=8, latent_dim=4)
    model.eval()
    
    # Create batch of 2 fake flows
    x = torch.rand((2, 16))
    
    # Forward pass
    with torch.no_grad():
        reconstructed = model(x)
        
    assert reconstructed.shape == (2, 16), "Output dimension must match input!"
    
    # Values should be squished by Sigmoid between 0 and 1
    assert torch.all(reconstructed >= 0.0)
    assert torch.all(reconstructed <= 1.0)
    
    print("✅ test_pytorch_autoencoder PASSED")

def test_pytorch_classifier():
    from aerocifer.ml.models_pytorch import DeviceClassifierNN
    
    # 20 standard features for Device classification into 5 classes
    model = DeviceClassifierNN(input_dim=20, num_classes=5)
    model.eval()
    
    x = torch.rand((4, 20)) # batch of 4 devices
    
    with torch.no_grad():
        logits = model(x)
        
    assert logits.shape == (4, 5)
    
    print("✅ test_pytorch_classifier PASSED")

# ═══════════════════════════════════════════════════════════════════════════
# AI NLP Engine Tests
# ═══════════════════════════════════════════════════════════════════════════

class MockRuleEngine:
    async def block_ip(self, ip, reason, duration):
        pass

class MockZoneManager:
    def __init__(self):
        self._zones = {}
        
    def create_zone(self, name, description):
        zone_id = f"mock_id_{name}"
        class MockZone:
            pass
        mz = MockZone()
        mz.name = name
        self._zones[zone_id] = mz
        return zone_id
        
    def assign_device(self, ip, zone_id):
        pass

def test_ai_nlp_parser():
    from aerocifer.ai.nlp_engine import NLPCommandEngine
    
    zm = MockZoneManager()
    re_mock = MockRuleEngine()
    
    ai = NLPCommandEngine(zone_manager=zm, rule_engine=re_mock)
    
    async def run_tests():
        # Test 1: Create Zone
        res = await ai.execute_prompt("Hey, AI, create a zone for IoT")
        assert res.success
        assert res.details.get("zone") == "iot"
        
        # Test 2: Double command
        res = await ai.execute_prompt("create network for basic_devices and add device 10.0.0.5 to basic_devices")
        assert res.success
        assert "basic_devices" in zm._zones[f"mock_id_basic_devices"].name
        
        # Test 3: Block command
        res = await ai.execute_prompt("Please block traffic from 192.168.1.100 immediately")
        assert res.success
        assert res.action_taken == "block_ip"
        assert res.details.get("ip") == "192.168.1.100"
        
        # Test 4: Unknown
        res = await ai.execute_prompt("Tell me the weather")
        assert not res.success
        
    run_async(run_tests())
    
    print("✅ test_ai_nlp_parser PASSED")

# ═══════════════════════════════════════════════════════════════════════════
# Execute
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AEROCIFER NGFW — Sprint 3: ML & AI Test Suite")
    print("=" * 60 + "\n")
    
    tests = [
        ("Feature Extractor", test_feature_extractor),
        ("PyTorch Autoencoder", test_pytorch_autoencoder),
        ("PyTorch Classifier", test_pytorch_classifier),
        ("AI NLP Engine Parser", test_ai_nlp_parser)
    ]
    
    passed, failed = 0, 0
    for name, t in tests:
        try:
            print(f"Running: {name}...")
            t()
            passed += 1
        except Exception as e:
            print(f"❌ {name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            
    if failed > 0:
        sys.exit(1)
        
    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 60)
