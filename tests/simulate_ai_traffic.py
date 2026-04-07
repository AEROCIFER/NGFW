"""
AEROCIFER NGFW — Live ML Traffic Simulation

Feeds a sequence of mock packets directly into the Session Tracker to simulate 
normal traffic patterns, then introduces strange anomalous behavior to watch
the PyTorch Autoencoder react and assign anomaly scores.
"""

import asyncio
import time
import os
import sys

# Ensure aerocifer can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aerocifer.core.session_tracker import SessionTracker, FlowEntry
from aerocifer.ml.anomaly_detector import TrafficAnomalyDetector
from aerocifer.ml.device_classifier import DeviceZoneClassifier

async def run_simulation():
    print("="*60)
    print(" AEROCIFER LIVE AI SIMULATION")
    print("="*60)
    
    # 1. Initialize ML components
    print("\n[+] Spinning up Neural Networks...")
    anomaly_detector = TrafficAnomalyDetector(threshold=0.5)
    device_classifier = DeviceZoneClassifier()
    
    # Force the autoencoder to train mode initially to simulate a blank slate
    print("[+] Pre-training Autoencoder on 'Normal' Web Browsing Traffic baseline...")
    
    # Generate 50 perfectly normal HTTP web flows 
    # (very symmetric, standard packet sizes, known ports)
    normal_flows = []
    for _ in range(50):
        flow = FlowEntry(
            src_ip="192.168.1.100", dst_ip="104.21.3.4", 
            src_port=50000 + _, dst_port=443, protocol="tcp"
        )
        flow.fwd_packets = 10
        flow.bwd_packets = 12
        flow.fwd_bytes = 10 * 1500
        flow.bwd_bytes = 12 * 1400
        flow.start_time = time.time() - 2.0
        flow.last_activity = time.time()
        flow.application = "https"
        flow.syn_count = 1
        flow.ack_count = 20
        flow.fin_count = 1
        
        normal_flows.append(flow)
        # Train incrementally
        anomaly_detector.train_on_flow(flow)
        
    print("[+] [OK] Normal Baseline Established.")
    
    # 2. Test a normal flow against the now-trained model
    print("\n[+] Testing a new, fully NORMAL flow against the trained Autoencoder:")
    test_normal = normal_flows[0]
    is_anomaly, loss = anomaly_detector.predict(test_normal)
    print(f"   => Normal Flow Loss: {loss:.5f} (Threshold: {anomaly_detector.threshold})")
    print(f"   => Is Anomaly? {'YES' if is_anomaly else 'NO (Expected)'}")
    
    # 3. Test an anomalous flow (simulate an attack/exfiltration)
    print("\n[+] Testing an ANOMALOUS flow (e.g. Data Exfiltration via UDP on strange port)...")
    weird_flow = FlowEntry(
        src_ip="192.168.1.100", dst_ip="185.33.2.1", 
        src_port=4444, dst_port=6667, protocol="udp"
    )
    # Exfiltration: Massive outgoing, very little incoming, weird port, weird timing
    weird_flow.fwd_packets = 15000
    weird_flow.bwd_packets = 3
    weird_flow.fwd_bytes = 15000 * 1500 # lots of data out
    weird_flow.bwd_bytes = 3 * 64       # tiny acks back
    weird_flow.start_time = time.time() - 0.5
    weird_flow.last_activity = time.time()
    weird_flow.application = ""
    # No TCP flags on UDP!
    
    is_anomaly, loss = anomaly_detector.predict(weird_flow)
    print(f"   => Anomalous Flow Loss: {loss:.5f} (Threshold: {anomaly_detector.threshold})")
    print(f"   => Is Anomaly? {'YES (It caught it!)' if is_anomaly else 'NO (Failed to catch)'}")
    
    # 4. Neural Device Classification Test
    print("\n[+] Grouping the flows to Classify the Device at 192.168.1.100...")
    # Add some IoT-like indicators to the flows
    for f in normal_flows:
        f.dst_port = 8883 # MQTT
        f.protocol = "tcp"
        
    category, confidence = device_classifier.classify_device(normal_flows)
    print(f"   => AI categorizes Device 192.168.1.100 as: '{category}' with {confidence*100:.1f}% confidence!")
    
    print("\n" + "="*60)
    print(" Simulation Complete.")

if __name__ == "__main__":
    asyncio.run(run_simulation())
