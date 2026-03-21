"""
AEROCIFER NGFW — ML Feature Extractor

Extracts numerical features from raw Network Flows to feed into Neural Networks.
"""
import numpy as np
from aerocifer.core.session_tracker import FlowEntry

class FlowFeatureExtractor:
    """Extracts a normalized feature vector from a FlowEntry."""
    
    # Standardize to 16 features for our ML model
    FEATURE_DIM = 16
    
    @staticmethod
    def extract_features(flow: FlowEntry) -> np.ndarray:
        """
        Convert a flow into a normalized numpy array of size FEATURE_DIM.
        All values are normalized roughly between 0 and 1 for the Neural Network.
        """
        duration = max(flow.duration, 0.001)
        
        # 1-2. Packet counts (Log scaled to squish huge numbers)
        fwd_pkts = np.log1p(flow.fwd_packets) / 10.0
        bwd_pkts = np.log1p(flow.bwd_packets) / 10.0
        
        # 3-4. Byte counts (Log scaled)
        fwd_bytes = np.log1p(flow.fwd_bytes) / 15.0
        bwd_bytes = np.log1p(flow.bwd_bytes) / 15.0
        
        # 5. Flow rate (bytes/sec)
        bytes_per_sec = np.log1p((flow.fwd_bytes + flow.bwd_bytes) / duration) / 15.0
        
        # 6. Packet rate (packets/sec)
        pkts_per_sec = np.log1p((flow.fwd_packets + flow.bwd_packets) / duration) / 10.0
        
        # 7. Asymmetry (0 = perfectly symmetric, 1 = perfectly asymmetric)
        total_pkts = max(flow.fwd_packets + flow.bwd_packets, 1)
        asymmetry = abs(flow.fwd_packets - flow.bwd_packets) / total_pkts
        
        # 8-13. TCP Flags ratios
        flag_syn = flow.syn_count / max(flow.fwd_packets, 1)
        flag_ack = flow.ack_count / max(flow.fwd_packets, 1)
        flag_fin = flow.fin_count / max(flow.fwd_packets, 1)
        flag_rst = flow.rst_count / max(flow.fwd_packets, 1)
        flag_psh = flow.psh_count / max(flow.fwd_packets, 1)
        flag_urg = flow.urg_count / max(flow.fwd_packets, 1)
        
        # 14. Is Well-known port? (1 if <= 1024 else 0)
        dest_is_well_known = 1.0 if flow.dst_port <= 1024 else 0.0
        
        # 15. Protocol type indicator (TCP=1.0, UDP=0.5, ICMP=0.0)
        proto_val = 0.0
        if flow.protocol == 'tcp': proto_val = 1.0
        elif flow.protocol == 'udp': proto_val = 0.5
        
        # 16. Has application protocol identified? (DPI)
        has_app = 1.0 if flow.application else 0.0

        features = [
            fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, 
            bytes_per_sec, pkts_per_sec, asymmetry,
            flag_syn, flag_ack, flag_fin, flag_rst, flag_psh, flag_urg,
            dest_is_well_known, proto_val, has_app
        ]
        
        # Ensure exact dimensions and clip to standard ranges
        vec = np.array(features, dtype=np.float32)
        vec = np.clip(vec, 0.0, 1.0)
        return vec
