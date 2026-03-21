"""
AEROCIFER NGFW — Neural Device Classifier

Uses a supervised neural network to classify devices on the network based on 
their aggregated behavioral history. This is heavily integrated with the 
AI logic to automatically suggest "Zones".
"""

import os
import torch
import torch.nn as nn
import numpy as np

from aerocifer.utils.logger import get_logger
from aerocifer.ml.models_pytorch import DeviceClassifierNN

log = get_logger("ml")

class DeviceZoneClassifier:
    """Classifies a device into appropriate firewall Zones."""

    # Pre-defined classes the ML model outputs
    CLASSES = ["Unknown", "IoT", "Basic Device", "Server", "Mobile"]
    
    def __init__(self, model_dir: str = "data/models"):
        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, "device_classifier.pt")
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # 16 features aggregate + 4 behavioral stats -> 20 inputs
        self.model = DeviceClassifierNN(input_dim=20, num_classes=len(self.CLASSES)).to(self.device)
        
        self.load_model()

    def load_model(self) -> None:
        if os.path.exists(self.model_path):
            try:
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                self.model.eval()
                log.info(f"Loaded Device Classifier from {self.model_path}")
            except Exception as e:
                log.error(f"Failed to load Device Classifier: {e}")
        else:
            log.info("No Device Classifier weights found. Initializing randomly.")

    def save_model(self) -> None:
        os.makedirs(self.model_dir, exist_ok=True)
        torch.save(self.model.state_dict(), self.model_path)

    def extract_device_features(self, flows: list) -> np.ndarray:
        """
        Aggregate features across multiple flows of the same device
        to build a 20-dimensional behavioral profile.
        """
        from aerocifer.ml.feature_extractor import FlowFeatureExtractor
        
        if not flows:
            return np.zeros(20, dtype=np.float32)
            
        # Extract features for all recent flows belonging to this device
        flow_features = [FlowFeatureExtractor.extract_features(f) for f in flows]
        
        # Average the features to represent general behavior (16 dims)
        mean_features = np.mean(flow_features, axis=0)
        
        # Additional behavioral flags (4 dims)
        # e.g., Does it use UDP broadcast mostly? IoT. Does it use port 80/443 exclusively? Basic Device.
        unique_ports = len(set(f.dst_port for f in flows))
        total_connections = len(flows)
        
        # Did it scan the network? (port sweep flag indicator)
        is_port_scanning = 1.0 if unique_ports > 50 else 0.0
        
        # Normalize connection count relative to "heavy" usage
        conn_density = np.clip(total_connections / 1000.0, 0.0, 1.0)
        
        device_profile = np.concatenate([
            mean_features, 
            np.array([unique_ports / 65535.0, conn_density, is_port_scanning, 0.0], dtype=np.float32)
        ])
        
        return device_profile

    def classify_device(self, flows: list) -> tuple[str, float]:
        """
        Given a list of recent FlowEntry objects for an IP/MAC, 
        returns the (Zone Prediction Name, Confidence).
        """
        if not flows:
            return "Unknown", 0.0
            
        features = self.extract_device_features(flows)
        
        with torch.no_grad():
            self.model.eval()
            x = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(self.device)
            logits = self.model(x)
            
            # Apply softmax to get probabilities
            probs = torch.nn.functional.softmax(logits, dim=1).squeeze()
            confidence, predicted_idx = torch.max(probs, dim=0)
            
            # Return prediction label and confidence score
            return self.CLASSES[predicted_idx.item()], confidence.item()

