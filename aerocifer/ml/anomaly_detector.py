"""
AEROCIFER NGFW — Neural Traffic Anomaly Detector

Uses the PyTorch Autoencoder to detect abnormal network sessions in real-time
and fine-tune the model automatically based on new regular traffic.
"""

import os
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

from aerocifer.utils.logger import get_logger
from aerocifer.core.session_tracker import FlowEntry
from aerocifer.ml.models_pytorch import TrafficAutoencoder
from aerocifer.ml.feature_extractor import FlowFeatureExtractor

log = get_logger("ml")

class TrafficAnomalyDetector:
    """Detects unusual traffic flows using an Autoencoder."""

    def __init__(self, model_dir: str = "data/models", threshold: float = 0.5):
        self.model_dir = model_dir
        self.threshold = threshold
        self.model_path = os.path.join(model_dir, "autoencoder.pt")
        
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize model
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = TrafficAutoencoder(
            input_dim=FlowFeatureExtractor.FEATURE_DIM
        ).to(self.device)
        
        # Loss and Optimizer for continuous learning
        self.criterion = nn.MSELoss()
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        
        self.load_model()
        
        # Training state buffers to batch process
        self._training_buffer = []
        self._batch_size = 64

    def load_model(self) -> None:
        """Load pre-trained weights if available."""
        if os.path.exists(self.model_path):
            try:
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                self.model.eval()
                log.info(f"Loaded Anomaly Detector from {self.model_path} on {self.device}")
            except Exception as e:
                log.error(f"Failed to load Autoencoder model: {e}")
        else:
            log.info(f"No existing ML model found. Initializing fresh model on {self.device}")
            # Ensure folder exists
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

    def save_model(self) -> None:
        """Save weights back to disk."""
        torch.save(self.model.state_dict(), self.model_path)
        log.debug(f"Saved Anomaly Detector weights to {self.model_path}")

    def predict(self, flow: FlowEntry) -> tuple[bool, float]:
        """
        Inference step: Returns (is_anomaly, reconstruction_error).
        If reconstruction_error > threshold, it's considered anomalous.
        """
        features = FlowFeatureExtractor.extract_features(flow)
        
        with torch.no_grad():
            self.model.eval()
            
            # Convert to PyTorch Tensor
            x = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(self.device)
            
            # Forward pass: Encode & Decode
            reconstructed = self.model(x)
            
            # Calculate error
            loss = self.criterion(reconstructed, x).item()
            
            is_anomaly = loss > self.threshold
        
        return is_anomaly, loss

    def train_on_flow(self, flow: FlowEntry) -> None:
        """
        Incremental learning: trains the model on clean/regular traffic 
        so it automatically adjusts and optimizes to the local network.
        """
        features = FlowFeatureExtractor.extract_features(flow)
        self._training_buffer.append(features)
        
        # When buffer is full, perform an optimization step
        if len(self._training_buffer) >= self._batch_size:
            self.model.train()
            batch = torch.tensor(
                np.array(self._training_buffer), dtype=torch.float32
            ).to(self.device)
            
            self.optimizer.zero_grad()
            reconstructed = self.model(batch)
            loss = self.criterion(reconstructed, batch)
            
            loss.backward()
            self.optimizer.step()
            
            self._training_buffer.clear()
            self.save_model()
