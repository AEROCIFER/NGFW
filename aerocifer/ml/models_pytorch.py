"""
PyTorch Neural Network Models for AEROCIFER NGFW

Contains:
1. TrafficAutoencoder: Unsupervised anomaly detection.
2. DeviceClassifierNN: Supervised classification for devices.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

class TrafficAutoencoder(nn.Module):
    """
    Neural Network for Unsupervised Anomaly Detection.
    
    Architecture: Autoencoder
    - Learns to compress and reconstruct "normal" network flows.
    - If a new flow has a high "reconstruction error", it is flagged as an anomaly.
    """
    def __init__(self, input_dim: int, hidden_dim: int = 32, latent_dim: int = 16):
        super(TrafficAutoencoder, self).__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LeakyReLU(0.1),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, latent_dim),
            nn.LeakyReLU(0.1)
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LeakyReLU(0.1),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid() # Normalize outputs between 0 and 1
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class DeviceClassifierNN(nn.Module):
    """
    Feedforward Neural Network for Device Classification.
    
    Classifies devices based on behavior features (protocols used, port usage, 
    packet sizes, connection frequencies) into categories like:
    - IoT Device
    - Workstation/Basic Device
    - Server
    - Mobile Device
    """
    def __init__(self, input_dim: int, num_classes: int, hidden_dim: int = 64):
        super(DeviceClassifierNN, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.bn1 = nn.BatchNorm1d(hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.bn2 = nn.BatchNorm1d(hidden_dim // 2)
        self.fc3 = nn.Linear(hidden_dim // 2, num_classes)
        self.dropout = nn.Dropout(0.2)

    def forward(self, x):
        x = F.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = F.relu(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        x = self.fc3(x)
        return x
