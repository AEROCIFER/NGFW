"""
AEROCIFER NGFW — Machine Learning Package

- FlowFeatureExtractor: Extract flow data to normalized vectors.
- TrafficAnomalyDetector: Unsupervised Autoencoder for anomalies.
- DeviceZoneClassifier: Supervised Neural Network for categorizing devices.
"""

from aerocifer.ml.feature_extractor import FlowFeatureExtractor
from aerocifer.ml.anomaly_detector import TrafficAnomalyDetector
from aerocifer.ml.device_classifier import DeviceZoneClassifier

__all__ = [
    "FlowFeatureExtractor",
    "TrafficAnomalyDetector",
    "DeviceZoneClassifier",
]
