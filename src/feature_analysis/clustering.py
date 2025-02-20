# src/feature_analysis/clustering.py
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
import numpy as np
from typing import List, Dict
import logging
from ..network_scanner.models import DeviceFingerprint

class DeviceClusterer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scaler = StandardScaler()
        
    def _extract_features(self, devices: List[DeviceFingerprint]) -> np.ndarray:
        """Convert device data into feature vectors"""
        features = []
        for device in devices:
            # Convert ports to binary feature vector (common ports)
            port_features = [1 if p in device.open_ports else 0 
                        for p in [21, 22, 23, 80, 443, 8080, 1883, 5683, 502]]
        
        # Enhanced OS fingerprinting
            os_map = {
                'Windows': 1,
                'Linux': 2,
                'BSD': 3,
                'IoT': 4,  # New category for IoT devices
                'Industrial': 5  # For ICS/SCADA systems
            }
            os_feature = os_map.get(device.os_type, 0)
            
            # Add service type features
            service_features = []
            common_services = ['ftp', 'ssh', 'telnet', 'http', 'https', 'mqtt', 'coap']
            for service in common_services:
                has_service = any(service in s.lower() 
                            for s in device.services.values()) if device.services else 0
                service_features.append(1 if has_service else 0)

            # Combine features
            device_features = port_features + [os_feature] + service_features
            features.append(device_features)
            
        return np.array(features)
    
    def cluster_devices(self, devices: List[DeviceFingerprint], method='kmeans') -> Dict:
        """Cluster devices using specified method"""
        if not devices:
            raise ValueError("No devices provided for clustering")
            
        # Extract and scale features
        X = self._extract_features(devices)
        X_scaled = self.scaler.fit_transform(X)
        
        if method == 'kmeans':
            # Use elbow method to find optimal k
            max_k = min(len(devices), 10)
            distortions = []
            K = range(1, max_k + 1)
            
            for k in K:
                kmeans = KMeans(n_clusters=k)
                kmeans.fit(X_scaled)
                distortions.append(kmeans.inertia_)
            
            # Simple elbow detection
            k = 1  # Default to 1 cluster
            if len(distortions) > 2:  # Need at least 3 points for elbow detection
                try:
                    for i in range(1, len(distortions)-1):
                        if (distortions[i-1] - distortions[i]) / max(0.0001, (distortions[i] - distortions[i+1])) < 1.5:
                            k = i + 1
                            break
                except ZeroDivisionError:
                    # If we get division by zero, just use k=1
                    k = 1
                    
            # Ensure k is at least 1 and at most the number of devices
            k = max(1, min(k, len(devices)))
                    
            # Perform final clustering
            clusterer = KMeans(n_clusters=k)
            
        elif method == 'dbscan':
            clusterer = DBSCAN(eps=0.3, min_samples=1)  # Reduced min_samples to 1
            
        else:
            raise ValueError(f"Unknown clustering method: {method}")
            
        labels = clusterer.fit_predict(X_scaled)
        
        # Group devices by cluster
        clusters = {}
        for device, label in zip(devices, labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(device)
            
        return clusters