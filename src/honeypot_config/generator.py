# src/honeypot_config/generator.py
from typing import List, Dict
import json
from pathlib import Path
import logging
from ..network_scanner.models import DeviceFingerprint

class HoneypotConfigGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        
    def generate_config(self, clusters: Dict[int, List[DeviceFingerprint]]) -> List[Dict]:
        """Generate honeypot configurations based on clustered devices"""
        configs = []
        
        for cluster_id, devices in clusters.items():
            if not devices:
                continue
                
            # Find most common characteristics in cluster
            ports = set()
            os_types = {}
            services = {}
            
            for device in devices:
                if device.open_ports:
                    ports.update(device.open_ports)
                if device.os_type:
                    os_types[device.os_type] = os_types.get(device.os_type, 0) + 1
                if device.services:
                    for port, service in device.services.items():
                        if port not in services:
                            services[port] = {}
                        services[port][service] = services[port].get(service, 0) + 1
            
            # Create honeypot config for this cluster
            config = {
                'cluster_id': cluster_id,
                'os_type': max(os_types.items(), key=lambda x: x[1])[0] if os_types else 'Linux',
                'ports': list(ports),
                'services': {
                    str(port): max(svc.items(), key=lambda x: x[1])[0]
                    for port, svc in services.items()
                },
                'personality': 'default',  # Can be customized based on OS
                'uptime_range': [24, 720]  # 1-30 days, randomized
            }
            
            configs.append(config)
            
        return configs
    
    def save_configs(self, configs: List[Dict], filename: str = 'honeypot_configs.json'):
        """Save honeypot configurations to file"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / filename
        
        with open(output_file, 'w') as f:
            json.dump(configs, f, indent=2)
            
        self.logger.info(f"Saved {len(configs)} honeypot configurations to {output_file}")
        return output_file