# src/honeypot_config/generator.py
from typing import List, Dict
import json
from pathlib import Path
import logging
from ..network_scanner.models import DeviceFingerprint
import numpy as np
import random
from datetime import datetime

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
            
            # Determine most common OS type
            os_type = max(os_types.items(), key=lambda x: x[1])[0] if os_types else 'Linux'
            
            # Calculate port consistency (% of devices with each port)
            port_consistency = {}
            for port in ports:
                count = sum(1 for device in devices if port in device.open_ports)
                port_consistency[port] = count / len(devices)
            
            # Calculate service consistency for each port
            service_consistency = {}
            for port, port_services in services.items():
                if port_services:
                    most_common = max(port_services.items(), key=lambda x: x[1])[0]
                    consistency = port_services[most_common] / sum(port_services.values())
                    service_consistency[port] = consistency
            
            # Create service mapping with most common service for each port
            service_mapping = {}
            for port, port_services in services.items():
                if port_services:
                    service_mapping[str(port)] = max(port_services.items(), key=lambda x: x[1])[0]
            
            # Determine device type based on services
            device_type = self._infer_device_type(service_mapping)
            
            # Create honeypot config for this cluster with enhanced metadata
            config = {
                'cluster_id': cluster_id,
                'os_type': os_type,
                'ports': list(ports),
                'services': service_mapping,
                'personality': self._determine_personality(os_type),
                'uptime_range': [24, 720],  # 1-30 days, randomized
                'variability': {
                    'port_consistency': port_consistency,
                    'service_consistency': service_consistency,
                    'device_count': len(devices)
                },
                'device_type': device_type,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add HTTP headers if available
            http_headers = self._extract_http_headers(devices)
            if http_headers:
                config['http_headers'] = http_headers
            
            configs.append(config)
            
        return configs
    
    def _infer_device_type(self, services: Dict[str, str]) -> str:
        """Infer device type from services"""
        service_values = services.values()
        
        # Check for common device types based on services
        if 'rtsp' in service_values or 'mjpeg' in service_values:
            return 'camera'
        elif 'mqtt' in service_values:
            return 'iot-gateway'
        elif 'modbus' in service_values or 'bacnet' in service_values:
            return 'industrial-control'
        elif 'http' in service_values or 'http-alt' in service_values:
            return 'web-device'
        elif 'ssh' in service_values and 'telnet' in service_values:
            return 'network-device'
        elif 'snmp' in service_values:
            return 'managed-device'
        elif any('coap' in s for s in service_values):
            return 'iot-sensor'
        
        # Default
        return 'generic-device'
    
    def _determine_personality(self, os_type: str) -> str:
        """Determine honeypot personality based on OS type"""
        os_map = {
            'Linux': ['debian', 'ubuntu', 'centos', 'alpine'],
            'Windows': ['windows-10', 'windows-server-2019', 'windows-iot'],
            'BSD': ['freebsd', 'openbsd'],
            'RTOS': ['contiki', 'freertos', 'riot']
        }
        
        # Find the best matching OS category
        for category, variants in os_map.items():
            if os_type.lower() in [v.lower() for v in variants]:
                return random.choice(variants)
            elif category.lower() in os_type.lower():
                return random.choice(variants)
        
        # Default personality by OS category
        if os_type.lower() in ['linux', 'unix', 'posix']:
            return random.choice(os_map['Linux'])
        elif os_type.lower() in ['windows', 'win', 'microsoft']:
            return random.choice(os_map['Windows'])
        elif os_type.lower() in ['bsd', 'berkeley']:
            return random.choice(os_map['BSD'])
        elif os_type.lower() in ['rtos', 'embedded', 'iot']:
            return random.choice(os_map['RTOS'])
        
        # Default to a common Linux distribution
        return 'ubuntu'
    
    def _extract_http_headers(self, devices: List[DeviceFingerprint]) -> Dict[str, str]:
        """Extract common HTTP headers from devices"""
        headers = {}
        header_counts = {}
        
        for device in devices:
            if hasattr(device, 'http_headers') and device.http_headers:
                for header, value in device.http_headers.items():
                    if header not in header_counts:
                        header_counts[header] = {}
                    header_counts[header][value] = header_counts[header].get(value, 0) + 1
        
        # Select most common value for each header
        for header, values in header_counts.items():
            if values:
                most_common = max(values.items(), key=lambda x: x[1])[0]
                headers[header] = most_common
        
        return headers
    
    def save_configs(self, configs: List[Dict], filename: str = 'honeypot_configs.json'):
        """Save honeypot configurations to file"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / filename
        
        # Convert numpy types to Python native types
        def convert_to_native(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            return obj
        
        # Convert configs to native Python types
        native_configs = []
        for config in configs:
            native_config = {k: convert_to_native(v) for k, v in config.items()}
            native_configs.append(native_config)
        
        with open(output_file, 'w') as f:
            json.dump(native_configs, f, indent=2)
            
        self.logger.info(f"Saved {len(configs)} honeypot configurations to {output_file}")
        return output_file