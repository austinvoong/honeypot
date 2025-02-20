# src/network_scanner/scanner.py
from typing import List
from pathlib import Path
import json
import logging
from .nmap_scanner import NmapScanner
from .p0f_scanner import P0fScanner
from .models import DeviceFingerprint

class NetworkScanner:
    def __init__(self, target_network: str, interface: str = 'eth0'):
        self.nmap_scanner = NmapScanner(target_network)
        self.p0f_scanner = P0fScanner(interface)
        self.logger = logging.getLogger(__name__)
        
    def scan_network(self) -> List[DeviceFingerprint]:
        """Run full network scan using both Nmap and p0f"""
        self.logger.info("Starting network scan...")
        
        # Run Nmap scan
        self.logger.info("Running Nmap scan...")
        try:
            nmap_results = self.nmap_scanner.scan()
            self.logger.info(f"Nmap scan complete. Found {len(nmap_results)} devices")
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {str(e)}")
            nmap_results = []
        
        # Run p0f scan
        self.logger.info("Running p0f scan...")
        try:
            p0f_results = self.p0f_scanner.scan()
            self.logger.info(f"p0f scan complete. Found {len(p0f_results)} devices")
        except Exception as e:
            self.logger.error(f"p0f scan failed: {str(e)}")
            p0f_results = []
        
        # Merge results
        devices = self._merge_fingerprints(nmap_results, p0f_results)
        self.logger.info(f"Merged results. Total unique devices: {len(devices)}")
        
        # Save results
        self._save_results(devices)
        
        return devices
    
    def _merge_fingerprints(self, nmap_devices: List[DeviceFingerprint],
                           p0f_devices: List[DeviceFingerprint]) -> List[DeviceFingerprint]:
        merged = {}
        
        for device in nmap_devices:
            merged[device.ip_address] = device
            
        for device in p0f_devices:
            if device.ip_address in merged:
                merged[device.ip_address].tcp_fingerprint = device.tcp_fingerprint
                merged[device.ip_address].uptime = device.uptime
            else:
                merged[device.ip_address] = device
                
        return list(merged.values())
    
    def _save_results(self, devices: List[DeviceFingerprint],
                     output_dir: str = 'scan_results'):
        Path(output_dir).mkdir(exist_ok=True)
        
        results = []
        for device in devices:
            results.append({
                'ip_address': device.ip_address,
                'os_type': device.os_type,
                'open_ports': device.open_ports,
                'services': device.services,
                'tcp_fingerprint': device.tcp_fingerprint,
                'uptime': device.uptime
            })
            
        output_file = Path(output_dir) / 'network_scan.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        self.logger.info(f"Scan results saved to {output_file}")