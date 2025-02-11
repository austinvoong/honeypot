# src/network_scanner/p0f_scanner.py
import subprocess
import json
import logging
from typing import List
from pathlib import Path
from .models import DeviceFingerprint

class P0fScanner:
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
        self.logger = logging.getLogger(__name__)
    
    def scan(self, duration: int = 300) -> List[DeviceFingerprint]:
        """Run passive p0f scan"""
        self.logger.info(f"Starting p0f scan on interface {self.interface}")
        
        try:
            cmd = f"p0f -i {self.interface} -o /tmp/p0f.json -t {duration}"
            subprocess.run(cmd, shell=True, check=True)
            
            devices = []
            with open('/tmp/p0f.json') as f:
                p0f_data = json.load(f)
                
            for entry in p0f_data:
                device = DeviceFingerprint(
                    ip_address=entry['client_ip'],
                    tcp_fingerprint=entry.get('tcp_fingerprint'),
                    uptime=entry.get('uptime')
                )
                devices.append(device)
                
            return devices
            
        except Exception as e:
            self.logger.error(f"p0f scan failed: {str(e)}")
            raise