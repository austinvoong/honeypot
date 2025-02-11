# src/network_scanner/nmap_scanner.py
import nmap
import logging
import os
from typing import List, Dict
from .models import DeviceFingerprint

class NmapScanner:
    def __init__(self, target_network: str):
        self.target_network = target_network
        self.nm = nmap.PortScanner()
        self.logger = logging.getLogger(__name__)
        
    def _is_root(self) -> bool:
        """Check if running with root privileges"""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
    def scan(self) -> List[DeviceFingerprint]:
        """Run Nmap scan with appropriate privileges"""
        self.logger.info(f"Starting Nmap scan of {self.target_network}")
        
        try:
            # Choose scan type based on privileges
            if self._is_root():
                self.logger.info("Running privileged scan with OS detection")
                scan_args = '-sS -sU -O -F --max-retries 2'
            else:
                self.logger.warning("Running with limited privileges - using basic TCP scan")
                scan_args = '-sT -F -n --max-retries 2'
            
            self.nm.scan(
                self.target_network,
                arguments=scan_args
            )
            
            devices = []
            for host in self.nm.all_hosts():
                device = DeviceFingerprint(ip_address=host)
                
                # Get OS info if available (only in privileged mode)
                if 'osmatch' in self.nm[host]:
                    matches = self.nm[host]['osmatch']
                    if matches:
                        device.os_type = matches[0]['name']
                
                device.open_ports = []
                device.services = {}
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        device.open_ports.append(port)
                        service = self.nm[host][proto][port]['name']
                        device.services[port] = service
                
                devices.append(device)
                
            self.logger.info(f"Scan completed. Found {len(devices)} devices")
            return devices
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan failed: {str(e)}")
            if "requires root privileges" in str(e):
                self.logger.error("This scan requires root privileges. Try running with sudo")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {str(e)}")
            raise