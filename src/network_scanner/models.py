# src/network_scanner/models.py
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class DeviceFingerprint:
    """Data class to store device fingerprint information"""
    ip_address: str
    os_type: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None
    tcp_fingerprint: Optional[str] = None
    uptime: Optional[float] = None