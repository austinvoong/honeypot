# src/utils/config.py
from pathlib import Path

class Config:
    # Network configuration
    TARGET_NETWORK = '172.20.0.0/16'  # Docker network
    INTERFACE = 'eth0'
    
    # Scanning configuration
    SCAN_DURATION = 300  # seconds
    MAX_RETRIES = 2
    
    # Output configuration
    OUTPUT_DIR = Path('scan_results')
    
    # T-Pot configuration
    # src/utils/config.py
    TPOT_DIR = Path('/opt/tpot')  # Or wherever T-Pot is installed

    # Logging configuration
    LOG_LEVEL = 'DEBUG'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'