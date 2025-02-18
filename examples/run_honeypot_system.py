# examples/run_honeypot_system.py
#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
import time

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.network_scanner.scanner import NetworkScanner
from src.feature_analysis.clustering import DeviceClusterer
from src.honeypot_config.generator import HoneypotConfigGenerator
from src.honeypot_deploy.tpot_deployer import TPotDeployer
from src.utils.config import Config

def main():
    # Configure logging
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format=Config.LOG_FORMAT
    )
    logger = logging.getLogger(__name__)
    
    try:
        # 1. Scan network
        logger.info("Starting network scan...")
        scanner = NetworkScanner(
            target_network=Config.TARGET_NETWORK,
            interface=Config.INTERFACE
        )
        devices = scanner.scan_network()
        logger.info(f"Found {len(devices)} devices")
        
        # 2. Analyze and cluster devices
        logger.info("Clustering devices...")
        clusterer = DeviceClusterer()
        clusters = clusterer.cluster_devices(devices, method='kmeans')
        logger.info(f"Created {len(clusters)} device clusters")
        
        # 3. Generate honeypot configurations
        logger.info("Generating honeypot configurations...")
        config_gen = HoneypotConfigGenerator(Config.OUTPUT_DIR)
        configs = config_gen.generate_config(clusters)
        config_file = config_gen.save_configs(configs)
        logger.info(f"Generated {len(configs)} honeypot configurations")
        
        # 4. Deploy honeypots
        logger.info("Deploying honeypots...")
        deployer = TPotDeployer(Config.TPOT_DIR)
        if deployer.deploy_honeypots(config_file):
            logger.info("Honeypots deployed successfully")
        else:
            logger.error("Failed to deploy honeypots")
            
        # 5. Monitor and update (continuous operation)
        logger.info("Entering monitoring mode...")
        try:
            while True:
                # Periodically rescan and update
                time.sleep(Config.SCAN_DURATION)
                
                # Rescan network
                new_devices = scanner.scan_network()
                
                # Recluster and update if needed
                new_clusters = clusterer.cluster_devices(new_devices)
                
                # Generate and deploy new configs if changes detected
                if new_clusters != clusters:
                    logger.info("Network changes detected, updating configurations...")
                    new_configs = config_gen.generate_config(new_clusters)
                    config_file = config_gen.save_configs(new_configs)
                    deployer.deploy_honeypots(config_file)
                    clusters = new_clusters
                
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            
    except Exception as e:
        logger.error(f"System error: {str(e)}")
        if "requires root privileges" in str(e):
            logger.error("Try running with sudo for full functionality")
        sys.exit(1)

if __name__ == '__main__':
    main()