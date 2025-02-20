# examples/run_honeypot_system_docker.py
#!/usr/bin/env python3
import logging
import sys
import asyncio
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import Docker scanner
from docker_device_scanner import DockerDeviceScanner
from src.feature_analysis.clustering import DeviceClusterer
from src.honeypot_config.generator import HoneypotConfigGenerator
from src.honeypot_deploy.tpot_deployer import TPotDeployer
from src.utils.config import Config

async def main():
    # Configure logging
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format=Config.LOG_FORMAT
    )
    logger = logging.getLogger(__name__)
    
    try:
        # 1. Scan using Docker scanner
        logger.info("Scanning Docker test environment...")
        scanner = DockerDeviceScanner()
        devices = scanner.scan()
        scanner.save_results(devices)
        logger.info(f"Found {len(devices)} devices")
        
        if not devices:
            logger.error("No devices found in test environment")
            return
        
        # 2. Analyze and cluster devices
        logger.info("Clustering devices...")
        clusterer = DeviceClusterer()
        clusters = clusterer.cluster_devices(devices, method='kmeans')
        logger.info(f"Created {len(clusters)} device clusters")
        
        for cluster_id, cluster_devices in clusters.items():
            logger.info(f"Cluster {cluster_id}: {len(cluster_devices)} devices")
            for device in cluster_devices:
                logger.info(f"  - {device.ip_address} ({device.os_type}): {len(device.open_ports)} ports")
        
        # 3. Generate honeypot configurations
        logger.info("Generating honeypot configurations...")
        config_gen = HoneypotConfigGenerator(Config.OUTPUT_DIR)
        configs = config_gen.generate_config(clusters)
        config_file = config_gen.save_configs(configs)
        logger.info(f"Generated {len(configs)} honeypot configurations")
        
        # 4. Deploy honeypots to T-Pot
        logger.info("Deploying honeypots to T-Pot...")
        deployer = TPotDeployer(Config.TPOT_DIR)
        success = await deployer.deploy_honeypots(config_file)
        
        if success:
            logger.info("Honeypots deployed successfully!")
            
            # Get honeypot status
            status = deployer.get_honeypot_status()
            logger.info("T-Pot honeypot status:")
            for name, info in status.items():
                logger.info(f"  {name}: {info['status']}")
        else:
            logger.error("Failed to deploy honeypots")
            
    except Exception as e:
        logger.error(f"System error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())