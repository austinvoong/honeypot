#!/usr/bin/env python3
"""
Honeypot Analysis Tool for T-Pot

This script connects to your T-Pot instance, extracts data from the Elasticsearch database,
and provides comprehensive analysis of attack patterns, similar to Zhang and Shi's research.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple

import aiohttp
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from elasticsearch import Elasticsearch
from pandas.plotting import register_matplotlib_converters

# Register converters for matplotlib date plotting
register_matplotlib_converters()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HoneypotAnalyzer:
    """Analyzer for T-Pot honeypot data"""
    
    def __init__(self, host: str, port: int = 64298, username: str = None, password: str = None):
        """
        Initialize the honeypot analyzer
        
        Args:
            host: T-Pot hostname or IP
            port: Elasticsearch port (default: 64298)
            username: Elasticsearch username (optional)
            password: Elasticsearch password (optional)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        
        # Set up Elasticsearch client
        self.es_url = f"https://{host}:{port}"
        self.es = None
        
        # Initialize data containers
        self.attack_data = None
        self.output_dir = "honeypot_analysis_results"
        
    async def connect(self) -> bool:
        """Connect to Elasticsearch"""
        try:
            # Create output directory
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Connect to Elasticsearch
            logger.info(f"Connecting to Elasticsearch at {self.es_url}")
            
            # Set up authentication if provided
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)
            
            # Connect to Elasticsearch
            self.es = Elasticsearch(
                [self.es_url],
                basic_auth=auth,
                verify_certs=False,  # T-Pot typically uses self-signed certs
                ssl_show_warn=False
            )
            
            # Check connection
            if not self.es.ping():
                logger.error("Connection to Elasticsearch failed")
                return False
                
            logger.info("Successfully connected to Elasticsearch")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {str(e)}")
            return False
            
    async def fetch_data(self, days_back: int = 7) -> bool:
        """
        Fetch honeypot data from Elasticsearch
        
        Args:
            days_back: Number of days to look back
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Fetching data from the last {days_back} days")
            
            # Calculate time range
            now = datetime.now()
            start_time = now - timedelta(days=days_back)
            
            # Fetch data from Elasticsearch
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
                                        "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 10000  # Adjust based on expected data volume
            }
            
            # Get the list of indices
            indices = self.es.indices.get("*")
            logger.info(f"Found {len(indices)} indices")
            
            all_data = []
            
            # Process each relevant index
            for index_name in indices:
                # Skip system indices
                if index_name.startswith("."):
                    continue
                    
                logger.info(f"Querying index: {index_name}")
                
                # Execute the query
                response = self.es.search(
                    index=index_name,
                    body=query
                )
                
                # Process hits
                hits = response.get("hits", {}).get("hits", [])
                logger.info(f"Found {len(hits)} hits in {index_name}")
                
                # Add to the data collection
                all_data.extend(hits)
            
            # Convert to DataFrame for easier analysis
            logger.info(f"Processing {len(all_data)} total events")
            
            if not all_data:
                logger.warning("No data found in Elasticsearch")
                return False
                
            # Extract relevant fields and normalize
            processed_data = []
            for hit in all_data:
                source = hit.get("_source", {})
                index = hit.get("_index", "unknown")
                
                # Extract timestamp
                timestamp = source.get("@timestamp", "")
                
                # Determine honeypot type from index name
                honeypot_type = self._extract_honeypot_type(index)
                
                # Get source IP
                src_ip = self._extract_source_ip(source)
                
                # Get destination port
                dest_port = self._extract_destination_port(source)
                
                # Extract attack details
                attack_type = self._extract_attack_type(source, index)
                
                # Extract protocol
                protocol = self._extract_protocol(source)
                
                # Get country information
                country = self._extract_country(source)
                
                # Convert timestamp to datetime
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    dt = datetime.now()  # Fallback
                
                # Add to processed data
                processed_data.append({
                    "timestamp": dt,
                    "honeypot_type": honeypot_type,
                    "src_ip": src_ip,
                    "dest_port": dest_port,
                    "attack_type": attack_type,
                    "protocol": protocol,
                    "country": country,
                    "index": index
                })
            
            # Convert to DataFrame
            self.attack_data = pd.DataFrame(processed_data)
            
            # Save to CSV for reference
            csv_path = os.path.join(self.output_dir, "attack_data.csv")
            self.attack_data.to_csv(csv_path, index=False)
            logger.info(f"Data saved to {csv_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch data: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False
            
    def _extract_honeypot_type(self, index_name: str) -> str:
        """Extract honeypot type from index name"""
        # Common honeypot names in T-Pot
        honeypot_patterns = {
            "cowrie": "ssh",
            "dionaea": "multipurpose",
            "honeytrap": "multipurpose",
            "tanner": "web",
            "heralding": "auth",
            "ciscoasa": "cisco",
            "conpot": "industrial",
            "elasticpot": "elastic",
            "mailoney": "smtp",
            "rdpy": "rdp",
            "adbhoney": "adb",
            "fatt": "tls",
            "ipphoney": "printer",
            "medpot": "medical"
        }
        
        for pattern, htype in honeypot_patterns.items():
            if pattern in index_name.lower():
                return pattern
                
        # For dynamic honeypots (using our system)
        if "dyn_" in index_name.lower():
            parts = index_name.split("_")
            if len(parts) >= 2:
                return parts[1]  # The honeypot type follows dyn_
                
        return "unknown"
        
    def _extract_source_ip(self, source: Dict) -> str:
        """Extract source IP from event data"""
        # Try common field names
        candidates = [
            "src_ip", "srcip", "source.ip", "src", "source", 
            "source_ip", "remote_host", "remote.host", "remote.ip",
            "client_ip", "client.ip"
        ]
        
        for field in candidates:
            # Handle nested fields
            if "." in field:
                parts = field.split(".")
                value = source
                for part in parts:
                    value = value.get(part, {})
                if value and isinstance(value, str):
                    return value
            else:
                value = source.get(field)
                if value and isinstance(value, str):
                    return value
                    
        return "unknown"
        
    def _extract_destination_port(self, source: Dict) -> int:
        """Extract destination port from event data"""
        # Try common field names
        candidates = [
            "dest_port", "dstport", "destination.port", "dst_port",
            "port", "target_port", "target.port", "local_port",
            "local.port", "service_port"
        ]
        
        for field in candidates:
            # Handle nested fields
            if "." in field:
                parts = field.split(".")
                value = source
                for part in parts:
                    value = value.get(part, {})
                if value and (isinstance(value, int) or (isinstance(value, str) and value.isdigit())):
                    return int(value)
            else:
                value = source.get(field)
                if value and (isinstance(value, int) or (isinstance(value, str) and value.isdigit())):
                    return int(value)
                    
        return 0
        
    def _extract_attack_type(self, source: Dict, index: str) -> str:
        """Extract attack type from event data"""
        # Cowrie-specific fields
        if "cowrie" in index:
            if source.get("eventid") == "cowrie.login.failed":
                return "failed_login"
            elif source.get("eventid") == "cowrie.login.success":
                return "successful_login"
            elif source.get("eventid") == "cowrie.command.input":
                return "command_execution"
            elif source.get("eventid") == "cowrie.session.file_download":
                return "file_download"
                
        # Dionaea-specific fields
        if "dionaea" in index:
            if "smb" in str(source):
                return "smb_attack"
            elif "dcerpc" in str(source):
                return "dcerpc_attack"
            elif "mssql" in str(source):
                return "mssql_attack"
            elif "mysql" in str(source):
                return "mysql_attack"
                
        # Generic attack type detection
        if "attack_type" in source:
            return source["attack_type"]
            
        if "attack" in source:
            return source["attack"]
            
        if "type" in source:
            return source["type"]
            
        # Look for suspicious commands
        commands = []
        for field in ["command", "input", "payload"]:
            if field in source and isinstance(source[field], str):
                commands.append(source[field])
                
        if commands:
            # Detect common attack patterns
            command_str = " ".join(commands).lower()
            if any(x in command_str for x in ["wget", "curl", "http://", "https://"]):
                return "download_attack"
            if "chmod" in command_str and any(x in command_str for x in ["777", "755", "x"]):
                return "permission_change"
            if any(x in command_str for x in ["bot", "ddos", "flood"]):
                return "botnet_activity"
                
        return "generic_attack"
        
    def _extract_protocol(self, source: Dict) -> str:
        """Extract protocol from event data"""
        # Try common field names
        candidates = [
            "protocol", "proto", "service", "transport_protocol",
            "transport.protocol", "network_protocol", "network.protocol"
        ]
        
        for field in candidates:
            # Handle nested fields
            if "." in field:
                parts = field.split(".")
                value = source
                for part in parts:
                    value = value.get(part, {})
                if value and isinstance(value, str):
                    return value.lower()
            else:
                value = source.get(field)
                if value and isinstance(value, str):
                    return value.lower()
                    
        # Infer from service port
        port = self._extract_destination_port(source)
        if port == 22 or port == 2222:
            return "ssh"
        elif port == 23 or port == 2323:
            return "telnet"
        elif port == 80 or port == 8080:
            return "http"
        elif port == 443 or port == 8443:
            return "https"
        elif port == 21:
            return "ftp"
        elif port == 25:
            return "smtp"
        elif port == 3306:
            return "mysql"
        elif port == 5432:
            return "postgresql"
        elif port == 1433:
            return "mssql"
            
        return "unknown"
        
    def _extract_country(self, source: Dict) -> str:
        """Extract country information from event data"""
        # Try common field names
        candidates = [
            "geoip.country_name", "country_name", "country", 
            "geoip.country", "geo.country", "geo.country_name"
        ]
        
        for field in candidates:
            # Handle nested fields
            if "." in field:
                parts = field.split(".")
                value = source
                for part in parts:
                    value = value.get(part, {})
                if value and isinstance(value, str):
                    return value
            else:
                value = source.get(field)
                if value and isinstance(value, str):
                    return value
                    
        return "unknown"
        
    async def analyze(self) -> bool:
        """Perform comprehensive analysis on the fetched data"""
        if self.attack_data is None or self.attack_data.empty:
            logger.error("No data available for analysis")
            return False
            
        try:
            logger.info("Starting analysis of attack data")
            
            # Create analysis output directory
            analysis_dir = os.path.join(self.output_dir, "analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # 1. Time-based analysis
            await self._analyze_time_patterns(analysis_dir)
            
            # 2. Attacker analysis
            await self._analyze_attackers(analysis_dir)
            
            # 3. Protocol and service analysis
            await self._analyze_protocols(analysis_dir)
            
            # 4. Attack type analysis
            await self._analyze_attack_types(analysis_dir)
            
            # 5. Geographic analysis
            await self._analyze_geographic(analysis_dir)
            
            # 6. Generate summary report
            await self._generate_summary_report(analysis_dir)
            
            logger.info(f"Analysis complete. Results saved to {analysis_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False
            
    async def _analyze_time_patterns(self, output_dir: str):
        """Analyze time-based patterns in attacks"""
        logger.info("Analyzing time-based attack patterns")
        
        # Ensure timestamp is in datetime format
        self.attack_data['timestamp'] = pd.to_datetime(self.attack_data['timestamp'])
        
        # Create hourly attack distribution
        plt.figure(figsize=(15, 8))
        
        # Group by hour
        hourly_attacks = self.attack_data.groupby(self.attack_data['timestamp'].dt.hour).size()
        
        # Plot hourly distribution
        plt.subplot(2, 2, 1)
        hourly_attacks.plot(kind='bar', color='skyblue')
        plt.title('Attacks by Hour of Day')
        plt.xlabel('Hour')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=0)
        
        # Plot daily distribution
        plt.subplot(2, 2, 2)
        daily_attacks = self.attack_data.groupby(self.attack_data['timestamp'].dt.date).size()
        daily_attacks.plot(kind='line', marker='o', color='coral')
        plt.title('Attacks by Day')
        plt.xlabel('Date')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        
        # Plot weekly pattern
        plt.subplot(2, 2, 3)
        weekly_attacks = self.attack_data.groupby(self.attack_data['timestamp'].dt.day_name()).size()
        # Reorder days of week
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        weekly_attacks = weekly_attacks.reindex(days_order)
        weekly_attacks.plot(kind='bar', color='lightgreen')
        plt.title('Attacks by Day of Week')
        plt.xlabel('Day')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        
        # Plot honeypot comparison over time
        plt.subplot(2, 2, 4)
        honeypot_daily = self.attack_data.pivot_table(
            index=self.attack_data['timestamp'].dt.date,
            columns='honeypot_type',
            aggfunc='size',
            fill_value=0
        )
        
        # Only include top 5 honeypots for readability
        top_honeypots = self.attack_data['honeypot_type'].value_counts().nlargest(5).index
        honeypot_daily[top_honeypots].plot(marker='o')
        plt.title('Top 5 Honeypots Attack Trends')
        plt.xlabel('Date')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'time_patterns.png'), dpi=300)
        plt.close()
        
        # Additional time-based analysis - Heatmap of attacks by hour and day
        plt.figure(figsize=(12, 8))
        
        # Create a pivot table for the heatmap
        heatmap_data = self.attack_data.pivot_table(
            index=self.attack_data['timestamp'].dt.day_name(),
            columns=self.attack_data['timestamp'].dt.hour,
            aggfunc='size',
            fill_value=0
        )
        
        # Reorder days
        heatmap_data = heatmap_data.reindex(days_order)
        
        # Plot heatmap
        sns.heatmap(heatmap_data, cmap='YlOrRd', linewidths=.5)
        plt.title('Attack Heatmap by Hour and Day of Week')
        plt.xlabel('Hour of Day')
        plt.ylabel('Day of Week')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'time_heatmap.png'), dpi=300)
        plt.close()
        
        # Hourly analysis data
        hourly_analysis = pd.DataFrame({
            'hour': hourly_attacks.index,
            'attacks': hourly_attacks.values
        })
        hourly_analysis.to_csv(os.path.join(output_dir, 'hourly_attacks.csv'), index=False)
        
        # Daily analysis data
        daily_analysis = pd.DataFrame({
            'date': daily_attacks.index,
            'attacks': daily_attacks.values
        })
        daily_analysis.to_csv(os.path.join(output_dir, 'daily_attacks.csv'), index=False)
        
    async def _analyze_attackers(self, output_dir: str):
        """Analyze attacker patterns"""
        logger.info("Analyzing attacker patterns")
        
        # Top attackers by number of attacks
        top_attackers = self.attack_data['src_ip'].value_counts().nlargest(20)
        
        plt.figure(figsize=(12, 8))
        top_attackers.plot(kind='bar', color='tomato')
        plt.title('Top 20 Attacker IPs')
        plt.xlabel('IP Address')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=90)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'top_attackers.png'), dpi=300)
        plt.close()
        
        # Analyze attacker behavior patterns
        attacker_behavior = self.attack_data.groupby('src_ip')['attack_type'].value_counts().unstack().fillna(0)
        
        # Only include top 10 attackers for readability
        top_10_ips = top_attackers.nlargest(10).index
        if not attacker_behavior.empty and len(top_10_ips) > 0:
            # Ensure all top IPs are in the behavior dataframe
            existing_ips = set(attacker_behavior.index).intersection(set(top_10_ips))
            if existing_ips:
                plt.figure(figsize=(15, 10))
                attacker_behavior.loc[existing_ips].plot(kind='bar', stacked=True)
                plt.title('Attack Types by Top 10 Attackers')
                plt.xlabel('IP Address')
                plt.ylabel('Number of Attacks')
                plt.xticks(rotation=90)
                plt.legend(loc='upper right')
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, 'attacker_behavior.png'), dpi=300)
                plt.close()
        
        # Analyze time patterns by attacker
        plt.figure(figsize=(12, 8))
        # For the top 5 attackers
        top_5_ips = top_attackers.nlargest(5).index
        for ip in top_5_ips:
            ip_data = self.attack_data[self.attack_data['src_ip'] == ip]
            if not ip_data.empty:
                ip_hourly = ip_data.groupby(ip_data['timestamp'].dt.hour).size()
                ip_hourly.plot(marker='o', label=f"IP: {ip}")
        
        plt.title('Attack Patterns by Hour for Top 5 Attackers')
        plt.xlabel('Hour of Day')
        plt.ylabel('Number of Attacks')
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'attacker_timing.png'), dpi=300)
        plt.close()
        
        # Honeypot targeting by attackers
        attacker_targets = self.attack_data.groupby('src_ip')['honeypot_type'].value_counts().unstack().fillna(0)
        
        # Save attacker data
        top_attackers_df = pd.DataFrame({
            'ip_address': top_attackers.index,
            'attack_count': top_attackers.values
        })
        top_attackers_df.to_csv(os.path.join(output_dir, 'top_attackers.csv'), index=False)
        
        if not attacker_targets.empty and len(top_10_ips) > 0:
            # Ensure all top IPs are in the targets dataframe
            existing_ips = set(attacker_targets.index).intersection(set(top_10_ips))
            if existing_ips:
                attacker_targets.loc[existing_ips].to_csv(os.path.join(output_dir, 'attacker_targets.csv'))
        
    async def _analyze_protocols(self, output_dir: str):
        """Analyze protocols and services targeted"""
        logger.info("Analyzing targeted protocols and services")
        
        # Protocols analysis
        protocol_counts = self.attack_data['protocol'].value_counts()
        
        plt.figure(figsize=(10, 6))
        protocol_counts.plot(kind='bar', color='lightblue')
        plt.title('Attacks by Protocol')
        plt.xlabel('Protocol')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'protocol_distribution.png'), dpi=300)
        plt.close()
        
        # Port analysis
        port_counts = self.attack_data['dest_port'].value_counts().nlargest(20)
        
        plt.figure(figsize=(12, 6))
        port_counts.plot(kind='bar', color='lightgreen')
        plt.title('Top 20 Targeted Ports')
        plt.xlabel('Port')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'port_distribution.png'), dpi=300)
        plt.close()
        
        # Protocol by honeypot type
        protocol_by_honeypot = self.attack_data.pivot_table(
            index='honeypot_type',
            columns='protocol',
            aggfunc='size',
            fill_value=0
        )
        
        if not protocol_by_honeypot.empty:
            plt.figure(figsize=(12, 8))
            protocol_by_honeypot.plot(kind='bar', stacked=True)
            plt.title('Protocols by Honeypot Type')
            plt.xlabel('Honeypot Type')
            plt.ylabel('Number of Attacks')
            plt.legend(title='Protocol')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'protocol_by_honeypot.png'), dpi=300)
            plt.close()
        
        # Save protocol data
        protocol_df = pd.DataFrame({
            'protocol': protocol_counts.index,
            'attack_count': protocol_counts.values
        })
        protocol_df.to_csv(os.path.join(output_dir, 'protocol_counts.csv'), index=False)
        
        port_df = pd.DataFrame({
            'port': port_counts.index,
            'attack_count': port_counts.values
        })
        port_df.to_csv(os.path.join(output_dir, 'port_counts.csv'), index=False)
        
    async def _analyze_attack_types(self, output_dir: str):
        """Analyze attack types"""
        logger.info("Analyzing attack types")
        
        # Attack type distribution
        attack_counts = self.attack_data['attack_type'].value_counts()
        
        plt.figure(figsize=(12, 8))
        attack_counts.plot(kind='bar', color='salmon')
        plt.title('Distribution of Attack Types')
        plt.xlabel('Attack Type')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=90)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'attack_types.png'), dpi=300)
        plt.close()
        
        # Attack types by honeypot
        attack_by_honeypot = self.attack_data.pivot_table(
            index='honeypot_type',
            columns='attack_type',
            aggfunc='size',
            fill_value=0
        )
        
        if not attack_by_honeypot.empty:
            plt.figure(figsize=(15, 10))
            attack_by_honeypot.plot(kind='bar', stacked=True)
            plt.title('Attack Types by Honeypot')
            plt.xlabel('Honeypot Type')
            plt.ylabel('Number of Attacks')
            plt.legend(title='Attack Type', loc='upper right')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'attack_by_honeypot.png'), dpi=300)
            plt.close()
        
        # Attack types over time
        plt.figure(figsize=(12, 8))
        
        # Get top 5 attack types
        top_attacks = attack_counts.nlargest(5).index
        
        # For each top attack type, plot trend over time
        for attack in top_attacks:
            attack_data = self.attack_data[self.attack_data['attack_type'] == attack]
            if not attack_data.empty:
                # Group by day
                attack_daily = attack_data.groupby(attack_data['timestamp'].dt.date).size()
                attack_daily.plot(marker='o', label=attack)
        
        plt.title('Top 5 Attack Types Over Time')
        plt.xlabel('Date')
        plt.ylabel('Number of Attacks')
        plt.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'attack_types_trend.png'), dpi=300)
        plt.close()
        
        # Save attack type data
        attack_df = pd.DataFrame({
            'attack_type': attack_counts.index,
            'count': attack_counts.values
        })
        attack_df.to_csv(os.path.join(output_dir, 'attack_types.csv'), index=False)
        
        if not attack_by_honeypot.empty:
            attack_by_honeypot.to_csv(os.path.join(output_dir, 'attack_by_honeypot.csv'))
        
    async def _analyze_geographic(self, output_dir: str):
        """Analyze geographic distribution of attacks"""
        logger.info("Analyzing geographic distribution of attacks")
        
        # Country distribution
        country_counts = self.attack_data['country'].value_counts().nlargest(20)
        
        plt.figure(figsize=(12, 8))
        country_counts.plot(kind='bar', color='purple')
        plt.title('Top 20 Countries of Origin')
        plt.xlabel('Country')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'country_distribution.png'), dpi=300)
        plt.close()
        
        # Attack types by country
        country_attack_types = self.attack_data.pivot_table(
            index='country',
            columns='attack_type',
            aggfunc='size',
            fill_value=0
        )
        
        # Filter for top 10 countries
        top_10_countries = country_counts.nlargest(10).index
        if not country_attack_types.empty and len(top_10_countries) > 0:
            # Ensure all top countries are in the dataframe
            existing_countries = set(country_attack_types.index).intersection(set(top_10_countries))
            if existing_countries:
                plt.figure(figsize=(15, 10))
                country_attack_types.loc[existing_countries].plot(kind='bar', stacked=True)
                plt.title('Attack Types by Top 10 Countries')
                plt.xlabel('Country')
                plt.ylabel('Number of Attacks')
                plt.legend(title='Attack Type', loc='upper right')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, 'country_attack_types.png'), dpi=300)
                plt.close()
        
        # Honeypot targeting by country
        country_honeypot = self.attack_data.pivot_table(
            index='country',
            columns='honeypot_type',
            aggfunc='size',
            fill_value=0
        )
        
        if not country_honeypot.empty and len(top_10_countries) > 0:
            # Ensure all top countries are in the dataframe
            existing_countries = set(country_honeypot.index).intersection(set(top_10_countries))
            if existing_countries:
                plt.figure(figsize=(15, 10))
                country_honeypot.loc[existing_countries].plot(kind='bar', stacked=True)
                plt.title('Honeypot Targeting by Top 10 Countries')
                plt.xlabel('Country')
                plt.ylabel('Number of Attacks')
                plt.legend(title='Honeypot Type', loc='upper right')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(os.path.join(output_dir, 'country_honeypot.png'), dpi=300)
                plt.close()
        
        # Save geographic data
        country_df = pd.DataFrame({
            'country': country_counts.index,
            'attack_count': country_counts.values
        })
        country_df.to_csv(os.path.join(output_dir, 'country_counts.csv'), index=False)
        
    async def _generate_summary_report(self, output_dir: str):
        """Generate a comprehensive summary report"""
        logger.info("Generating summary report")
        
        # Create report file
        report_path = os.path.join(output_dir, 'summary_report.html')
        
        # Calculate summary statistics
        total_attacks = len(self.attack_data)
        unique_attackers = self.attack_data['src_ip'].nunique()
        unique_countries = self.attack_data['country'].nunique()
        top_country = self.attack_data['country'].value_counts().idxmax()
        top_attacker = self.attack_data['src_ip'].value_counts().idxmax()
        top_protocol = self.attack_data['protocol'].value_counts().idxmax()
        top_attack_type = self.attack_data['attack_type'].value_counts().idxmax()
        top_honeypot = self.attack_data['honeypot_type'].value_counts().idxmax()
        
        # Time range
        min_date = self.attack_data['timestamp'].min().strftime('%Y-%m-%d')
        max_date = self.attack_data['timestamp'].max().strftime('%Y-%m-%d')
        
        # Prepare HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Honeypot Analysis Summary Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .summary-box {{ background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                .stat {{ display: inline-block; width: 30%; margin-bottom: 10px; }}
                .stat-value {{ font-weight: bold; font-size: 18px; }}
                .stat-label {{ font-size: 14px; color: #6c757d; }}
                .section {{ margin-bottom: 30px; }}
                img {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; }}
                .img-container {{ display: flex; flex-wrap: wrap; justify-content: space-between; }}
                .img-item {{ width: 48%; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Honeypot Analysis Summary Report</h1>
                <p>Analysis period: {min_date} to {max_date}</p>
                
                <div class="summary-box">
                    <h2>Key Statistics</h2>
                    <div class="stat">
                        <div class="stat-value">{total_attacks}</div>
                        <div class="stat-label">Total Attacks</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{unique_attackers}</div>
                        <div class="stat-label">Unique Attackers</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{unique_countries}</div>
                        <div class="stat-label">Countries of Origin</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{top_country}</div>
                        <div class="stat-label">Top Country</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{top_protocol}</div>
                        <div class="stat-label">Top Protocol</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{top_attack_type}</div>
                        <div class="stat-label">Top Attack Type</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Time-Based Analysis</h2>
                    <p>Analysis of attack patterns over time shows temporal distribution of attacks.</p>
                    <div class="img-container">
                        <div class="img-item">
                            <img src="time_patterns.png" alt="Time Patterns">
                            <p>Temporal distribution of attacks by hour, day, and week.</p>
                        </div>
                        <div class="img-item">
                            <img src="time_heatmap.png" alt="Time Heatmap">
                            <p>Heatmap showing attack intensity by hour and day of week.</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Attacker Analysis</h2>
                    <p>Analysis of attack sources, patterns, and behaviors.</p>
                    <div class="img-container">
                        <div class="img-item">
                            <img src="top_attackers.png" alt="Top Attackers">
                            <p>Top 20 attacker IP addresses by number of attacks.</p>
                        </div>
                        <div class="img-item">
                            <img src="attacker_timing.png" alt="Attacker Timing">
                            <p>Attack timing patterns for top attackers.</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Protocol & Service Analysis</h2>
                    <p>Analysis of targeted protocols, ports, and services.</p>
                    <div class="img-container">
                        <div class="img-item">
                            <img src="protocol_distribution.png" alt="Protocol Distribution">
                            <p>Distribution of attacks by protocol.</p>
                        </div>
                        <div class="img-item">
                            <img src="port_distribution.png" alt="Port Distribution">
                            <p>Top 20 targeted ports.</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Attack Type Analysis</h2>
                    <p>Analysis of different attack types and their distribution.</p>
                    <div class="img-container">
                        <div class="img-item">
                            <img src="attack_types.png" alt="Attack Types">
                            <p>Distribution of different attack types.</p>
                        </div>
                        <div class="img-item">
                            <img src="attack_types_trend.png" alt="Attack Types Trend">
                            <p>Trend of top attack types over time.</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Geographic Analysis</h2>
                    <p>Analysis of attack origins by country.</p>
                    <div class="img-container">
                        <div class="img-item">
                            <img src="country_distribution.png" alt="Country Distribution">
                            <p>Top 20 countries of attack origin.</p>
                        </div>
                        <div class="img-item">
                            <img src="country_attack_types.png" alt="Country Attack Types">
                            <p>Attack types by top countries.</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Honeypot Effectiveness</h2>
                    <p>Analysis of honeypot performance and attack capture.</p>
                    <table>
                        <tr>
                            <th>Honeypot Type</th>
                            <th>Attacks Captured</th>
                            <th>Unique Attackers</th>
                            <th>Top Attack Type</th>
                        </tr>
        """
        
        # Add honeypot effectiveness data
        honeypot_stats = self.attack_data.groupby('honeypot_type').agg({
            'src_ip': 'nunique',
            'attack_type': lambda x: x.value_counts().index[0] if len(x) > 0 else 'N/A'
        }).reset_index()
        
        honeypot_counts = self.attack_data['honeypot_type'].value_counts().reset_index()
        honeypot_counts.columns = ['honeypot_type', 'count']
        
        honeypot_stats = honeypot_stats.merge(honeypot_counts, on='honeypot_type')
        
        for _, row in honeypot_stats.iterrows():
            html_content += f"""
                        <tr>
                            <td>{row['honeypot_type']}</td>
                            <td>{row['count']}</td>
                            <td>{row['src_ip']}</td>
                            <td>{row['attack_type']}</td>
                        </tr>
            """
        
        html_content += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>Conclusions</h2>
                    <p>Based on the analysis, we can draw the following conclusions:</p>
                    <ul>
                        <li>The most active attack sources are concentrated in a few countries.</li>
                        <li>There are distinct patterns in attack timing, with certain hours showing higher activity.</li>
                        <li>Different honeypot types are effective at capturing different attack types.</li>
                        <li>Regular monitoring and analysis of honeypot data can provide valuable insights into current attack trends.</li>
                    </ul>
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    <p>Based on the analysis, we recommend:</p>
                    <ul>
                        <li>Focus defenses on the most common attack vectors identified.</li>
                        <li>Enhance security during peak attack hours.</li>
                        <li>Deploy additional honeypots targeting the most common attack types.</li>
                        <li>Regularly update firewall rules to block persistent attackers.</li>
                        <li>Continuously monitor for new attack patterns and adapt defenses accordingly.</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write HTML report
        with open(report_path, 'w') as f:
            f.write(html_content)
            
        logger.info(f"Summary report generated at {report_path}")

async def main():
    """Main function"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='T-Pot Honeypot Analyzer')
    parser.add_argument('--host', type=str, required=True, help='T-Pot hostname or IP')
    parser.add_argument('--port', type=int, default=64298, help='Elasticsearch port (default: 64298)')
    parser.add_argument('--username', type=str, help='Elasticsearch username (optional)')
    parser.add_argument('--password', type=str, help='Elasticsearch password (optional)')
    parser.add_argument('--days', type=int, default=7, help='Number of days to analyze (default: 7)')
    parser.add_argument('--output', type=str, default='honeypot_analysis_results', help='Output directory (default: honeypot_analysis_results)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
    
    try:
        # Create analyzer
        analyzer = HoneypotAnalyzer(args.host, args.port, args.username, args.password)
        analyzer.output_dir = args.output
        
        # Connect to Elasticsearch
        if not await analyzer.connect():
            logger.error("Failed to connect to Elasticsearch. Exiting.")
            return 1
            
        # Fetch data
        if not await analyzer.fetch_data(args.days):
            logger.error("Failed to fetch data. Exiting.")
            return 1
            
        # Analyze data
        if not await analyzer.analyze():
            logger.error("Analysis failed. Exiting.")
            return 1
            
        logger.info(f"Analysis complete. Results saved to {analyzer.output_dir}")
        logger.info(f"Open {os.path.join(analyzer.output_dir, 'analysis/summary_report.html')} to view the report")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.debug:
            import traceback
            logger.error(traceback.format_exc())
        return 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))