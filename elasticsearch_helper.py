#!/usr/bin/env python3
"""
Elasticsearch Helper for T-Pot

This script helps verify and explore your T-Pot Elasticsearch instance,
making it easier to understand what data is available and how to access it.
"""

import argparse
import json
import ssl
import sys
from datetime import datetime, timedelta

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from tabulate import tabulate
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure HTTPS warnings (T-Pot typically uses self-signed certs)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ElasticsearchHelper:
    """Helper class for exploring a T-Pot Elasticsearch instance"""

    def __init__(self, host: str, port: int = 64298, username: str = None, password: str = None):
        """
        Initialize the Elasticsearch helper
        
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
        
        # Base URL for Elasticsearch API
        self.base_url = f"https://{host}:{port}"
        
        # Authentication
        self.auth = None
        if username and password:
            self.auth = HTTPBasicAuth(username, password)
    
    def check_connection(self) -> bool:
        """Check if Elasticsearch is accessible"""
        try:
            response = requests.get(
                f"{self.base_url}",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                print("Successfully connected to Elasticsearch!")
                print(f"Elasticsearch Info: {response.json()}")
                return True
            else:
                print(f"Failed to connect. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error connecting to Elasticsearch: {str(e)}")
            return False
    
    def list_indices(self) -> bool:
        """List all indices in Elasticsearch"""
        try:
            response = requests.get(
                f"{self.base_url}/_cat/indices?v",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code == 200:
                print("Elasticsearch Indices:")
                print(response.text)
                return True
            else:
                print(f"Failed to retrieve indices. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error retrieving indices: {str(e)}")
            return False
    
    def explore_index(self, index_name: str) -> bool:
        """Explore a specific index in detail"""
        try:
            # Get index mappings
            response = requests.get(
                f"{self.base_url}/{index_name}/_mapping",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                print(f"Failed to retrieve index mapping. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
            mappings = response.json()
            print(f"\nIndex Mapping for {index_name}:")
            print(json.dumps(mappings, indent=2))
            
            # Get sample documents
            response = requests.get(
                f"{self.base_url}/{index_name}/_search",
                json={
                    "size": 3,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                },
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                print(f"Failed to retrieve sample documents. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
            documents = response.json()
            print(f"\nSample Documents from {index_name}:")
            
            hits = documents.get('hits', {}).get('hits', [])
            if hits:
                for i, doc in enumerate(hits):
                    print(f"\nDocument {i+1}:")
                    print(json.dumps(doc.get('_source', {}), indent=2))
            else:
                print("No documents found in the index.")
            
            # Get index stats
            response = requests.get(
                f"{self.base_url}/{index_name}/_stats",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                print(f"Failed to retrieve index stats. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
            stats = response.json()
            print(f"\nIndex Stats for {index_name}:")
            
            # Extract relevant stats
            index_stats = stats.get('indices', {}).get(index_name, {}).get('total', {})
            docs = index_stats.get('docs', {})
            store = index_stats.get('store', {})
            
            print(f"  Documents: {docs.get('count', 'N/A')}")
            print(f"  Size: {store.get('size_in_bytes', 'N/A')} bytes")
            
            return True
                
        except Exception as e:
            print(f"Error exploring index: {str(e)}")
            return False
    
    def search_recent_events(self, index_pattern: str = "*", time_range: int = 24) -> bool:
        """
        Search for recent events across indices
        
        Args:
            index_pattern: Index pattern to search (default: all indices)
            time_range: Time range in hours (default: 24 hours)
        """
        try:
            # Calculate time range
            now = datetime.now()
            start_time = now - timedelta(hours=time_range)
            
            # Format for Elasticsearch
            start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
            now_str = now.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Search query
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time_str,
                                        "lte": now_str
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 100  # Limit results
            }
            
            # Execute search
            response = requests.get(
                f"{self.base_url}/{index_pattern}/_search",
                json=query,
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                print(f"Failed to search events. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
            results = response.json()
            hits = results.get('hits', {}).get('hits', [])
            
            if not hits:
                print(f"No events found in the last {time_range} hours")
                return True
                
            # Process and display results
            print(f"\nFound {len(hits)} events in the last {time_range} hours")
            
            # Extract common fields for display
            event_data = []
            for hit in hits:
                source = hit.get('_source', {})
                index = hit.get('_index', 'unknown')
                
                # Extract timestamp
                timestamp = source.get('@timestamp', '')
                if timestamp:
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                
                # Extract IP and port information
                src_ip = self._find_field(source, ['src_ip', 'srcip', 'source.ip', 'src'])
                dest_port = self._find_field(source, ['dest_port', 'dstport', 'destination.port', 'port'])
                
                # Extract honeypot-specific fields
                honeypot_type = self._extract_honeypot_type(index)
                
                # Get a summary or relevant information
                summary = self._get_event_summary(source, honeypot_type)
                
                event_data.append([
                    timestamp,
                    honeypot_type,
                    src_ip,
                    dest_port,
                    summary
                ])
            
            # Display as table
            headers = ["Timestamp", "Honeypot", "Source IP", "Dest Port", "Summary"]
            print(tabulate(event_data, headers=headers, tablefmt="grid"))
            
            return True
                
        except Exception as e:
            print(f"Error searching events: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False
    
    def _find_field(self, data: dict, field_candidates: list) -> str:
        """Find a field in the data using multiple candidate field names"""
        for field in field_candidates:
            # Handle nested fields
            if "." in field:
                parts = field.split(".")
                value = data
                for part in parts:
                    value = value.get(part, {})
                if value and not isinstance(value, dict):
                    return str(value)
            else:
                if field in data and data[field] and not isinstance(data[field], dict):
                    return str(data[field])
        
        return "N/A"
    
    def _extract_honeypot_type(self, index_name: str) -> str:
        """Extract honeypot type from index name"""
        # Common honeypot names in T-Pot
        honeypot_patterns = [
            "cowrie", "dionaea", "honeytrap", "tanner", "heralding", 
            "ciscoasa", "conpot", "elasticpot", "mailoney", "rdpy",
            "adbhoney", "fatt", "ipphoney", "medpot"
        ]
        
        for pattern in honeypot_patterns:
            if pattern in index_name.lower():
                return pattern
                
        # For dynamic honeypots
        if "dyn_" in index_name.lower():
            parts = index_name.split("_")
            if len(parts) >= 2:
                return parts[1]  # The honeypot type follows dyn_
                
        return "unknown"
    
    def _get_event_summary(self, source: dict, honeypot_type: str) -> str:
        """Generate a summary of the event based on honeypot type"""
        # Cowrie-specific summary
        if honeypot_type == "cowrie":
            if source.get('eventid') == "cowrie.login.failed":
                return f"Failed login: {source.get('username', 'N/A')}/{source.get('password', 'N/A')}"
            elif source.get('eventid') == "cowrie.login.success":
                return f"Successful login: {source.get('username', 'N/A')}/{source.get('password', 'N/A')}"
            elif source.get('eventid') == "cowrie.command.input":
                return f"Command: {source.get('input', 'N/A')}"
            elif source.get('eventid') == "cowrie.session.file_download":
                return f"File download: {source.get('url', 'N/A')}"
            else:
                return source.get('eventid', 'Unknown event')
        
        # Dionaea-specific summary
        elif honeypot_type == "dionaea":
            if "smb" in str(source):
                return "SMB attack"
            elif "dcerpc" in str(source):
                return "DCERPC attack"
            elif "mssql" in str(source):
                return "MSSQL attack"
            elif "mysql" in str(source):
                return "MySQL attack"
            else:
                return "Generic attack"
        
        # Generic summary for other honeypots
        else:
            # Look for common fields that might contain useful information
            for field in ['attack_type', 'type', 'protocol', 'summary', 'description']:
                if field in source:
                    return str(source[field])
            
            # If nothing specific found, return a generic message
            return f"Activity detected on {honeypot_type}"
    
    def count_events_by_honeypot(self, time_range: int = 24) -> bool:
        """
        Count events by honeypot type
        
        Args:
            time_range: Time range in hours (default: 24 hours)
        """
        try:
            # Get all indices first
            response = requests.get(
                f"{self.base_url}/_cat/indices?format=json",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                print(f"Failed to retrieve indices. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
            indices = response.json()
            
            # Filter out system indices
            honeypot_indices = []
            for index in indices:
                index_name = index.get('index', '')
                if not index_name.startswith('.'):
                    honeypot_indices.append(index_name)
            
            # Calculate time range
            now = datetime.now()
            start_time = now - timedelta(hours=time_range)
            
            # Format for Elasticsearch
            start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
            now_str = now.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Collect counts for each honeypot type
            honeypot_counts = {}
            
            for index in honeypot_indices:
                # Determine honeypot type
                honeypot_type = self._extract_honeypot_type(index)
                
                # Search query to count events
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": start_time_str,
                                            "lte": now_str
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": 0  # We only want the count
                }
                
                # Execute search
                response = requests.get(
                    f"{self.base_url}/{index}/_count",
                    json=query,
                    auth=self.auth,
                    verify=False
                )
                
                if response.status_code != 200:
                    print(f"Failed to count events for {index}. Skipping.")
                    continue
                    
                count = response.json().get('count', 0)
                
                # Add to honeypot counts
                if honeypot_type in honeypot_counts:
                    honeypot_counts[honeypot_type] += count
                else:
                    honeypot_counts[honeypot_type] = count
            
            # Display results
            print(f"\nEvent Counts by Honeypot Type (Last {time_range} hours):")
            
            count_data = [[honeypot, count] for honeypot, count in honeypot_counts.items()]
            count_data.sort(key=lambda x: x[1], reverse=True)  # Sort by count, descending
            
            headers = ["Honeypot Type", "Event Count"]
            print(tabulate(count_data, headers=headers, tablefmt="grid"))
            
            # Calculate total
            total = sum(honeypot_counts.values())
            print(f"\nTotal Events: {total}")
            
            return True
                
        except Exception as e:
            print(f"Error counting events: {str(e)}")
            return False
    
    def list_top_attackers(self, time_range: int = 24, limit: int = 10):
        """
        List top attacker IPs
        
        Args:
            time_range: Time range in hours (default: 24 hours)
            limit: Number of top attackers to show (default: 10)
        """
        try:
            # Calculate time range
            now = datetime.now()
            start_time = now - timedelta(hours=time_range)
            
            # Format for Elasticsearch
            start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
            now_str = now.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Aggregate query to find top attackers
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time_str,
                                        "lte": now_str
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 0,
                "aggs": {
                    "top_attackers": {
                        "terms": {
                            "field": "src_ip.keyword",
                            "size": limit
                        }
                    }
                }
            }
            
            # Execute search across all indices
            response = requests.get(
                f"{self.base_url}/*/_search",
                json=query,
                auth=self.auth,
                verify=False
            )
            
            if response.status_code != 200:
                # Try alternative field names
                query["aggs"]["top_attackers"]["terms"]["field"] = "source.ip.keyword"
                response = requests.get(
                    f"{self.base_url}/*/_search",
                    json=query,
                    auth=self.auth,
                    verify=False
                )
                
                if response.status_code != 200:
                    print(f"Failed to find top attackers. Status code: {response.status_code}")
                    print(f"Response: {response.text}")
                    return False
                    
            results = response.json()
            
            # Extract top attackers
            buckets = results.get('aggregations', {}).get('top_attackers', {}).get('buckets', [])
            
            if not buckets:
                print(f"No attackers found in the last {time_range} hours")
                return True
                
            # Display results
            print(f"\nTop {limit} Attackers (Last {time_range} hours):")
            
            attacker_data = []
            for bucket in buckets:
                ip = bucket.get('key', 'N/A')
                count = bucket.get('doc_count', 0)
                attacker_data.append([ip, count])
            
            headers = ["IP Address", "Attack Count"]
            print(tabulate(attacker_data, headers=headers, tablefmt="grid"))
            
            return True
                
        except Exception as e:
            print(f"Error finding top attackers: {str(e)}")
            return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='T-Pot Elasticsearch Helper')
    parser.add_argument('--host', type=str, required=True, help='T-Pot hostname or IP')
    parser.add_argument('--port', type=int, default=64298, help='Elasticsearch port (default: 64298)')
    parser.add_argument('--username', type=str, help='Elasticsearch username (optional)')
    parser.add_argument('--password', type=str, help='Elasticsearch password (optional)')
    parser.add_argument('--check', action='store_true', help='Check Elasticsearch connection')
    parser.add_argument('--indices', action='store_true', help='List all indices')
    parser.add_argument('--explore', type=str, help='Explore a specific index')
    parser.add_argument('--recent', action='store_true', help='Show recent events')
    parser.add_argument('--hours', type=int, default=24, help='Time range in hours (default: 24)')
    parser.add_argument('--counts', action='store_true', help='Count events by honeypot type')
    parser.add_argument('--attackers', action='store_true', help='List top attackers')
    parser.add_argument('--limit', type=int, default=10, help='Limit for top listings (default: 10)')
    
    args = parser.parse_args()
    
    # Create helper
    helper = ElasticsearchHelper(
        args.host, 
        args.port, 
        args.username, 
        args.password
    )
    
    # Execute requested actions
    if args.check:
        helper.check_connection()
        
    if args.indices:
        helper.list_indices()
        
    if args.explore:
        helper.explore_index(args.explore)
        
    if args.recent:
        helper.search_recent_events(time_range=args.hours)
        
    if args.counts:
        helper.count_events_by_honeypot(time_range=args.hours)
        
    if args.attackers:
        helper.list_top_attackers(time_range=args.hours, limit=args.limit)
        
    # If no specific action requested, show help
    if not (args.check or args.indices or args.explore or args.recent or args.counts or args.attackers):
        parser.print_help()


if __name__ == '__main__':
    main()