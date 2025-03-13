#honeypot-proj/honeypot_analyzer/__main__.py
import argparse
import asyncio
import json
import re
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class HoneypotLogAnalyzer:
    """Analyzes logs from various honeypots to determine attacker engagement depth"""
    
    def __init__(self, remote=False, host=None, port=64295, user=None, password=None, key_path=None, 
                 debug=False, output_dir="honeypot_analysis"):
        self.remote = remote
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_path = key_path
        self.debug = debug
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Setup logging
        self.log(f"Initializing Honeypot Log Analyzer", level="INFO")
        if self.debug:
            self.log("Debug mode enabled", level="DEBUG")
            
        # Define honeypot types and their log patterns
        self.honeypot_patterns = {
            "cowrie": {
                "login_attempt": r"login attempt \[(?P<username>.*?)/(?P<password>.*?)\]",
                "command_executed": r"Command found: (?P<command>.*)",
                "file_download": r"Saved (?P<url>.*) to (?P<file>.*)",
                "session_started": r"New connection: (?P<src_ip>[\d\.]+):(?P<src_port>\d+)",
                "session_closed": r"Connection lost after (?P<duration>\d+) seconds"
            },
            "dionaea": {
                "connection": r"connection: (?P<protocol>\w+) connection from (?P<src_ip>[\d\.]+):(?P<src_port>\d+)",
                "exploit_attempt": r"(?i)exploit|shellcode|payload",
                "malware_download": r"dionaea_binary_fetch.url (?P<url>.*)",
                "smb_attack": r"SMB (?P<action>\w+)"
            },
            "honeytrap": {
                "connection": r"connection from (?P<src_ip>[\d\.]+):(?P<src_port>\d+)",
                "attack_detected": r"attack (?P<attack_type>\w+) detected",
                "payload_detected": r"payload detected: (?P<payload>.*)"
            },
            "heralding": {
                "login_attempt": r"auth attempt \[(?P<username>.*?)/(?P<password>.*?)\]",
                "connection": r"Connection from (?P<src_ip>[\d\.]+):(?P<src_port>\d+)"
            },
            "adbhoney": {
                "connection": r"Incoming connection from (?P<src_ip>[\d\.]+):(?P<src_port>\d+)",
                "command_executed": r"command executed: (?P<command>.*)"
            },
            "conpot": {
                "connection": r"New connection from (?P<src_ip>[\d\.]+):(?P<src_port>\d+)",
                "request": r"(?P<protocol>\w+) request from (?P<src_ip>[\d\.]+)"
            }
        }
        
    def log(self, message, level="INFO"):
        """Log a message with the specified level"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if level == "ERROR":
            print(f"{Colors.RED}[{timestamp}] ERROR: {message}{Colors.ENDC}")
        elif level == "WARNING":
            print(f"{Colors.WARNING}[{timestamp}] WARNING: {message}{Colors.ENDC}")
        elif level == "DEBUG" and self.debug:
            print(f"{Colors.BLUE}[{timestamp}] DEBUG: {message}{Colors.ENDC}")
        elif level == "SUCCESS":
            print(f"{Colors.GREEN}[{timestamp}] SUCCESS: {message}{Colors.ENDC}")
        else:
            print(f"[{timestamp}] INFO: {message}")
    
    async def run_ssh_command(self, command, use_sudo=False):
        """Run a command on the remote T-Pot server via SSH"""
        if not self.remote:
            self.log(f"Not in remote mode, executing locally: {command}", level="DEBUG")
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0, stdout.decode(), stderr.decode()
        
        # Build the SSH command
        ssh_cmd = ['ssh']
        if self.port:
            ssh_cmd.extend(['-p', str(self.port)])
        
        if self.key_path:
            ssh_cmd.extend(['-i', self.key_path])
        
        ssh_cmd.extend(['-o', 'StrictHostKeyChecking=no'])
        ssh_cmd.append(f"{self.user}@{self.host}")
        
        # Add sudo if needed
        if use_sudo:
            if self.password:
                full_command = f"echo '{self.password}' | sudo -S {command}"
            else:
                full_command = f"sudo {command}"
        else:
            full_command = command
        
        ssh_cmd.append(full_command)
        
        self.log(f"Running SSH command: {' '.join(ssh_cmd)}", level="DEBUG")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            success = process.returncode == 0
            stdout_str = stdout.decode('utf-8')
            stderr_str = stderr.decode('utf-8')
            
            if not success:
                self.log(f"Command failed with exit code {process.returncode}", level="ERROR")
                self.log(f"Error output: {stderr_str}", level="ERROR")
                
            return success, stdout_str, stderr_str
            
        except Exception as e:
            self.log(f"Failed to run command: {str(e)}", level="ERROR")
            return False, "", str(e)
    
    async def get_running_honeypots(self):
        """Get a list of all running honeypot containers"""
        command = "docker ps | grep -E 'dyn_|tpot_' | awk '{print $1, $2}'"
        success, stdout, stderr = await self.run_ssh_command(command, use_sudo=True)
        
        if not success:
            self.log("Failed to get running honeypots", level="ERROR")
            return []
        
        honeypots = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                container_id = parts[0]
                image = parts[1]
                
                # Determine honeypot type from image name
                honeypot_type = None
                for hp_type in self.honeypot_patterns.keys():
                    if hp_type in image.lower():
                        honeypot_type = hp_type
                        break
                
                if honeypot_type:
                    honeypots.append({
                        "container_id": container_id,
                        "image": image,
                        "type": honeypot_type
                    })
        
        self.log(f"Found {len(honeypots)} running honeypot containers", level="INFO")
        return honeypots
    
    async def get_container_logs(self, container_id, tail=1000):
        """Get logs from a specific container"""
        command = f"docker logs --tail {tail} {container_id}"
        success, stdout, stderr = await self.run_ssh_command(command, use_sudo=True)
        
        if not success:
            self.log(f"Failed to get logs for container {container_id}", level="ERROR")
            return []
            
        return stdout.splitlines()
    
    async def analyze_container(self, container):
        """Analyze logs from a specific container"""
        self.log(f"Analyzing {container['type']} container {container['container_id']}", level="INFO")
        
        logs = await self.get_container_logs(container['container_id'])
        if not logs:
            self.log(f"No logs found for container {container['container_id']}", level="WARNING")
            return None
            
        honeypot_type = container['type']
        patterns = self.honeypot_patterns.get(honeypot_type, {})
        
        if not patterns:
            self.log(f"No patterns defined for honeypot type {honeypot_type}", level="WARNING")
            return None
            
        results = {
            "container_id": container['container_id'],
            "honeypot_type": honeypot_type,
            "image": container['image'],
            "log_entries": len(logs),
            "events": defaultdict(list),
            "unique_ips": set(),
            "interaction_scores": [],
            "commands": Counter(),
            "usernames": Counter(),
            "passwords": Counter(),
            "urls": Counter(),
            "timestamps": []
        }
        
        for line in logs:
            # Extract timestamp if present
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                try:
                    timestamp = datetime.strptime(timestamp_match.group(1).replace('T', ' '), 
                                                "%Y-%m-%d %H:%M:%S")
                    results["timestamps"].append(timestamp)
                except ValueError:
                    pass
            
            # Check all patterns for this honeypot type
            for event_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    event_data = match.groupdict()
                    results["events"][event_type].append(event_data)
                    
                    # Extract and count specific data points
                    if 'src_ip' in event_data:
                        results["unique_ips"].add(event_data['src_ip'])
                        
                    if 'command' in event_data:
                        results["commands"][event_data['command']] += 1
                        
                    if 'username' in event_data:
                        results["usernames"][event_data['username']] += 1
                        
                    if 'password' in event_data:
                        results["passwords"][event_data['password']] += 1
                        
                    if 'url' in event_data:
                        results["urls"][event_data['url']] += 1
        
        # Calculate an interaction score (higher = more meaningful interaction)
        interaction_score = 0
        
        # Basic connections (low value)
        connection_count = len(results["events"].get("connection", []))
        interaction_score += connection_count * 1
        
        # Login attempts (medium value)
        login_attempts = len(results["events"].get("login_attempt", []))
        interaction_score += login_attempts * 2
        
        # Command execution (high value)
        commands_executed = len(results["events"].get("command_executed", []))
        interaction_score += commands_executed * 10
        
        # File downloads/malware (highest value)
        file_downloads = len(results["events"].get("file_download", [])) + len(results["events"].get("malware_download", []))
        interaction_score += file_downloads * 25
        
        # Exploit attempts (high value)
        exploit_attempts = len(results["events"].get("exploit_attempt", []))
        interaction_score += exploit_attempts * 15
        
        results["interaction_score"] = interaction_score
        results["unique_ip_count"] = len(results["unique_ips"])
        results["unique_ips"] = list(results["unique_ips"])  # Convert set to list for JSON serialization
        
        # Determine engagement level
        if interaction_score == 0:
            engagement_level = "None"
        elif interaction_score < 10:
            engagement_level = "Low (scanning only)"
        elif interaction_score < 50:
            engagement_level = "Medium (authentication attempts)"
        elif interaction_score < 200:
            engagement_level = "High (active exploitation)"
        else:
            engagement_level = "Critical (successful compromise attempt)"
            
        results["engagement_level"] = engagement_level
        
        self.log(f"Container {container['container_id']} analysis complete. Interaction score: {interaction_score}, Level: {engagement_level}", 
                 level="SUCCESS" if interaction_score > 0 else "INFO")
        
        return results
        
    async def analyze_all_honeypots(self):
        """Analyze logs from all running honeypot containers"""
        honeypots = await self.get_running_honeypots()
        if not honeypots:
            self.log("No honeypot containers found to analyze", level="WARNING")
            return {}
            
        results = []
        for honeypot in honeypots:
            container_results = await self.analyze_container(honeypot)
            if container_results:
                results.append(container_results)
                
        return results
    
    def generate_report(self, results):
        """Generate a comprehensive report of honeypot analysis results"""
        if not results:
            self.log("No results to generate report from", level="WARNING")
            return
            
        report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"honeypot_analysis_report_{report_time}.txt"
        json_file = self.output_dir / f"honeypot_analysis_data_{report_time}.json"
        
        # Save the full JSON data
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        self.log(f"Detailed JSON data saved to {json_file}", level="SUCCESS")
        
        # Create a text report
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("HONEYPOT INTERACTION ANALYSIS REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary section
            total_honeypots = len(results)
            total_score = sum(r["interaction_score"] for r in results)
            active_honeypots = sum(1 for r in results if r["interaction_score"] > 0)
            
            f.write(f"SUMMARY:\n")
            f.write(f"Total honeypots analyzed: {total_honeypots}\n")
            f.write(f"Honeypots with attacker interaction: {active_honeypots}\n")
            f.write(f"Total interaction score: {total_score}\n\n")
            
            # Detailed results by honeypot
            f.write("DETAILED ANALYSIS BY HONEYPOT:\n\n")
            
            # Sort by interaction score (highest first)
            for result in sorted(results, key=lambda x: x["interaction_score"], reverse=True):
                f.write("-" * 80 + "\n")
                f.write(f"Honeypot Type: {result['honeypot_type']}\n")
                f.write(f"Container ID: {result['container_id']}\n")
                f.write(f"Image: {result['image']}\n")
                f.write(f"Interaction Score: {result['interaction_score']}\n")
                f.write(f"Engagement Level: {result['engagement_level']}\n")
                f.write(f"Unique IPs: {result['unique_ip_count']}\n")
                f.write("\n")
                
                # Event details
                f.write("Activity Breakdown:\n")
                for event_type, events in result["events"].items():
                    if events:
                        f.write(f"  - {event_type}: {len(events)}\n")
                
                # Top commands (if any)
                if result["commands"]:
                    f.write("\nTop commands:\n")
                    for cmd, count in result["commands"].most_common(5):
                        f.write(f"  - {cmd}: {count}\n")
                
                # Top usernames (if any)
                if result["usernames"]:
                    f.write("\nTop usernames:\n")
                    for username, count in result["usernames"].most_common(5):
                        f.write(f"  - {username}: {count}\n")
                
                # Top passwords (if any)
                if result["passwords"]:
                    f.write("\nTop passwords:\n")
                    for password, count in result["passwords"].most_common(5):
                        f.write(f"  - {password}: {count}\n")
                
                f.write("\n")
                
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
        
        self.log(f"Report generated and saved to {report_file}", level="SUCCESS")
        return report_file, json_file
    
    def generate_visualizations(self, results):
        """Generate visualizations from the analysis results"""
        if not results:
            self.log("No results to generate visualizations from", level="WARNING")
            return
            
        # Create a timestamp for the visualization files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Interaction Score by Honeypot Type
        plt.figure(figsize=(10, 6))
        honeypot_types = [r["honeypot_type"] for r in results]
        interaction_scores = [r["interaction_score"] for r in results]
        
        df = pd.DataFrame({
            'Honeypot Type': honeypot_types,
            'Interaction Score': interaction_scores
        })
        
        # Aggregate by honeypot type
        summary_df = df.groupby('Honeypot Type')['Interaction Score'].sum().reset_index()
        summary_df = summary_df.sort_values('Interaction Score', ascending=False)
        
        plt.bar(summary_df['Honeypot Type'], summary_df['Interaction Score'], color='skyblue')
        plt.title('Interaction Score by Honeypot Type')
        plt.xlabel('Honeypot Type')
        plt.ylabel('Interaction Score')
        plt.tight_layout()
        
        # Save the plot
        score_plot_file = self.output_dir / f"interaction_score_by_type_{timestamp}.png"
        plt.savefig(score_plot_file)
        plt.close()
        
        # 2. Unique IPs by Honeypot
        plt.figure(figsize=(10, 6))
        unique_ips = [r["unique_ip_count"] for r in results]
        labels = [f"{r['honeypot_type']}-{r['container_id'][:6]}" for r in results]
        
        plt.bar(labels, unique_ips, color='coral')
        plt.title('Unique Attacker IPs by Honeypot')
        plt.xlabel('Honeypot')
        plt.ylabel('Unique IP Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save the plot
        ips_plot_file = self.output_dir / f"unique_ips_by_honeypot_{timestamp}.png"
        plt.savefig(ips_plot_file)
        plt.close()
        
        # 3. Engagement Level Distribution
        plt.figure(figsize=(10, 6))
        engagement_levels = [r["engagement_level"] for r in results]
        level_counts = Counter(engagement_levels)
        
        levels = list(level_counts.keys())
        counts = list(level_counts.values())
        
        plt.bar(levels, counts, color='lightgreen')
        plt.title('Honeypot Engagement Level Distribution')
        plt.xlabel('Engagement Level')
        plt.ylabel('Count')
        plt.tight_layout()
        
        # Save the plot
        engagement_plot_file = self.output_dir / f"engagement_level_distribution_{timestamp}.png"
        plt.savefig(engagement_plot_file)
        plt.close()
        
        # 4. Event Type Distribution
        plt.figure(figsize=(12, 7))
        
        # Collect all event types and counts
        event_counts = defaultdict(int)
        for result in results:
            for event_type, events in result["events"].items():
                event_counts[event_type] += len(events)
        
        event_types = list(event_counts.keys())
        counts = list(event_counts.values())
        
        # Sort by count
        sorted_indices = np.argsort(counts)[::-1]
        event_types = [event_types[i] for i in sorted_indices]
        counts = [counts[i] for i in sorted_indices]
        
        plt.bar(event_types, counts, color='plum')
        plt.title('Event Type Distribution Across All Honeypots')
        plt.xlabel('Event Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save the plot
        events_plot_file = self.output_dir / f"event_type_distribution_{timestamp}.png"
        plt.savefig(events_plot_file)
        plt.close()
        
        # 5. Time-based Activity (if timestamps available)
        # Collect all timestamps from all honeypots
        all_timestamps = []
        for result in results:
            all_timestamps.extend(result["timestamps"])
        
        if all_timestamps:
            plt.figure(figsize=(12, 7))
            
            # Convert to pandas datetime for easier manipulation
            ts_series = pd.Series(all_timestamps)
            
            # Resample by hour and count
            ts_df = pd.DataFrame({'timestamp': ts_series})
            ts_df['count'] = 1
            ts_df.set_index('timestamp', inplace=True)
            
            # Resample by hour
            hourly = ts_df.resample('H').sum()
            
            plt.plot(hourly.index, hourly['count'], marker='o', linestyle='-')
            plt.title('Honeypot Activity Over Time')
            plt.xlabel('Time')
            plt.ylabel('Event Count')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            
            # Save the plot
            time_plot_file = self.output_dir / f"activity_over_time_{timestamp}.png"
            plt.savefig(time_plot_file)
            plt.close()
            
            self.log(f"Time-based activity plot saved to {time_plot_file}", level="SUCCESS")
        
        self.log(f"Visualizations generated and saved to {self.output_dir}", level="SUCCESS")
        
        # Return the paths to the generated plots
        return {
            "interaction_score": score_plot_file,
            "unique_ips": ips_plot_file,
            "engagement_levels": engagement_plot_file,
            "event_types": events_plot_file,
            "time_activity": time_plot_file if all_timestamps else None
        }
        
    async def analyze(self):
        """Run the full analysis pipeline"""
        self.log("Starting analysis of honeypot logs", level="INFO")
        
        try:
            # Get and analyze all honeypot containers
            results = await self.analyze_all_honeypots()
            
            if not results:
                self.log("No honeypot data found to analyze", level="WARNING")
                return False
                
            # Generate report
            report_file, json_file = self.generate_report(results)
            
            # Generate visualizations
            visualization_files = self.generate_visualizations(results)
            
            self.log("=" * 80, level="INFO")
            self.log("ANALYSIS SUMMARY:", level="INFO")
            self.log(f"Total honeypots analyzed: {len(results)}", level="INFO")
            
            # Number of honeypots with actual interaction
            active_honeypots = sum(1 for r in results if r["interaction_score"] > 0)
            self.log(f"Honeypots with attacker interaction: {active_honeypots}", 
                     level="SUCCESS" if active_honeypots > 0 else "WARNING")
            
            # Most effective honeypot
            if results:
                best_honeypot = max(results, key=lambda x: x["interaction_score"])
                self.log(f"Most effective honeypot: {best_honeypot['honeypot_type']} " +
                         f"(Score: {best_honeypot['interaction_score']}, Level: {best_honeypot['engagement_level']})",
                         level="SUCCESS" if best_honeypot["interaction_score"] > 0 else "INFO")
            
            self.log(f"Detailed report saved to: {report_file}", level="SUCCESS")
            self.log(f"JSON data saved to: {json_file}", level="SUCCESS")
            self.log("=" * 80, level="INFO")
            
            return True
            
        except Exception as e:
            self.log(f"Analysis failed: {str(e)}", level="ERROR")
            import traceback
            self.log(traceback.format_exc(), level="ERROR")
            return False

async def main():
    parser = argparse.ArgumentParser(description="Analyze T-Pot honeypot logs for attacker engagement")
    
    # Connection options
    parser.add_argument("--remote", action="store_true", help="Connect to remote T-Pot")
    parser.add_argument("--host", help="Remote T-Pot hostname or IP")
    parser.add_argument("--port", type=int, default=64295, help="SSH port (default: 64295)")
    parser.add_argument("--user", help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", help="Path to SSH private key file")
    
    # Analysis options
    parser.add_argument("--output-dir", default="honeypot_analysis", help="Output directory for reports and visualizations")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.remote and not args.host:
        print("Error: --host is required when using --remote")
        sys.exit(1)
        
    if args.remote and not args.user:
        print("Error: --user is required when using --remote")
        sys.exit(1)
        
    if args.remote and not (args.password or args.key):
        print("Error: Either --password or --key is required when using --remote")
        sys.exit(1)
    
    analyzer = HoneypotLogAnalyzer(
        remote=args.remote,
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        key_path=args.key,
        debug=args.debug,
        output_dir=args.output_dir
    )
    
    success = await analyzer.analyze()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    asyncio.run(main())