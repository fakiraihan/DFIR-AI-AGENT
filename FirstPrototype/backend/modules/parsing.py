"""
Drain Log Parsing Module
Integrates Drain algorithm for log template extraction
"""
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import pandas as pd
import re
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import Evtx.Evtx as evtx
import xmltodict
import json
from tqdm import tqdm

# Add LogADEmpirical to path to reuse existing code
LOGAD_PATH = Path(__file__).parent.parent.parent.parent / "LogADEmpirical-dev"
sys.path.insert(0, str(LOGAD_PATH))


class DrainParser:
    """
    Drain-based log parser for Windows EVTX, Sysmon, and text logs
    """
    
    def __init__(self, depth: int = 4, sim_threshold: float = 0.5, max_children: int = 100):
        """
        Initialize Drain parser
        
        Args:
            depth: Tree depth for parsing
            sim_threshold: Similarity threshold for template matching
            max_children: Maximum children per node
        """
        config = TemplateMinerConfig()
        config.drain_depth = depth
        config.drain_sim_th = sim_threshold
        config.drain_max_children = max_children
        config.drain_max_clusters = 10000
        
        self.template_miner = TemplateMiner(config=config)
        self.parsed_logs = []
        
    def preprocess_log_line(self, log_line: str) -> str:
        """
        Preprocess log line with regex patterns to mask dynamic content
        """
        # Mask IPv4 addresses
        log_line = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', log_line)
        
        # Mask numbers
        log_line = re.sub(r'\b\d+\b', '<NUM>', log_line)
        
        # Mask hex values
        log_line = re.sub(r'\b0x[0-9a-fA-F]+\b', '<HEX>', log_line)
        
        # Mask file paths
        log_line = re.sub(r'[A-Za-z]:\\[\w\\\.\-]+', '<PATH>', log_line)
        
        # Mask UUIDs
        log_line = re.sub(
            r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
            '<UUID>',
            log_line
        )
        
        return log_line
    
    def parse_evtx_file(self, file_path: str) -> pd.DataFrame:
        """
        Parse Windows EVTX file
        
        Args:
            file_path: Path to .evtx file
            
        Returns:
            DataFrame with columns: event_id, event_template, parameters, raw_line
        """
        print(f"Parsing EVTX file: {file_path}")
        parsed_events = []
        
        try:
            with evtx.Evtx(file_path) as log:
                for record in tqdm(log.records(), desc="Parsing EVTX"):
                    try:
                        xml_content = record.xml()
                        event_dict = xmltodict.parse(xml_content)
                        event_data = event_dict.get('Event', {})
                        
                        # Extract basic info
                        system = event_data.get('System', {})
                        event_id = system.get('EventID', {})
                        if isinstance(event_id, dict):
                            event_id = event_id.get('#text', 'Unknown')
                        
                        provider = system.get('Provider', {}).get('@Name', 'Unknown')
                        
                        # Create simplified log line for parsing
                        raw_line = f"{provider} EventID={event_id}"
                        
                        # Add event data if available
                        event_data_section = event_data.get('EventData', {})
                        if event_data_section:
                            data_items = event_data_section.get('Data', [])
                            if not isinstance(data_items, list):
                                data_items = [data_items]
                            
                            for item in data_items:
                                if isinstance(item, dict):
                                    name = item.get('@Name', 'Unknown')
                                    value = item.get('#text', '')
                                    if value:
                                        raw_line += f" {name}={value}"
                        
                        # Parse with Drain
                        result = self.template_miner.add_log_message(raw_line)
                        
                        # Extract parameters (values that were masked)
                        parameters = self._extract_parameters(raw_line, result['template_mined'])
                        
                        parsed_events.append({
                            'event_id': len(parsed_events),
                            'event_template': result['template_mined'],
                            'parameters': json.dumps(parameters),
                            'raw_line': raw_line,
                            'cluster_id': result['cluster_id']
                        })
                        
                    except Exception as e:
                        print(f"Error parsing record: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error opening EVTX file: {e}")
            raise
        
        df = pd.DataFrame(parsed_events)
        print(f"Parsed {len(df)} events, {df['cluster_id'].nunique()} unique templates")
        
        return df
    
    def parse_text_log(self, file_path: str) -> pd.DataFrame:
        """
        Parse text-based log file (.log, .txt, .csv)
        
        Args:
            file_path: Path to log file
            
        Returns:
            DataFrame with columns: event_id, event_template, parameters, raw_line
        """
        print(f"Parsing text log file: {file_path}")
        parsed_events = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for idx, line in enumerate(tqdm(lines, desc="Parsing logs")):
                line = line.strip()
                if not line:
                    continue
                
                # Parse with Drain
                result = self.template_miner.add_log_message(line)
                
                # Extract parameters
                parameters = self._extract_parameters(line, result['template_mined'])
                
                parsed_events.append({
                    'event_id': idx,
                    'event_template': result['template_mined'],
                    'parameters': json.dumps(parameters),
                    'raw_line': line,
                    'cluster_id': result['cluster_id']
                })
                
        except Exception as e:
            print(f"Error parsing text file: {e}")
            raise
        
        df = pd.DataFrame(parsed_events)
        print(f"Parsed {len(df)} events, {df['cluster_id'].nunique()} unique templates")
        
        return df
    
    def parse_file(self, file_path: str) -> pd.DataFrame:
        """
        Auto-detect file type and parse accordingly
        
        Args:
            file_path: Path to log file
            
        Returns:
            DataFrame with parsed logs
        """
        path = Path(file_path)
        
        if path.suffix.lower() == '.evtx':
            return self.parse_evtx_file(file_path)
        else:
            return self.parse_text_log(file_path)
    
    def _extract_parameters(self, original: str, template: str) -> List[str]:
        """
        Extract masked parameters from original log line
        
        Args:
            original: Original log line
            template: Drain-generated template with wildcards
            
        Returns:
            List of parameter values
        """
        # Simple parameter extraction
        # In production, would need more sophisticated matching
        params = []
        
        # Extract IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', original)
        params.extend(ips)
        
        # Extract file hashes (MD5, SHA256)
        hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b', original)
        params.extend(hashes)
        
        # Extract domains (simplified)
        domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', original)
        params.extend(domains)
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s]+', original)
        params.extend(urls)
        
        return params
    
    def get_templates(self) -> List[Dict]:
        """
        Get all discovered templates
        
        Returns:
            List of template dictionaries
        """
        templates = []
        for cluster in self.template_miner.drain.clusters:
            templates.append({
                'cluster_id': cluster.cluster_id,
                'template': str(cluster),
                'size': cluster.size
            })
        return templates


def parse_log_file(file_path: str, **kwargs) -> Tuple[pd.DataFrame, List[Dict]]:
    """
    Convenience function to parse a log file
    
    Args:
        file_path: Path to log file
        **kwargs: Additional parameters for DrainParser
        
    Returns:
        Tuple of (parsed_dataframe, templates_list)
    """
    parser = DrainParser(**kwargs)
    df = parser.parse_file(file_path)
    templates = parser.get_templates()
    
    return df, templates


if __name__ == "__main__":
    # Test parsing
    test_file = LOGAD_PATH / "EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx"
    
    if test_file.exists():
        df, templates = parse_log_file(str(test_file))
        print(f"\nSample parsed logs:")
        print(df.head())
        print(f"\nTotal templates: {len(templates)}")
