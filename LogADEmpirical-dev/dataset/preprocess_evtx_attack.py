"""
Preprocessing EVTX-ATTACK-SAMPLES untuk training
Convert Windows EVTX files ke format CSV untuk DeepLog/LogAnomaly

Requirements:
    pip install python-evtx xmltodict pandas
"""

import os
import sys
import json
from pathlib import Path
import pandas as pd
from datetime import datetime

try:
    import Evtx.Evtx as evtx
    import xmltodict
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-evtx", "xmltodict"])
    import Evtx.Evtx as evtx
    import xmltodict


def parse_evtx_file(evtx_path):
    """
    Parse EVTX file and extract log entries
    """
    entries = []
    
    try:
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    data = xmltodict.parse(xml_str)
                    
                    event = data.get('Event', {})
                    system = event.get('System', {})
                    event_data = event.get('EventData', {})
                    
                    # Extract key fields
                    timestamp = system.get('TimeCreated', {}).get('@SystemTime', '')
                    event_id = system.get('EventID', {})
                    if isinstance(event_id, dict):
                        event_id = event_id.get('#text', '')
                    
                    level = system.get('Level', '')
                    provider = system.get('Provider', {}).get('@Name', '')
                    channel = system.get('Channel', '')
                    
                    # Get event data content
                    content_parts = []
                    if isinstance(event_data, dict):
                        for key, value in event_data.items():
                            if isinstance(value, dict) and '@Name' in value:
                                content_parts.append(f"{value.get('@Name', '')}={value.get('#text', '')}")
                            elif isinstance(value, str):
                                content_parts.append(value)
                    
                    content = " ".join(content_parts) if content_parts else str(event_data)
                    
                    entries.append({
                        'Timestamp': timestamp,
                        'EventID': event_id,
                        'Level': level,
                        'Provider': provider,
                        'Channel': channel,
                        'Content': content[:500]  # Limit content length
                    })
                    
                except Exception as e:
                    continue
    
    except Exception as e:
        print(f"Error parsing {evtx_path}: {e}")
    
    return entries


def process_evtx_dataset(evtx_repo_path, output_csv, max_files_per_category=10):
    """
    Process EVTX-ATTACK-SAMPLES repository
    
    Args:
        evtx_repo_path: Path to cloned EVTX-ATTACK-SAMPLES repo
        output_csv: Output CSV file path
        max_files_per_category: Max EVTX files to process per attack category
    """
    
    print(f"Processing EVTX-ATTACK-SAMPLES from: {evtx_repo_path}")
    
    # MITRE ATT&CK categories (folders in repo)
    attack_categories = [
        "Credential Access",
        "Defense Evasion",
        "Discovery",
        "Execution",
        "Lateral Movement",
        "Persistence",
        "Privilege Escalation",
        "Command and Control",
        "Other"
    ]
    
    all_entries = []
    category_stats = {}
    
    for category in attack_categories:
        category_path = os.path.join(evtx_repo_path, category)
        
        if not os.path.exists(category_path):
            print(f"[WARN] Category not found: {category}")
            continue
        
        print(f"\n[*] Processing: {category}")
        
        # Find all EVTX files in category
        evtx_files = list(Path(category_path).rglob("*.evtx"))
        
        if not evtx_files:
            print(f"   No EVTX files found")
            continue
        
        # Limit files per category to avoid imbalance
        evtx_files = evtx_files[:max_files_per_category]
        
        category_count = 0
        for evtx_file in evtx_files:
            print(f"   Parsing: {evtx_file.name}...", end=' ')
            
            entries = parse_evtx_file(str(evtx_file))
            
            # Label as anomaly (attack)
            for entry in entries:
                entry['Label'] = '1'  # Anomaly
                entry['AttackCategory'] = category
                entry['EventTemplate'] = f"{entry['Provider']} EventID={entry['EventID']}"
                entry['Component'] = entry['Provider']
            
            all_entries.extend(entries)
            category_count += len(entries)
            print(f"[OK] {len(entries)} events")
        
        category_stats[category] = category_count
        print(f"   Total: {category_count} events")
    
    # Create DataFrame
    df = pd.DataFrame(all_entries)
    
    if len(df) == 0:
        print("\n[ERROR] No data extracted!")
        return None
    
    # Add LineId
    df.insert(0, 'LineId', range(1, len(df) + 1))
    
    # Reorder columns to match LogADEmpirical format (Timestamp, Label, EventID, EventTemplate, Content)
    columns = ['Timestamp', 'Label', 'EventID', 'EventTemplate', 'Content', 'AttackCategory']
    df = df[columns]
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    
    print(f"\n{'='*60}")
    print(f"[SUCCESS] Processing Complete!")
    print(f"{'='*60}")
    print(f"Total events: {len(df):,}")
    print(f"Output file: {output_csv}")
    print(f"\nEvents per category:")
    for cat, count in sorted(category_stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {cat:30s}: {count:5,} events")
    
    print(f"\nDataset statistics:")
    print(f"  Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"  Unique Event IDs: {df['EventID'].nunique()}")
    print(f"  Attack categories: {df['AttackCategory'].nunique()}")
    
    return df


def add_normal_data(attack_csv, normal_log_path, output_combined_csv):
    """
    Combine attack data with normal Windows logs for balanced dataset
    
    Args:
        attack_csv: CSV with attack/anomaly data
        normal_log_path: Path to normal Windows log CSV
        output_combined_csv: Output combined CSV
    """
    
    print("\n[*] Creating balanced dataset (normal + attack)...")
    
    # Load attack data
    df_attack = pd.read_csv(attack_csv)
    print(f"Attack events: {len(df_attack):,}")
    
    # Load normal data if available
    if os.path.exists(normal_log_path):
        df_normal = pd.read_csv(normal_log_path)
        
        # Convert normal data to match attack data format
        # Expected format: Timestamp, Label, EventID, EventTemplate, Content, AttackCategory
        df_normal_converted = pd.DataFrame({
            'Timestamp': df_normal['Timestamp'],
            'Label': '-',  # Normal
            'EventID': df_normal['EventId'] if 'EventId' in df_normal.columns else df_normal['EventID'],
            'EventTemplate': df_normal['EventTemplate'],
            'Content': df_normal['Content'],
            'AttackCategory': ''  # No attack category for normal
        })
        
        # Sample normal data to balance with attacks (e.g., 2:1 ratio)
        n_normal = min(len(df_normal_converted), len(df_attack) * 2)
        df_normal_sampled = df_normal_converted.sample(n=n_normal, random_state=42)
        
        # Combine
        df_combined = pd.concat([df_normal_sampled, df_attack], ignore_index=True)
        
        # Shuffle
        df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save
        df_combined.to_csv(output_combined_csv, index=False)
        
        print(f"[SUCCESS] Combined dataset created!")
        print(f"  Normal events: {n_normal:,} ({n_normal/len(df_combined)*100:.1f}%)")
        print(f"  Attack events: {len(df_attack):,} ({len(df_attack)/len(df_combined)*100:.1f}%)")
        print(f"  Total events: {len(df_combined):,}")
        print(f"  Output: {output_combined_csv}")
        
        return df_combined
    else:
        print(f"[WARN] Normal log not found: {normal_log_path}")
        print(f"   Using attack data only (for demo/testing)")
        return df_attack


if __name__ == "__main__":
    print("="*60)
    print("EVTX-ATTACK-SAMPLES Preprocessing")
    print("="*60)
    
    # Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    # EVTX repo path - check both in parent and current directory
    evtx_repo = os.path.join(parent_dir, "EVTX-ATTACK-SAMPLES")
    if not os.path.exists(evtx_repo):
        # Try in script directory
        evtx_repo = os.path.join(script_dir, "EVTX-ATTACK-SAMPLES")
    
    # Output paths
    output_dir = os.path.join(script_dir, "EVTX_Dataset")
    os.makedirs(output_dir, exist_ok=True)
    
    attack_csv = os.path.join(output_dir, "evtx_attacks.csv")
    combined_csv = os.path.join(output_dir, "evtx_combined_structured.csv")
    normal_csv = os.path.join(script_dir, "Windows", "output.log_structured.csv")
    
    # Check if repo exists
    if not os.path.exists(evtx_repo):
        print(f"\n[ERROR] EVTX-ATTACK-SAMPLES not found at: {evtx_repo}")
        print(f"\nPlease clone the repository first:")
        print(f"  cd {os.path.dirname(script_dir)}")
        print(f"  git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git")
        sys.exit(1)
    
    # Process EVTX files
    df_attack = process_evtx_dataset(
        evtx_repo_path=evtx_repo,
        output_csv=attack_csv,
        max_files_per_category=10  # Limit to avoid too much data
    )
    
    if df_attack is not None:
        # Combine with normal data
        df_combined = add_normal_data(
            attack_csv=attack_csv,
            normal_log_path=normal_csv,
            output_combined_csv=combined_csv
        )
        
        print(f"\n{'='*60}")
        print(f"[SUCCESS] DONE!")
        print(f"{'='*60}")
        print(f"\nNext steps:")
        print(f"1. Create config file for EVTX dataset")
        print(f"2. Train DeepLog:")
        print(f"   python main_run.py --config_file config/evtx_deeplog.yaml")
        print(f"3. Train LogAnomaly:")
        print(f"   python main_run.py --config_file config/evtx_loganomaly.yaml")
