"""
Preprocessing script for Windows CBS log files
Converts output.log to CSV format required for training
"""

import re
import sys
from datetime import datetime

try:
    import pandas as pd
except ImportError:
    print("Error: pandas not installed. Installing pandas...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
    import pandas as pd

def parse_windows_log(log_file, output_csv):
    """
    Parse Windows CBS log format to CSV
    Format: YYYY-MM-DD HH:MM:SS, Level Component Message
    """
    
    print(f"Reading log file: {log_file}")
    
    # Check if file exists
    import os
    if not os.path.exists(log_file):
        print(f"Error: File not found: {log_file}")
        sys.exit(1)
    
    log_entries = []
    line_count = 0
    
    # Regex pattern for Windows CBS log format
    # Pattern: timestamp, level, component, content
    pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+(\w+)\s+(\w+)\s+(.+)$'
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_count += 1
            line = line.strip()
            
            if not line:
                continue
                
            match = re.match(pattern, line)
            
            if match:
                timestamp_str = match.group(1)
                level = match.group(2)
                component = match.group(3)
                content = match.group(4).strip()
                
                # Simple template extraction: keep component + first few words
                words = content.split()
                if len(words) > 5:
                    template = component + " " + " ".join(words[:5])
                else:
                    template = component + " " + content
                    
                # For Windows logs, we assume all are normal (Label = 0)
                # You can manually label some as anomalies (Label = 1) later
                log_entries.append({
                    'LineId': line_count,
                    'Timestamp': timestamp_str,
                    'Level': level,
                    'Component': component,
                    'Content': content,
                    'EventId': template,  # Simplified template
                    'EventTemplate': template,
                    'Label': '-'  # '-' means normal
                })
            else:
                # Handle continuation lines or malformed lines
                if log_entries:
                    # Append to previous entry's content
                    log_entries[-1]['Content'] += ' ' + line
    
    print(f"Parsed {len(log_entries)} log entries from {line_count} lines")
    
    # Create DataFrame
    df = pd.DataFrame(log_entries)
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"Saved to: {output_csv}")
    print(f"\nDataset statistics:")
    print(f"  Total entries: {len(df)}")
    print(f"  Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"  Components: {df['Component'].nunique()}")
    print(f"  Unique templates: {df['EventTemplate'].nunique()}")
    
    return df

if __name__ == "__main__":
    # Determine paths based on script location
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    log_file = os.path.join(parent_dir, "output.log")
    output_dir = os.path.join(script_dir, "Windows")
    output_csv = os.path.join(output_dir, "output.log_structured.csv")
    
    # Create Windows directory if not exists
    os.makedirs(output_dir, exist_ok=True)
    
    df = parse_windows_log(log_file, output_csv)
    
    print("\n✓ Preprocessing complete!")
    print(f"Next step: Generate embeddings with:")
    print(f"  python generate_embeddings.py Windows average")
