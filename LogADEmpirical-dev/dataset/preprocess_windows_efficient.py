"""
Efficient preprocessing script for large Windows CBS log files
Samples a subset of the log data for training
"""

import re
import sys
import os

try:
    import pandas as pd
except ImportError:
    print("Installing pandas...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
    import pandas as pd

def parse_windows_log_streaming(log_file, output_csv, max_lines=100000, sample_rate=100):
    """
    Parse Windows CBS log format to CSV with sampling
    
    Args:
        log_file: Path to log file
        output_csv: Output CSV path
        max_lines: Maximum lines to process (for speed)
        sample_rate: Sample every Nth line for large files
    """
    
    print(f"Reading log file: {log_file}")
    
    # Check if file exists
    if not os.path.exists(log_file):
        print(f"Error: File not found: {log_file}")
        sys.exit(1)
    
    # Regex pattern for Windows CBS log format
    pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+(\w+)\s+(\w+)\s+(.+)$'
    
    # First, count total lines
    print("Counting log file size...")
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"Total lines in file: {total_lines:,}")
    
    # Determine sampling strategy
    if total_lines > max_lines:
        sample_rate = max(1, total_lines // max_lines)
        print(f"Large file detected. Sampling every {sample_rate} lines...")
    else:
        sample_rate = 1
        print("Processing all lines...")
    
    # Create CSV file and write header
    with open(output_csv, 'w', encoding='utf-8', newline='') as out_file:
        out_file.write('LineId,Timestamp,Level,Component,Content,EventId,EventTemplate,Label\n')
        
        processed = 0
        written = 0
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Sample lines
                if line_num % sample_rate != 0:
                    continue
                
                processed += 1
                line = line.strip()
                
                if not line:
                    continue
                
                match = re.match(pattern, line)
                
                if match:
                    timestamp_str = match.group(1).replace(',', '')
                    level = match.group(2)
                    component = match.group(3)
                    content = match.group(4).strip().replace('"', '""')  # Escape quotes
                    
                    # Simple template extraction
                    words = content.split()
                    if len(words) > 5:
                        template = component + " " + " ".join(words[:5])
                    else:
                        template = component + " " + content[:50]
                    
                    template = template.replace('"', '""')
                    
                    # Write line to CSV
                    out_file.write(f'{line_num},{timestamp_str},{level},{component},"{content}","{template}","{template}",-\n')
                    written += 1
                
                # Progress update
                if processed % 10000 == 0:
                    print(f"Processed: {processed:,} lines, Written: {written:,} entries...", end='\r')
    
    print(f"\n\n✓ Parsing complete!")
    print(f"  Processed lines: {processed:,}")
    print(f"  Written entries: {written:,}")
    print(f"  Sample rate: 1 every {sample_rate} lines")
    print(f"  Saved to: {output_csv}")
    
    # Load and show statistics
    print("\nLoading dataset statistics...")
    df = pd.read_csv(output_csv)
    print(f"\nDataset statistics:")
    print(f"  Total entries: {len(df):,}")
    print(f"  Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"  Components: {df['Component'].nunique()}")
    print(f"  Unique templates: {df['EventTemplate'].nunique()}")
    print(f"  Labels: {df['Label'].value_counts().to_dict()}")
    
    return df

if __name__ == "__main__":
    # Determine paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    log_file = os.path.join(parent_dir, "output.log")
    output_dir = os.path.join(script_dir, "Windows")
    output_csv = os.path.join(output_dir, "output.log_structured.csv")
    
    # Create Windows directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Parse with sampling (default: sample to ~100k lines)
    df = parse_windows_log_streaming(log_file, output_csv, max_lines=100000, sample_rate=1)
    
    print("\n" + "="*60)
    print("✓ Preprocessing complete!")
    print("="*60)
    print("\nNext steps:")
    print("1. Generate embeddings:")
    print("   python generate_embeddings.py Windows average")
    print("\n2. Train DeepLog:")
    print("   python main_run.py --config_file config/windows_deeplog.yaml")
    print("\n3. Train LogAnomaly:")
    print("   python main_run.py --config_file config/windows_loganomaly.yaml")
