"""
Parse wintrim.log (2.32 GB Windows CBS log) for DeepLog training
Samples 1 million lines from the full dataset
"""

import re
import sys
import os
import pandas as pd
from datetime import datetime

def parse_wintrim_log(log_file, output_csv, max_lines=1000000):
    """
    Parse Windows CBS log format to CSV with sampling
    
    Args:
        log_file: Path to wintrim.log
        output_csv: Output CSV path
        max_lines: Maximum lines to sample (default 1M)
    """
    
    print(f"Parsing: {log_file}")
    print(f"Target sample size: {max_lines:,} lines")
    
    # Check if file exists
    if not os.path.exists(log_file):
        print(f"Error: File not found: {log_file}")
        sys.exit(1)
    
    # Regex pattern for Windows CBS log format
    # Format: 2016-09-28 04:30:30, Info                  CBS    Starting TrustedInstaller...
    pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s+(\w+)\s+(\w+)\s+(.+)$'
    
    # First pass: count total lines and calculate sampling rate
    print("Analyzing file size...")
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"Total lines in file: {total_lines:,}")
    
    # Calculate sampling rate
    if total_lines > max_lines:
        sample_rate = max(1, total_lines // max_lines)
        print(f"Sampling every {sample_rate} lines to reach ~{max_lines:,} samples")
    else:
        sample_rate = 1
        print("File smaller than target, processing all lines")
    
    # Second pass: parse and sample
    print("Parsing log entries...")
    
    data = []
    line_num = 0
    parsed_count = 0
    skipped_count = 0
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_num += 1
            
            # Sample based on rate
            if line_num % sample_rate != 0:
                continue
            
            # Progress indicator
            if line_num % 100000 == 0:
                print(f"  Processed {line_num:,} lines, parsed {parsed_count:,} entries...")
            
            # Stop if reached target
            if parsed_count >= max_lines:
                break
            
            line = line.strip()
            if not line:
                continue
            
            # Try to parse the line
            match = re.match(pattern, line)
            if match:
                timestamp = match.group(1)
                level = match.group(2).strip()
                component = match.group(3).strip()
                content = match.group(4).strip()
                
                # Extract event template (first few words)
                # For CBS logs, use component + first meaningful part
                words = content.split()[:5]  # Take first 5 words
                event_template = component + " " + " ".join(words)
                
                data.append({
                    'LineId': line_num,
                    'Timestamp': timestamp,
                    'Level': level,
                    'Component': component,
                    'Content': content,
                    'EventId': event_template,  # Use template as EventId
                    'EventTemplate': event_template,
                    'Label': '-'  # All normal logs
                })
                parsed_count += 1
            else:
                skipped_count += 1
    
    print(f"\nParsing complete!")
    print(f"  Total lines scanned: {line_num:,}")
    print(f"  Successfully parsed: {parsed_count:,}")
    print(f"  Skipped (unparseable): {skipped_count:,}")
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Save to CSV
    print(f"\nSaving to: {output_csv}")
    df.to_csv(output_csv, index=False)
    
    # Print statistics
    print("\n" + "="*60)
    print("DATASET STATISTICS")
    print("="*60)
    print(f"Total entries:        {len(df):,}")
    print(f"Unique components:    {df['Component'].nunique()}")
    print(f"Unique event types:   {df['EventId'].nunique()}")
    print(f"Date range:           {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"All labels:           Normal (no attacks)")
    print("="*60)
    
    return df


if __name__ == "__main__":
    print("\n" + "="*60)
    print("WINTRIM.LOG PREPROCESSING")
    print("="*60 + "\n")
    
    # File paths
    log_file = "wintrim.log"
    output_dir = "dataset/Wintrim"
    output_csv = os.path.join(output_dir, "wintrim_structured.csv")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Parse with 1M sample size
    df = parse_wintrim_log(log_file, output_csv, max_lines=1000000)
    
    print("\n" + "="*60)
    print("✓ Preprocessing complete!")
    print("="*60)
    print(f"\nOutput: {output_csv}")
    print("\nNext steps:")
    print("1. Generate embeddings:")
    print("   cd dataset && python generate_embeddings.py Wintrim average")
    print("\n2. Create config file: config/wintrim_deeplog.yaml")
    print("\n3. Train DeepLog:")
    print("   python main_run.py --config_file config/wintrim_deeplog.yaml")
