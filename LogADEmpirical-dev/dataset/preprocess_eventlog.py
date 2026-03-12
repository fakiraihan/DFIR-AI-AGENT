"""
Preprocessing script for eventlog.csv
Converts Windows Event Log CSV to DeepLog-compatible structured format

Input columns: "","MachineName","Category","EntryType","Message","Source","TimeGenerated","country","regionName","city","zip","timezone","isp"
Output format: LineId,Timestamp,Label,EventId,EventTemplate,Content
"""

import re
import sys
import os
import hashlib

try:
    import pandas as pd
except ImportError:
    print("Installing pandas...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
    import pandas as pd

def clean_value(value):
    """Clean and handle missing values"""
    if pd.isna(value) or value == "" or str(value) == "0":
        return "Unknown"
    return str(value).strip()

def generate_event_template(source, entry_type):
    """
    Generate event template from Source + EntryType
    Example: "ESENT_Error", "SoftwareProtection_Information"
    """
    source_clean = clean_value(source).replace(" ", "")
    entry_type_clean = clean_value(entry_type)
    
    # Handle empty or "0" values
    if entry_type_clean == "Unknown":
        entry_type_clean = "Information"
    
    template = f"{source_clean}_{entry_type_clean}"
    return template

def generate_event_id(template):
    """
    Generate numeric EventId from template using hash
    """
    # Use MD5 hash and convert to integer (modulo to keep reasonable size)
    hash_obj = hashlib.md5(template.encode())
    event_id = int(hash_obj.hexdigest()[:8], 16) % 100000
    return event_id

def assign_label(entry_type):
    """
    Assign label based on EntryType:
    - Information/Warning/"0"/empty -> normal (-)
    - Error -> anomaly (1)
    """
    entry_type_clean = clean_value(entry_type).lower()
    
    if entry_type_clean == "error":
        return "1"
    else:
        # Information, Warning, Unknown, 0, etc. are all normal
        return "-"

def parse_eventlog_csv(log_file, output_csv, chunk_size=50000):
    """
    Parse eventlog.csv to DeepLog structured format
    
    Args:
        log_file: Path to eventlog.csv
        output_csv: Output CSV path
        chunk_size: Process in chunks to handle large files
    """
    
    print(f"Reading eventlog.csv: {log_file}")
    print("Processing in chunks to handle large file...")
    
    # Check if file exists
    if not os.path.exists(log_file):
        print(f"Error: File not found: {log_file}")
        sys.exit(1)
    
    # Count total lines first
    print("Counting total rows...")
    try:
        total_lines = sum(1 for _ in open(log_file, 'r', encoding='utf-8', errors='ignore')) - 1  # -1 for header
        print(f"Total rows in file: {total_lines:,}")
    except Exception as e:
        print(f"Could not count lines: {e}")
        total_lines = None
    
    # Process in chunks
    processed_count = 0
    normal_count = 0
    anomaly_count = 0
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    # Open output file
    with open(output_csv, 'w', encoding='utf-8', newline='') as out_file:
        # Write header
        out_file.write('LineId,Timestamp,Label,EventId,EventTemplate,Content\n')
        
        # Read and process in chunks
        try:
            for chunk_num, chunk in enumerate(pd.read_csv(log_file, 
                                                          chunksize=chunk_size,
                                                          encoding='utf-8',
                                                          on_bad_lines='skip',
                                                          low_memory=False), 1):
                
                print(f"\nProcessing chunk {chunk_num} ({len(chunk):,} rows)...")
                
                for idx, row in chunk.iterrows():
                    processed_count += 1
                    
                    # Extract columns
                    source = row.get('Source', 'Unknown')
                    entry_type = row.get('EntryType', 'Information')
                    message = row.get('Message', '')
                    time_generated = row.get('TimeGenerated', '')
                    
                    # Clean and format timestamp
                    timestamp = clean_value(time_generated)
                    if timestamp != "Unknown":
                        # Parse and reformat timestamp if needed
                        try:
                            # Handle format like "11/14/2020 3:16:29 AM"
                            from datetime import datetime
                            dt = pd.to_datetime(timestamp)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            # Keep original if parsing fails
                            pass
                    
                    # Generate EventTemplate and EventId
                    event_template = generate_event_template(source, entry_type)
                    event_id = generate_event_id(event_template)
                    
                    # Assign label
                    label = assign_label(entry_type)
                    if label == "1":
                        anomaly_count += 1
                    else:
                        normal_count += 1
                    
                    # Clean message content
                    content = clean_value(message).replace('"', '""')  # Escape quotes for CSV
                    if len(content) > 5000:  # Limit content length
                        content = content[:5000] + "..."
                    
                    # Write to CSV
                    line_id = processed_count
                    out_file.write(f'{line_id},"{timestamp}",{label},{event_id},"{event_template}","{content}"\n')
                    
                    # Progress update
                    if processed_count % 10000 == 0:
                        print(f"  Processed: {processed_count:,} rows (Normal: {normal_count:,}, Anomaly: {anomaly_count:,})", end='\r')
        
        except Exception as e:
            print(f"\nError during processing: {e}")
            print(f"Processed {processed_count} rows before error")
            if processed_count == 0:
                raise
    
    print(f"\n\n{'='*70}")
    print("✓ Parsing complete!")
    print(f"{'='*70}")
    print(f"  Total entries processed: {processed_count:,}")
    print(f"  Normal logs (-): {normal_count:,} ({100*normal_count/processed_count:.1f}%)")
    print(f"  Anomaly logs (1): {anomaly_count:,} ({100*anomaly_count/processed_count:.1f}%)")
    print(f"  Saved to: {output_csv}")
    
    # Load and show detailed statistics
    print(f"\n{'='*70}")
    print("Loading dataset for detailed statistics...")
    print(f"{'='*70}")
    
    try:
        df = pd.read_csv(output_csv)
        
        print(f"\nDataset Statistics:")
        print(f"  Total entries: {len(df):,}")
        print(f"  Unique EventTemplates: {df['EventTemplate'].nunique():,}")
        print(f"  Unique EventIds: {df['EventId'].nunique():,}")
        
        if 'Timestamp' in df.columns and len(df) > 0:
            print(f"\nTime Range:")
            print(f"  First log: {df['Timestamp'].iloc[0]}")
            print(f"  Last log: {df['Timestamp'].iloc[-1]}")
        
        print(f"\nLabel Distribution:")
        label_counts = df['Label'].value_counts()
        for label, count in label_counts.items():
            label_name = "Normal" if label == "-" else "Anomaly"
            print(f"  {label_name} ({label}): {count:,} ({100*count/len(df):.2f}%)")
        
        print(f"\nTop 10 Event Templates:")
        template_counts = df['EventTemplate'].value_counts().head(10)
        for template, count in template_counts.items():
            print(f"  {template}: {count:,}")
        
        print(f"\nVocabulary Size (for DeepLog):")
        print(f"  Unique templates: {df['EventTemplate'].nunique():,}")
        print(f"  Note: Vocabulary size affects model complexity")
        
        return df
        
    except Exception as e:
        print(f"Could not load statistics: {e}")
        return None

if __name__ == "__main__":
    # Determine paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    # Input: eventlog.csv in parent directory
    log_file = os.path.join(parent_dir, "..", "eventlog.csv")
    
    # Output: dataset/EventLog/eventlog_structured.csv
    output_dir = os.path.join(script_dir, "EventLog")
    output_csv = os.path.join(output_dir, "eventlog_structured.csv")
    
    # Create EventLog directory
    os.makedirs(output_dir, exist_ok=True)
    
    print("="*70)
    print("EventLog.csv Preprocessing for DeepLog")
    print("="*70)
    print(f"Input: {log_file}")
    print(f"Output: {output_csv}")
    print("="*70)
    print("\nLabeling Strategy:")
    print("  - EntryType = 'Information' or 'Warning' → Normal (-)")
    print("  - EntryType = 'Error' → Anomaly (1)")
    print("\nTemplate Generation:")
    print("  - Format: Source_EntryType (e.g., 'ESENT_Error')")
    print("="*70)
    
    # Parse eventlog.csv
    df = parse_eventlog_csv(log_file, output_csv)
    
    print("\n" + "="*70)
    print("✓ Preprocessing Complete!")
    print("="*70)
    print("\nNext Steps:")
    print("1. Create config file:")
    print("   config/eventlog_deeplog.yaml")
    print("\n2. Train DeepLog:")
    print("   python main_run.py --config_file config/eventlog_deeplog.yaml")
    print("\n3. Evaluate model:")
    print("   python test_deeplog.py --config_file config/eventlog_deeplog.yaml")
    print("="*70)
