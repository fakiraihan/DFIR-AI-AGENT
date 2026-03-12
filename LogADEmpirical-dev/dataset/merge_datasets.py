"""
Merge Windows CBS (normal) + EVTX Attack (anomaly) datasets
Creates balanced training dataset for anomaly detection
"""
import pandas as pd
import os

print("="*60)
print("Merging Windows CBS (Normal) + EVTX Attack (Anomaly)")
print("="*60)

# Load EVTX attack data
print("\n[*] Loading EVTX attack data...")
evtx_df = pd.read_csv('dataset/EVTX_Dataset/evtx_attacks.csv')
print(f"  EVTX attacks: {len(evtx_df):,} events")
print(f"  Columns: {list(evtx_df.columns)}")

# Load Windows CBS (normal) data
print("\n[*] Loading Windows CBS (normal) data...")
windows_df = pd.read_csv('dataset/Windows/output.log_structured.csv')
print(f"  Windows CBS: {len(windows_df):,} events")
print(f"  Columns: {list(windows_df.columns)}")

# Make sure Windows data has Label column (all normal = 0 or '-')
if 'Label' not in windows_df.columns:
    windows_df['Label'] = '-'
else:
    windows_df['Label'] = '-'  # Force all to normal

# Convert Windows to match EVTX format
# EVTX format: Timestamp, Label, EventID, EventTemplate, Content, AttackCategory
print("\n[*] Converting Windows CBS to match EVTX format...")

# Check column names
if 'EventId' in windows_df.columns:
    windows_df['EventID'] = windows_df['EventId']
elif 'EventID' not in windows_df.columns:
    # Create EventID from EventTemplate
    windows_df['EventID'] = windows_df['EventTemplate']

# Add AttackCategory column (empty for normal logs)
if 'AttackCategory' not in windows_df.columns:
    windows_df['AttackCategory'] = ''

# Select only needed columns
windows_converted = windows_df[['Timestamp', 'Label', 'EventID', 'EventTemplate', 'Content', 'AttackCategory']]

# Balance dataset: EVTX attacks (4k) vs Windows normal (sample ~8k for 2:1 ratio)
print("\n[*] Balancing dataset...")
n_attacks = len(evtx_df)
n_normal = min(len(windows_converted), n_attacks * 2)  # 2:1 ratio normal:attack

print(f"  EVTX attacks: {n_attacks:,}")
print(f"  Windows normal (sampled): {n_normal:,}")

# Sample normal data
windows_sampled = windows_converted.sample(n=n_normal, random_state=42)

# Combine
print("\n[*] Merging datasets...")
combined_df = pd.concat([windows_sampled, evtx_df], ignore_index=True)

# Shuffle
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save
output_path = 'dataset/Windows_EVTX_Combined/combined_dataset.csv'
os.makedirs('dataset/Windows_EVTX_Combined', exist_ok=True)
combined_df.to_csv(output_path, index=False)

print("\n" + "="*60)
print("[SUCCESS] Dataset Merged!")
print("="*60)
print(f"\nOutput: {output_path}")
print(f"Total events: {len(combined_df):,}")
print(f"\nLabel distribution:")
print(combined_df['Label'].value_counts())
print(f"\nNormal events: {(combined_df['Label'] == '-').sum():,} ({(combined_df['Label'] == '-').sum()/len(combined_df)*100:.1f}%)")
print(f"Attack events: {(combined_df['Label'] == '1').sum():,} ({(combined_df['Label'] == '1').sum()/len(combined_df)*100:.1f}%)")

print(f"\nAttack categories:")
attack_df = combined_df[combined_df['AttackCategory'] != '']
if len(attack_df) > 0:
    print(attack_df['AttackCategory'].value_counts())

print("\nNext step: Train model with this balanced dataset!")
print("  python main_run.py --config_file config/combined_deeplog.yaml")
