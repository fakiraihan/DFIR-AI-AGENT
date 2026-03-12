"""
Test Wintrim DeepLog model on a single EVTX attack file
Includes EVTX parsing and anomaly detection
"""

import torch
import pickle
import pandas as pd
import sys
from pathlib import Path
import json
import xmltodict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog

try:
    from Evtx.Evtx import Evtx
except ImportError:
    print("Installing python-evtx...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-evtx"])
    from Evtx.Evtx import Evtx


def parse_single_evtx(evtx_file):
    """
    Parse a single EVTX file to extract events
    """
    print(f"\nParsing: {Path(evtx_file).name}")
    
    events = []
    
    try:
        with Evtx(evtx_file) as log:
            for record in log.records():
                try:
                    # Parse XML to dict
                    xml_str = record.xml()
                    event_dict = xmltodict.parse(xml_str)
                    
                    # Extract Event node
                    event = event_dict.get('Event', {})
                    system = event.get('System', {})
                    event_data = event.get('EventData', {})
                    
                    # Extract key fields
                    event_id = system.get('EventID', {}).get('#text', 'Unknown')
                    if isinstance(event_id, dict):
                        event_id = event_id.get('#text', 'Unknown')
                    
                    time_created = system.get('TimeCreated', {}).get('@SystemTime', '')
                    provider = system.get('Provider', {}).get('@Name', 'Unknown')
                    
                    # Create event template (provider + eventid)
                    event_template = f"{provider} EventID={event_id}"
                    
                    events.append({
                        'Timestamp': time_created,
                        'EventID': event_id,
                        'EventTemplate': event_template,
                        'Provider': provider,
                        'Label': 1  # Attack
                    })
                    
                except Exception as e:
                    continue
    
    except Exception as e:
        print(f"Error parsing EVTX: {e}")
        return None
    
    if not events:
        print("No events found!")
        return None
    
    df = pd.DataFrame(events)
    
    print(f"\nParsed {len(df)} events from EVTX file")
    print(f"{'='*60}")
    
    return df


def load_model_and_vocab(model_path, vocab_path):
    """Load trained model and vocabulary"""
    print(f"\nLoading model...")
    
    vocab = Vocab.load_vocab(vocab_path)
    model = DeepLog(
        vocab_size=len(vocab),
        embedding_dim=128,
        hidden_size=128,
        num_layers=2,
        dropout=0.1
    )
    
    checkpoint = torch.load(model_path, map_location='cpu')
    
    # Handle different checkpoint formats
    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    elif 'state_dict' in checkpoint:
        model.load_state_dict(checkpoint['state_dict'])
    elif 'model' in checkpoint:
        model.load_state_dict(checkpoint['model'])
    else:
        model.load_state_dict(checkpoint)
    
    model = model.cpu()
    model.eval()
    print("Model loaded successfully")
    
    return model, vocab


def create_sequences(df, vocab, window_size=10, step_size=5):
    """
    Create sliding window sequences from events
    """
    sequences = []
    
    # Get event templates
    events = df['EventTemplate'].fillna('Unknown').tolist()
    
    # Create sliding windows
    for i in range(0, len(events) - window_size + 1, step_size):
        window = events[i:i+window_size]
        
        # Convert to vocab indices
        seq_ids = [vocab.get_event(event, use_similar=False) for event in window]
        sequences.append(seq_ids)
    
    return sequences


def predict_anomalies(model, sequences, df, topk=9):
    """
    Predict anomalies in sequences
    """
    device = 'cpu'
    model = model.to(device)
    
    anomaly_lines = []
    
    with torch.no_grad():
        for idx, seq in enumerate(sequences):
            if len(seq) < 10:
                continue
            
            # Target: 10th event
            target_event = seq[9]
            
            # Input: first 9 events
            input_seq = torch.tensor(seq[:9], dtype=torch.long).unsqueeze(0)
            batch = {'sequential': input_seq.to(device)}
            
            # Predict
            output = model(batch)
            logits = output.logits if hasattr(output, 'logits') else output
            
            # Handle different output shapes
            if logits.dim() == 3:
                logits = logits[0, -1, :]
            elif logits.dim() == 2:
                logits = logits[0, :]
            else:
                logits = logits.squeeze()
            
            # Get top-K predictions
            top_k_probs, top_k_indices = torch.topk(logits, topk)
            top_k_events = top_k_indices.cpu().numpy()
            
            # Check if target is in top-K
            is_anomaly = target_event not in top_k_events
            
            if is_anomaly:
                # Calculate actual line number in original log (window position + 9)
                line_num = idx * 5 + 9  # step_size=5, target is 10th event (index 9)
                if line_num < len(df):
                    log_line = df.iloc[line_num]
                    anomaly_lines.append({
                        'line': line_num + 1,  # 1-indexed for display
                        'timestamp': log_line['Timestamp'],
                        'event': log_line['EventTemplate'],
                        'provider': log_line['Provider']
                    })
    
    # Display anomalies cleanly
    print(f"\n{'='*60}")
    print(f"ANOMALIES DETECTED ({len(anomaly_lines)} events)")
    print(f"{'='*60}\n")
    
    if anomaly_lines:
        for anom in anomaly_lines:
            print(f"Line {anom['line']:3d}: {anom['event']}")
    else:
        print("No anomalies - all events appear normal.")
    
    print(f"{'='*60}")

    
    return len(anomaly_lines), len(sequences)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("DEEPLOG ANOMALY DETECTION")
    print("="*60)
    
    # Select one EVTX file to test - Pass The Hash attack (Lateral Movement)
    evtx_file = "EVTX-ATTACK-SAMPLES/Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx"
    
    # Alternative files to try:
    # evtx_file = "EVTX-ATTACK-SAMPLES/Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx"
    # evtx_file = "EVTX-ATTACK-SAMPLES/Defense Evasion/schtasks_SYSTEM_TaskDeleteEvent.evtx"
    
    # Model paths
    model_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/models/DeepLog.pt"
    vocab_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/vocabs/DeepLog.pkl"
    
    # Check if file exists
    if not Path(evtx_file).exists():
        print(f"\nError: File not found - {evtx_file}")
        sys.exit(1)
    
    # Step 1: Parse EVTX file
    df = parse_single_evtx(evtx_file)
    if df is None:
        print("Failed to parse EVTX file")
        sys.exit(1)
    
    # Step 2: Load model
    model, vocab = load_model_and_vocab(model_path, vocab_path)
    
    # Step 3: Create sequences
    sequences = create_sequences(df, vocab, window_size=10, step_size=5)
    
    # Step 4: Predict anomalies
    anomaly_count, total = predict_anomalies(model, sequences, df, topk=9)
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"File: {Path(evtx_file).name}")
    print(f"Events: {len(df)} | Anomalies: {anomaly_count}")
    print("="*60)
