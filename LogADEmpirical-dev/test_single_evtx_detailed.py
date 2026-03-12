"""
Test trained Wintrim DeepLog model on a single EVTX attack file
WITH DETAILED ANOMALY DISPLAY
"""

import torch
import sys
from pathlib import Path
from Evtx.Evtx import Evtx
import xmltodict
import pandas as pd
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog


def parse_evtx_file(evtx_path):
    """
    Parse single EVTX file to extract events
    """
    print(f"\n{'='*80}")
    print("PARSING EVTX FILE")
    print(f"{'='*80}")
    print(f"File: {evtx_path}")
    
    events = []
    
    try:
        with Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event_dict = xmltodict.parse(xml_str)
                    
                    event = event_dict['Event']
                    system = event['System']
                    
                    # Extract basic info
                    event_id = system.get('EventID', {})
                    if isinstance(event_id, dict):
                        event_id = event_id.get('#text', 'Unknown')
                    
                    provider = system.get('Provider', {})
                    if isinstance(provider, dict):
                        provider_name = provider.get('@Name', 'Unknown')
                    else:
                        provider_name = str(provider)
                    
                    # Create event template (EventID + Provider)
                    event_template = f"{provider_name} EventID={event_id}"
                    
                    events.append({
                        'Timestamp': system.get('TimeCreated', {}).get('@SystemTime', ''),
                        'EventID': str(event_id),
                        'Provider': provider_name,
                        'EventTemplate': event_template,
                        'Channel': system.get('Channel', 'Unknown')
                    })
                    
                except Exception as e:
                    continue
    
    except Exception as e:
        print(f"Error reading EVTX: {e}")
        return None
    
    if not events:
        print("No events found!")
        return None
    
    df = pd.DataFrame(events)
    
    print(f"\n{'='*80}")
    print("PARSING RESULTS")
    print(f"{'='*80}")
    print(f"Total events parsed:  {len(df)}")
    print(f"Unique event IDs:     {df['EventID'].nunique()}")
    print(f"Providers:            {', '.join(df['Provider'].unique()[:5])}")
    print(f"Date range:           {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    print(f"{'='*80}")
    
    return df


def load_model_and_vocab(model_path, vocab_path):
    """Load trained model and vocabulary"""
    print(f"\n{'='*80}")
    print("LOADING MODEL")
    print(f"{'='*80}")
    print(f"Vocab: {vocab_path}")
    
    vocab = Vocab.load_vocab(vocab_path)
    print(f"  Vocab size: {len(vocab)}")
    
    print(f"\nModel: {model_path}")
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
    print("  ✓ Model loaded on CPU")
    print(f"{'='*80}")
    
    return model, vocab


def create_sequences(df, vocab, window_size=10, step_size=5):
    """
    Create sliding window sequences from events
    """
    print(f"\n{'='*80}")
    print("CREATING SEQUENCES")
    print(f"{'='*80}")
    print(f"Window size: {window_size}, Step size: {step_size}")
    
    events_text = df['EventTemplate'].tolist()
    sequences = []
    
    for i in range(0, len(df) - window_size + 1, step_size):
        window = df.iloc[i:i+window_size]
        seq = window['EventTemplate'].tolist()
        
        # Convert to vocab indices
        seq_ids = [vocab.get_event(event, use_similar=False) for event in seq]
        sequences.append(seq_ids)
    
    print(f"Created {len(sequences)} sequences")
    print(f"{'='*80}")
    
    return sequences, events_text


def predict_detailed(model, sequences, vocab, events_text, topk=9):
    """
    Predict anomaly for sequences with DETAILED display
    """
    print(f"\n{'='*80}")
    print(f"RUNNING ANOMALY DETECTION (Top-{topk} threshold)")
    print(f"{'='*80}")
    
    device = 'cpu'
    model = model.to(device)
    
    anomalies = []
    normal_examples = []
    
    with torch.no_grad():
        for idx, seq in enumerate(sequences):
            if len(seq) < 10:
                continue
            
            # Target: 10th event
            target_event = seq[9]
            target_idx = idx * 5 + 9
            target_text = events_text[target_idx] if target_idx < len(events_text) else "Unknown"
            
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
            top_k_probs = top_k_probs.cpu().numpy()
            
            # Check if target is in top-K
            is_anomaly = target_event not in top_k_events
            
            # Get context (last 3 events before prediction)
            context = []
            for i in range(max(0, 9-3), 9):
                ctx_idx = idx * 5 + i
                if ctx_idx < len(events_text):
                    context.append(events_text[ctx_idx])
            
            detection = {
                'sequence_idx': idx,
                'target_event': target_event,
                'target_text': target_text,
                'top_k': top_k_events.tolist(),
                'top_k_probs': top_k_probs.tolist(),
                'context': context,
                'matched_rank': None
            }
            
            if is_anomaly:
                anomalies.append(detection)
            else:
                # Find which rank it matched
                for rank, pred_event in enumerate(top_k_events):
                    if pred_event == target_event:
                        detection['matched_rank'] = rank + 1
                        break
                normal_examples.append(detection)
    
    total = len(sequences)
    anomaly_count = len(anomalies)
    anomaly_rate = (anomaly_count / total) * 100 if total > 0 else 0
    
    print(f"\n{'='*80}")
    print("DETECTION SUMMARY")
    print(f"{'='*80}")
    print(f"Total sequences:      {total}")
    print(f"🔴 Anomalies:          {anomaly_count} ({anomaly_rate:.1f}%)")
    print(f"✅ Normal:             {len(normal_examples)} ({100 - anomaly_rate:.1f}%)")
    print(f"{'='*80}")
    
    # Show ALL anomalies
    if anomalies:
        print(f"\n{'='*80}")
        print(f"🔴 ANOMALY DETAILS - ALL {len(anomalies)} DETECTIONS")
        print(f"{'='*80}")
        
        for i, anom in enumerate(anomalies):
            print(f"\n{'─'*80}")
            print(f"🔴 Anomaly #{i+1} of {len(anomalies)} - Sequence {anom['sequence_idx'] + 1}/{total}")
            print(f"{'─'*80}")
            
            # Show context
            if anom['context']:
                print(f"\n📋 Context (last 3 events):")
                for j, ctx in enumerate(anom['context']):
                    print(f"  {j+1}. {ctx[:75]}")
            
            # Show actual next event
            print(f"\n▶️  ACTUAL next event:")
            print(f"   {anom['target_text'][:75]}")
            
            # Show top-K predictions
            print(f"\n❌ Model TOP-{topk} predictions (NONE MATCHED):")
            for j, (event_id, prob) in enumerate(zip(anom['top_k'], anom['top_k_probs'])):
                try:
                    if event_id < len(vocab.itos):
                        pred_text = vocab.itos[event_id]
                    else:
                        pred_text = f"<Unknown ID: {event_id}>"
                except:
                    pred_text = f"<ID: {event_id}>"
                
                print(f"   {j+1}. {pred_text[:65]:<65} (prob: {prob:.4f})")
    
    # Show normal examples if any
    if normal_examples:
        print(f"\n{'='*80}")
        print(f"✅ NORMAL SEQUENCES - {len(normal_examples)} DETECTIONS")
        print(f"{'='*80}")
        print(f"These had their actual next event in top-{topk} predictions")
        
        # Show first few normal examples
        for i, norm in enumerate(normal_examples[:3]):
            print(f"\n✅ Normal example #{i+1}: Sequence {norm['sequence_idx'] + 1}")
            print(f"   Actual: {norm['target_text'][:70]}")
            print(f"   ✓ Found at rank: {norm['matched_rank']}")
    
    return anomaly_count, total


if __name__ == "__main__":
    print("\n" + "="*80)
    print("TEST DEEPLOG ON SINGLE EVTX ATTACK FILE - DETAILED OUTPUT")
    print("="*80)
    
    # Select one EVTX file to test
    evtx_file = "EVTX-ATTACK-SAMPLES/Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx"
    
    # Model paths
    model_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/models/DeepLog.pt"
    vocab_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/vocabs/DeepLog.pkl"
    
    # Check if file exists
    if not Path(evtx_file).exists():
        print(f"\n❌ File not found: {evtx_file}")
        sys.exit(1)
    
    # Parse EVTX
    df = parse_evtx_file(evtx_file)
    if df is None:
        sys.exit(1)
    
    # Load model
    model, vocab = load_model_and_vocab(model_path, vocab_path)
    
    # Create sequences
    sequences, events_text = create_sequences(df, vocab, window_size=10, step_size=5)
    
    # Predict with detailed output
    anomalies, total = predict_detailed(model, sequences, vocab, events_text, topk=9)
    
    print(f"\n{'='*80}")
    print("✓ TESTING COMPLETE")
    print(f"{'='*80}")
    print(f"\nSummary:")
    print(f"  Model: Wintrim DeepLog (trained on 996k normal Windows logs)")
    print(f"  Test file: {Path(evtx_file).name}")
    print(f"  Result: {anomalies}/{total} sequences detected as anomalies")
