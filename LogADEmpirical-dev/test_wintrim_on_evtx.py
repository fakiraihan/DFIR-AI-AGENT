"""
Test trained Wintrim DeepLog model on EVTX attack logs
"""

import torch
import pickle
import pandas as pd
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog

def load_model_and_vocab(model_path, vocab_path):
    """Load trained model and vocabulary"""
    print(f"Loading vocab from: {vocab_path}")
    vocab = Vocab.load_vocab(vocab_path)
    print(f"  Vocab size: {len(vocab)}")
    
    print(f"\nLoading model from: {model_path}")
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
        # Checkpoint is the state dict itself
        model.load_state_dict(checkpoint)
    
    # Move model to CPU to avoid device issues
    model = model.cpu()
    model.eval()
    print("  Model loaded successfully on CPU!")
    
    return model, vocab

def preprocess_evtx_log(csv_file, vocab, window_size=10):
    """
    Preprocess EVTX attack log for testing
    """
    print(f"\nLoading EVTX attack logs: {csv_file}")
    df = pd.read_csv(csv_file)
    
    print(f"  Total events: {len(df)}")
    print(f"  Attack categories: {df['AttackCategory'].unique()}")
    print(f"  Anomaly rate: {(df['Label'] == 1).sum() / len(df) * 100:.1f}%")
    
    # Extract event templates
    sequences = []
    labels = []
    
    # Create sliding windows
    for i in range(0, len(df) - window_size + 1, 5):  # step=5
        window = df.iloc[i:i+window_size]
        
        # Get EventID as sequence
        if 'EventId' in window.columns:
            seq = window['EventId'].fillna('Unknown').tolist()
        else:
            seq = window['EventTemplate'].fillna('Unknown').tolist()
        
        # Convert to vocab indices
        seq_ids = [vocab.get_event(event, use_similar=False) for event in seq]
        
        sequences.append(seq_ids)
        labels.append(int(window['Label'].max() > 0))  # 1 if any event is attack
    
    print(f"  Created {len(sequences)} windows")
    return sequences, labels

def predict(model, sequences, vocab, topk=9):
    """
    Predict anomaly for sequences
    """
    print(f"\nRunning predictions with top-{topk} threshold...")
    
    # USE CPU to avoid device mismatch issues
    device = 'cpu'
    model = model.to(device)
    
    anomalies = 0
    total = len(sequences)
    
    with torch.no_grad():
        for idx, seq in enumerate(sequences):
            if len(seq) < 10:
                continue
            
            # Target: 10th event
            target_event = seq[9]
            
            # Input: first 9 events - create tensor on correct device
            input_seq = torch.tensor(seq[:9], dtype=torch.long).unsqueeze(0)
            
            # Prepare batch dict (model expects this format)
            batch = {'sequential': input_seq.to(device)}
            
            # Predict
            output = model(batch)
            
            # Extract logits from ModelOutput
            logits = output.logits if hasattr(output, 'logits') else output
            
            # Handle different output shapes
            if logits.dim() == 3:
                # Shape: [batch, seq, vocab]
                logits = logits[0, -1, :]
            elif logits.dim() == 2:
                # Shape: [batch, vocab] - already last timestep
                logits = logits[0, :]
            else:
                logits = logits.squeeze()
            
            # Get top-K predictions
            top_k_probs, top_k_indices = torch.topk(logits, topk)
            top_k_events = top_k_indices.cpu().numpy()
            
            # Check if target is in top-K
            if target_event not in top_k_events:
                anomalies += 1
    
    anomaly_rate = anomalies / total * 100
    print(f"\n{'='*60}")
    print(f"ANOMALY DETECTION RESULTS")
    print(f"{'='*60}")
    print(f"Total windows tested:     {total}")
    print(f"Detected as anomaly:      {anomalies} ({anomaly_rate:.2f}%)")
    print(f"Detected as normal:       {total - anomalies} ({100 - anomaly_rate:.2f}%)")
    print(f"{'='*60}")
    
    return anomalies, total

if __name__ == "__main__":
    print("\n" + "="*60)
    print("TEST WINTRIM DEEPLOG MODEL ON EVTX ATTACKS")
    print("="*60 + "\n")
    
    # Paths
    model_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/models/DeepLog.pt"
    vocab_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/vocabs/DeepLog.pkl"
    test_csv = "dataset/EVTX_Dataset/evtx_attacks.csv"
    
    # Load model
    model, vocab = load_model_and_vocab(model_path, vocab_path)
    
    # Preprocess test data
    sequences, labels = preprocess_evtx_log(test_csv, vocab, window_size=10)
    
    # Predict
    anomalies, total = predict(model, sequences, vocab, topk=9)
    
    print("\n✓ Testing complete!")
    print(f"\nModel trained on: 996k normal Windows CBS logs (wintrim.log)")
    print(f"Tested on: 4,313 EVTX attack events")
    print(f"\nExpected: High anomaly detection (attacks should be flagged)")
    print(f"Result: {anomalies}/{total} = {anomalies/total*100:.1f}% detected as anomalies")
