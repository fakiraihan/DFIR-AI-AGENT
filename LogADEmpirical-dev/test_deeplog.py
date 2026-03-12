"""
Test DeepLog model on Windows log
Usage: python test_deeplog.py --test_log test.log --model_path output/EVTX/sliding/W10_S5_CFalse_train0.7/models/DeepLog.pt
"""
import os
import sys
import re
import argparse
import pickle
import pandas as pd
import torch
import torch.nn.functional as F
from tqdm import tqdm
import csv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logadempirical.models.lstm import DeepLog
from logadempirical.data.vocab import Vocab


def preprocess_windows_log(log_file, output_csv, max_lines=10000):
    """
    Preprocess Windows CBS log to structured format
    """
    print(f"[*] Preprocessing {log_file}...")
    
    # CBS log pattern: timestamp, level, component, message
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s+(\w+)\s+(\w+)\s+(.*)$'
    
    processed = 0
    with open(output_csv, 'w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(['Timestamp', 'Label', 'EventID', 'EventTemplate', 'Content'])
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if max_lines and processed >= max_lines:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                
                match = re.match(pattern, line)
                if match:
                    timestamp, level, component, content = match.groups()
                    
                    # Create template (simplified)
                    template = f"{component} {content[:50]}..."
                    event_id = template
                    
                    writer.writerow([
                        timestamp,
                        '-',  # Label (normal, unknown for test)
                        event_id,
                        template,
                        content
                    ])
                    processed += 1
                    
                if line_num % 10000 == 0:
                    print(f"  Processed {line_num} lines, kept {processed} entries")
    
    print(f"[SUCCESS] Preprocessed {processed} log entries")
    print(f"  Output: {output_csv}")
    return output_csv


def sliding_window(data, window_size=10, step_size=5):
    """Create sliding windows from log sequence"""
    windows = []
    labels = []
    
    for i in range(0, len(data) - window_size + 1, step_size):
        window = data[i:i + window_size]
        windows.append(window)
        labels.append(0)  # Unknown label for test data
    
    return windows, labels


def load_model_and_vocab(model_path, vocab_path):
    """Load trained DeepLog model and vocabulary"""
    print(f"[*] Loading model from {model_path}")
    
    # Load vocab
    with open(vocab_path, 'rb') as f:
        vocab = pickle.load(f)
    
    print(f"[*] Vocab size: {len(vocab)}")
    
    # Initialize model
    model = DeepLog(
        vocab_size=len(vocab),
        embedding_dim=50,
        hidden_size=128,
        num_layers=2,
        dropout=0.1
    )
    
    # Load weights
    checkpoint = torch.load(model_path, map_location='cpu')
    
    # Check if checkpoint contains 'model' key (training checkpoint format)
    if isinstance(checkpoint, dict) and 'model' in checkpoint:
        model.load_state_dict(checkpoint['model'])
    else:
        model.load_state_dict(checkpoint)
    
    model.eval()
    
    print(f"[SUCCESS] Model loaded")
    return model, vocab


def predict(model, vocab, windows, topk=9, device='cuda'):
    """Run inference on windows"""
    print(f"[*] Running inference on {len(windows)} windows...")
    
    model.to(device)
    model.eval()
    
    anomalies = []
    anomaly_scores = []
    
    with torch.no_grad():
        for idx, window in enumerate(tqdm(windows, desc="Predicting")):
            # Convert events to indices
            event_indices = []
            for event in window:
                if event in vocab.stoi:
                    event_indices.append(vocab.stoi[event])
                else:
                    event_indices.append(vocab.unk_index)  # Unknown event
            
            # Prepare input (all but last event)
            inputs = torch.tensor([event_indices[:-1]], dtype=torch.long)
            target = event_indices[-1]
            
            # Forward pass
            batch = {'sequential': inputs}
            outputs = model(batch, device=device)
            logits = outputs.logits[0]  # Shape: [vocab_size]
            
            # Get top-k predictions
            probs = F.softmax(logits, dim=-1)
            topk_probs, topk_indices = torch.topk(probs, k=min(topk, len(probs)))
            
            # Check if target in top-k
            is_anomaly = target not in topk_indices.cpu().numpy()
            anomalies.append(is_anomaly)
            
            # Anomaly score (1 - max_prob)
            max_prob = topk_probs[0].item()
            anomaly_scores.append(1 - max_prob)
    
    return anomalies, anomaly_scores


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test_log', type=str, default='test.log', help='Input log file')
    parser.add_argument('--model_path', type=str, 
                       default='output/EVTX/sliding/W10_S5_CFalse_train0.7/models/DeepLog.pt',
                       help='Path to trained model')
    parser.add_argument('--vocab_path', type=str,
                       default='output/EVTX/sliding/W10_S5_CFalse_train0.7/vocabs/DeepLog.pkl',
                       help='Path to vocabulary')
    parser.add_argument('--max_lines', type=int, default=10000, help='Max lines to process')
    parser.add_argument('--window_size', type=int, default=10, help='Sliding window size')
    parser.add_argument('--step_size', type=int, default=5, help='Sliding window step')
    parser.add_argument('--topk', type=int, default=9, help='Top-K for prediction')
    parser.add_argument('--device', type=str, default='cuda' if torch.cuda.is_available() else 'cpu')
    args = parser.parse_args()
    
    print("="*60)
    print("Testing DeepLog on Windows Log")
    print("="*60)
    
    # Step 1: Preprocess log
    output_csv = 'test_structured.csv'
    if not os.path.exists(output_csv):
        preprocess_windows_log(args.test_log, output_csv, args.max_lines)
    else:
        print(f"[*] Using existing {output_csv}")
    
    # Step 2: Load data
    print(f"\n[*] Loading {output_csv}...")
    df = pd.read_csv(output_csv)
    print(f"[*] Loaded {len(df)} log entries")
    
    # Step 3: Create sliding windows
    print(f"\n[*] Creating sliding windows (size={args.window_size}, step={args.step_size})...")
    event_ids = df['EventID'].tolist()
    windows, labels = sliding_window(event_ids, args.window_size, args.step_size)
    print(f"[*] Created {len(windows)} windows")
    
    # Step 4: Load model
    print(f"\n[*] Loading model...")
    model, vocab = load_model_and_vocab(args.model_path, args.vocab_path)
    
    # Step 5: Predict
    print(f"\n[*] Running predictions...")
    anomalies, anomaly_scores = predict(model, vocab, windows, args.topk, args.device)
    
    # Step 6: Results
    print(f"\n{'='*60}")
    print("RESULTS")
    print("="*60)
    
    num_anomalies = sum(anomalies)
    anomaly_rate = num_anomalies / len(anomalies) * 100
    
    print(f"Total windows analyzed: {len(windows)}")
    print(f"Anomalies detected: {num_anomalies} ({anomaly_rate:.2f}%)")
    print(f"Normal windows: {len(anomalies) - num_anomalies} ({100-anomaly_rate:.2f}%)")
    print(f"Average anomaly score: {sum(anomaly_scores)/len(anomaly_scores):.4f}")
    print(f"Max anomaly score: {max(anomaly_scores):.4f}")
    print(f"Min anomaly score: {min(anomaly_scores):.4f}")
    
    # Show top anomalies
    print(f"\nTop 10 Anomalous Windows:")
    print("-" * 60)
    
    # Sort by anomaly score
    sorted_indices = sorted(range(len(anomaly_scores)), 
                          key=lambda i: anomaly_scores[i], 
                          reverse=True)
    
    for rank, idx in enumerate(sorted_indices[:10], 1):
        if anomalies[idx]:
            window_start = idx * args.step_size
            window_end = window_start + args.window_size
            print(f"\n#{rank} Window {idx} (lines {window_start}-{window_end})")
            print(f"   Anomaly Score: {anomaly_scores[idx]:.4f}")
            print(f"   Events: {windows[idx][:3]}...")  # Show first 3 events
    
    print(f"\n{'='*60}")
    print("Testing completed!")
    print("="*60)


if __name__ == "__main__":
    main()
