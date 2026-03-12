"""
DeepLog Anomaly Detection Module
Integrates trained DeepLog model for log anomaly detection
"""
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import pandas as pd
import torch
import torch.nn as nn
import pickle
import numpy as np
from tqdm import tqdm

# Add LogADEmpirical to path
LOGAD_PATH = Path(__file__).parent.parent.parent.parent / "LogADEmpirical-dev"
sys.path.insert(0, str(LOGAD_PATH))

# Import from existing LogADEmpirical implementation
from logadempirical.models.lstm import DeepLog as DeepLogModel
from logadempirical.data.vocab import Vocab


class DeepLogDetector:
    """
    DeepLog-based anomaly detector for log sequences
    """
    
    def __init__(
        self,
        model_path: str,
        vocab_path: str,
        window_size: int = 10,
        step_size: int = 5,
        topk: int = 9,
        device: str = 'cpu'
    ):
        """
        Initialize DeepLog detector
        
        Args:
            model_path: Path to trained DeepLog model (.pt file)
            vocab_path: Path to vocabulary file (.pkl file)
            window_size: Sliding window size
            step_size: Step size for sliding window
            topk: Number of top predictions to consider (lower = stricter)
            device: Device for inference ('cpu' or 'cuda')
        """
        self.window_size = window_size
        self.step_size = step_size
        self.topk = topk
        self.device = device
        
        # Load vocabulary
        print(f"Loading vocabulary from {vocab_path}")
        with open(vocab_path, 'rb') as f:
            self.vocab = pickle.load(f)
        
        print(f"Vocabulary size: {len(self.vocab)}")
        
        # Load model
        print(f"Loading DeepLog model from {model_path}")
        checkpoint = torch.load(model_path, map_location=device)
        
        # Initialize model architecture
        # Get vocab size from loaded vocab
        vocab_size = len(self.vocab)
        
        self.model = DeepLogModel(
            vocab_size=vocab_size,
            embedding_dim=128,
            hidden_size=128,
            num_layers=2,
            dropout=0.5,
            criterion=None
        )
        
        # Load model weights - the checkpoint stores model state directly
        if isinstance(checkpoint, dict) and 'model' in checkpoint:
            self.model.load_state_dict(checkpoint['model'])
        else:
            # Fallback: checkpoint might be the state dict itself
            self.model.load_state_dict(checkpoint)
        
        self.model.to(device)
        self.model.eval()
        
        print("DeepLog model loaded successfully")
    
    def create_sliding_windows(self, templates: List[str]) -> List[Tuple[List[str], str]]:
        """
        Create sliding windows from log template sequence
        
        Args:
            templates: List of event templates
            
        Returns:
            List of (window, next_event) tuples
        """
        windows = []
        
        for i in range(0, len(templates) - self.window_size, self.step_size):
            window = templates[i:i + self.window_size]
            if i + self.window_size < len(templates):
                next_event = templates[i + self.window_size]
                windows.append((window, next_event))
        
        return windows
    
    def templates_to_indices(self, templates: List[str]) -> List[int]:
        """
        Convert templates to vocabulary indices
        
        Args:
            templates: List of event templates
            
        Returns:
            List of vocabulary indices
        """
        indices = []
        for template in templates:
            # Get index from vocab, use <UNK> token if not found
            if hasattr(self.vocab, 'stoi'):
                idx = self.vocab.stoi.get(template, self.vocab.stoi.get('<UNK>', 0))
            else:
                # Fallback for different vocab implementations
                idx = self.vocab.get(template, 0)
            indices.append(idx)
        
        return indices
    
    def predict_topk(self, window_indices: List[int]) -> List[int]:
        """
        Get top-k predictions for next event given window
        
        Args:
            window_indices: List of vocabulary indices for window
            
        Returns:
            List of top-k predicted indices
        """
        with torch.no_grad():
            # Convert to tensor
            x = torch.tensor([window_indices], dtype=torch.long).to(self.device)
            
            # Create batch dict as expected by DeepLog model
            batch = {'sequential': x}
            
            # Get prediction
            output = self.model(batch, device=self.device)
            logits = output.logits  # Shape: (1, vocab_size)
            
            # Get top-k predictions
            topk_probs, topk_indices = torch.topk(logits[0], self.topk)
            
            return topk_indices.cpu().numpy().tolist()
    
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect anomalies in parsed log dataframe
        
        Args:
            df: DataFrame from Drain parser with 'event_template' column
            
        Returns:
            DataFrame with anomaly detection results
        """
        print(f"Starting anomaly detection on {len(df)} events")
        
        # Extract templates
        templates = df['event_template'].tolist()
        
        # Create sliding windows
        windows = self.create_sliding_windows(templates)
        print(f"Created {len(windows)} sliding windows")
        
        if len(windows) == 0:
            print("No windows created - log sequence too short")
            return pd.DataFrame(columns=['window_id', 'start_idx', 'end_idx', 'is_anomaly', 'actual_event', 'predicted_events'])
        
        # Detect anomalies
        results = []
        anomaly_count = 0
        
        for idx, (window, next_event) in enumerate(tqdm(windows, desc="Detecting anomalies")):
            # Convert to indices
            window_indices = self.templates_to_indices(window)
            next_event_idx = self.templates_to_indices([next_event])[0]
            
            # Get top-k predictions
            topk_predictions = self.predict_topk(window_indices)
            
            # Check if actual next event is in top-k
            is_anomaly = next_event_idx not in topk_predictions
            
            if is_anomaly:
                anomaly_count += 1
            
            # Store result
            start_idx = idx * self.step_size
            end_idx = start_idx + self.window_size
            
            results.append({
                'window_id': idx,
                'start_idx': start_idx,
                'end_idx': end_idx,
                'is_anomaly': is_anomaly,
                'actual_event': next_event,
                'predicted_events': ','.join([str(p) for p in topk_predictions]),
                'window_templates': ' | '.join(window)
            })
        
        results_df = pd.DataFrame(results)
        anomaly_rate = (anomaly_count / len(windows)) * 100 if windows else 0
        
        print(f"\nAnomaly Detection Results:")
        print(f"Total Windows: {len(windows)}")
        print(f"Anomalies Detected: {anomaly_count}")
        print(f"Anomaly Rate: {anomaly_rate:.2f}%")
        
        return results_df
    
    def get_anomalous_windows(self, results_df: pd.DataFrame) -> pd.DataFrame:
        """
        Filter only anomalous windows
        
        Args:
            results_df: DataFrame from detect_anomalies
            
        Returns:
            DataFrame with only anomalous windows
        """
        anomalies = results_df[results_df['is_anomaly'] == True].copy()
        return anomalies


def detect_anomalies_in_logs(
    parsed_df: pd.DataFrame,
    model_path: str,
    vocab_path: str,
    **kwargs
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Convenience function to detect anomalies in parsed logs
    
    Args:
        parsed_df: DataFrame from Drain parser
        model_path: Path to DeepLog model
        vocab_path: Path to vocabulary
        **kwargs: Additional parameters for DeepLogDetector
        
    Returns:
        Tuple of (all_results_df, anomalies_only_df)
    """
    detector = DeepLogDetector(model_path, vocab_path, **kwargs)
    results_df = detector.detect_anomalies(parsed_df)
    anomalies_df = detector.get_anomalous_windows(results_df)
    
    return results_df, anomalies_df


if __name__ == "__main__":
    # Test anomaly detection
    from modules.parsing import parse_log_file
    
    # Paths
    test_file = LOGAD_PATH / "EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx"
    model_path = LOGAD_PATH / "output" / "Wintrim" / "sliding" / "W10_S5_CFalse_train0.8" / "models" / "DeepLog.pt"
    vocab_path = LOGAD_PATH / "output" / "Wintrim" / "sliding" / "W10_S5_CFalse_train0.8" / "vocabs" / "DeepLog.pkl"
    
    if test_file.exists() and model_path.exists() and vocab_path.exists():
        # Parse logs
        print("=== PARSING ===")
        df, templates = parse_log_file(str(test_file))
        
        # Detect anomalies
        print("\n=== ANOMALY DETECTION ===")
        results_df, anomalies_df = detect_anomalies_in_logs(
            df,
            str(model_path),
            str(vocab_path),
            window_size=10,
            step_size=5,
            topk=9
        )
        
        print("\n=== ANOMALOUS WINDOWS ===")
        print(anomalies_df[['window_id', 'start_idx', 'end_idx', 'actual_event']].head())
