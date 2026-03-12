"""
LLM-based Anomaly Filter
Uses LLM as second gate to filter DeepLog anomaly detections
Reduces false positives by semantic understanding
"""
import pandas as pd
from typing import List, Dict, Any
from langchain_community.llms import Ollama
import json


class LLMAnomalyFilter:
    """
    LLM-based filter for anomaly detection results
    Acts as second gate after DeepLog
    """
    
    def __init__(self, ollama_base_url: str = "http://localhost:11434", 
                 ollama_model: str = "sec-foundation:8b-gpu"):
        """
        Initialize LLM filter
        
        Args:
            ollama_base_url: Ollama API URL
            ollama_model: Model name (preferably GPU version)
        """
        self.llm = Ollama(
            base_url=ollama_base_url,
            model=ollama_model,
            temperature=0.3,  # Lower temp for more consistent filtering
            top_p=0.9,
            top_k=40
        )
        
    def filter_anomalies(self, anomalies_df: pd.DataFrame, 
                        parsed_logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Filter anomalies using LLM semantic understanding
        
        Args:
            anomalies_df: DataFrame of DeepLog detected anomalies
            parsed_logs_df: Full parsed logs DataFrame
            
        Returns:
            Filtered DataFrame with only true positives
        """
        print("\n" + "="*60)
        print("LLM ANOMALY FILTERING (Second Gate)")
        print("="*60)
        
        if len(anomalies_df) == 0:
            print("No anomalies to filter")
            return anomalies_df
        
        print(f"\nDeepLog detected: {len(anomalies_df)} anomalies")
        print("Filtering with LLM semantic analysis...\n")
        
        filtered_anomalies = []
        
        for idx, anomaly in anomalies_df.iterrows():
            # Get context window
            start_idx = anomaly['start_idx']
            window_size = 10
            
            # Extract log events in window
            window_logs = parsed_logs_df.iloc[start_idx:start_idx+window_size]
            
            # Create filtering prompt
            is_true_anomaly, reason = self._evaluate_anomaly(anomaly, window_logs)
            
            if is_true_anomaly:
                # Add LLM reasoning to anomaly record
                anomaly_dict = anomaly.to_dict()
                anomaly_dict['llm_reason'] = reason
                anomaly_dict['llm_filtered'] = True
                filtered_anomalies.append(anomaly_dict)
                print(f"✓ Window {anomaly['window_id']}: CONFIRMED - {reason[:80]}...")
            else:
                print(f"✗ Window {anomaly['window_id']}: FILTERED OUT - {reason[:80]}...")
        
        # Convert back to DataFrame
        if filtered_anomalies:
            result_df = pd.DataFrame(filtered_anomalies)
            print(f"\n{'='*60}")
            print(f"LLM Filtering Results:")
            print(f"  Input: {len(anomalies_df)} anomalies")
            print(f"  Output: {len(result_df)} confirmed anomalies")
            print(f"  Filtered: {len(anomalies_df) - len(result_df)} false positives")
            print(f"  Precision improvement: {(len(result_df)/len(anomalies_df))*100:.1f}%")
            print(f"{'='*60}\n")
            return result_df
        else:
            print("\n⚠ All anomalies were filtered out as false positives!\n")
            return pd.DataFrame()
    
    def _evaluate_anomaly(self, anomaly: pd.Series, 
                         window_logs: pd.DataFrame) -> tuple[bool, str]:
        """
        Evaluate if anomaly is true positive using LLM
        
        Args:
            anomaly: Single anomaly record
            window_logs: Log events in anomaly window
            
        Returns:
            (is_true_anomaly: bool, reason: str)
        """
        # Build context
        log_events = []
        for _, log in window_logs.iterrows():
            if 'EventTemplate' in log:
                log_events.append(log['EventTemplate'])
            elif 'Content' in log:
                log_events.append(log['Content'])
        
        context = "\n".join([f"{i+1}. {event}" for i, event in enumerate(log_events)])
        
        # Build prompt
        prompt = f"""You are a cybersecurity expert analyzing Windows system logs.

DeepLog neural network flagged this sequence as ANOMALOUS.

Your task: Determine if this is a TRUE security anomaly or FALSE POSITIVE.

LOG SEQUENCE (in order):
{context}

ANOMALY DETAILS:
- Unexpected Event: {anomaly.get('actual_event', 'N/A')}
- Expected Events: {anomaly.get('expected_events', 'N/A')[:100]}...

EVALUATION CRITERIA:
TRUE ANOMALY indicators:
- Privilege escalation attempts
- Credential dumping (lsass, SAM, mimikatz)
- Lateral movement (Pass-the-Hash, WMI, PsExec)
- Code injection (CreateRemoteThread, process hollowing)
- Persistence mechanisms (registry, scheduled tasks)
- Defense evasion (disabling logs, AV)
- Unusual authentication patterns
- Suspicious process chains

FALSE POSITIVE indicators:
- Normal system operations (updates, maintenance)
- Standard user activities
- Benign admin tasks
- Expected service behaviors

Respond in JSON format:
{{
  "is_true_anomaly": true/false,
  "confidence": "high/medium/low",
  "reason": "Brief explanation in Indonesian (max 100 words)",
  "attack_category": "MITRE ATT&CK category if applicable, or 'benign'"
}}

Response:"""
        
        print(f"\n--- LLM Evaluation for Window {anomaly.get('window_id', 'N/A')} ---")
        print(f"Prompt length: {len(prompt)} chars")
        print(f"Log events in context: {len(log_events)}")
        
        try:
            print("Sending prompt to LLM... (waiting for response)")
            import time
            start_time = time.time()
            response = self.llm.invoke(prompt)
            elapsed = time.time() - start_time
            
            print(f"✓ LLM response received ({elapsed:.2f}s)")
            print(f"\nRaw LLM Response:")
            print("-" * 60)
            print(response[:500] + ("..." if len(response) > 500 else ""))
            print("-" * 60)
            
            # Parse JSON response
            # Handle code blocks if present
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response)
            
            is_anomaly = result.get('is_true_anomaly', False)
            confidence = result.get('confidence', 'medium')
            reason = result.get('reason', 'No reason provided')
            attack_category = result.get('attack_category', 'unknown')
            
            print(f"\nParsed Result:")
            print(f"  Is True Anomaly: {is_anomaly}")
            print(f"  Confidence: {confidence}")
            print(f"  Attack Category: {attack_category}")
            print(f"  Reason: {reason}")
            
            # Build detailed reason
            detailed_reason = f"[{confidence.upper()}] {reason}"
            if attack_category != 'benign':
                detailed_reason += f" | Category: {attack_category}"
            
            return is_anomaly, detailed_reason
            
        except json.JSONDecodeError as e:
            print(f"⚠ Warning: Failed to parse LLM response: {e}")
            print(f"Response was: {response[:200]}")
            # Default to accepting anomaly if parsing fails (conservative approach)
            return True, "LLM response parsing failed, accepting anomaly by default"
        except Exception as e:
            print(f"⚠ Warning: LLM evaluation error: {e}")
            import traceback
            print(traceback.format_exc())
            return True, f"LLM evaluation error: {str(e)}"


if __name__ == "__main__":
    # Test LLM filter
    filter = LLMAnomalyFilter()
    print("LLM Anomaly Filter initialized successfully")
    print(f"Model: {filter.llm.model}")
