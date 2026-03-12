"""
Minimal EVTX Anomaly Detection - Only shows file and anomalies
"""
import torch
import pandas as pd
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog
from Evtx.Evtx import Evtx
import xmltodict

def parse_evtx(evtx_file):
    events = []
    try:
        with Evtx(evtx_file) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event_dict = xmltodict.parse(xml_str)
                    event = event_dict.get('Event', {})
                    system = event.get('System', {})
                    
                    event_id = system.get('EventID', {}).get('#text', 'Unknown')
                    if isinstance(event_id, dict):
                        event_id = event_id.get('#text', 'Unknown')
                    
                    provider = system.get('Provider', {}).get('@Name', 'Unknown')
                    event_template = f"{provider} EventID={event_id}"
                    
                    events.append({'EventTemplate': event_template})
                except:
                    continue
    except:
        return None
    
    return pd.DataFrame(events) if events else None

def detect_anomalies(evtx_file, model_path, vocab_path):
    df = parse_evtx(evtx_file)
    if df is None:
        return []
    
    vocab = Vocab.load_vocab(vocab_path)
    model = DeepLog(vocab_size=len(vocab), embedding_dim=128, hidden_size=128, num_layers=2, dropout=0.1)
    
    checkpoint = torch.load(model_path, map_location='cpu')
    if 'model' in checkpoint:
        model.load_state_dict(checkpoint['model'])
    else:
        model.load_state_dict(checkpoint)
    
    model.cpu().eval()
    
    events = df['EventTemplate'].tolist()
    anomalies = []
    
    with torch.no_grad():
        for i in range(0, len(events) - 10 + 1, 5):
            window = events[i:i+10]
            seq_ids = [vocab.get_event(e, use_similar=False) for e in window]
            
            if len(seq_ids) < 10:
                continue
            
            input_seq = torch.tensor(seq_ids[:9], dtype=torch.long).unsqueeze(0)
            batch = {'sequential': input_seq}
            
            output = model(batch)
            logits = output.logits if hasattr(output, 'logits') else output
            
            if logits.dim() == 3:
                logits = logits[0, -1, :]
            elif logits.dim() == 2:
                logits = logits[0, :]
            
            top_k = torch.topk(logits, 9)[1].cpu().numpy()
            
            if seq_ids[9] not in top_k:
                anomalies.append({
                    'line': i + 10,
                    'log': events[i + 9]
                })
    
    return anomalies

if __name__ == "__main__":
    evtx_file = "EVTX-ATTACK-SAMPLES/Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx"
    model_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/models/DeepLog.pt"
    vocab_path = "output/Wintrim/sliding/W10_S5_CFalse_train0.8/vocabs/DeepLog.pkl"
    
    anomalies = detect_anomalies(evtx_file, model_path, vocab_path)
    
    print(f"File: {evtx_file}\n")
    print(f"Anomalies: {len(anomalies)}\n")
    for a in anomalies:
        print(f"Line {a['line']}: {a['log']}")
