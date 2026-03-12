import pandas as pd
import pickle

# Load the generated train.pkl file
with open('output/Windows_EVTX_Combined/sliding/W10_S5_CFalse_train0.7/train.pkl', 'rb') as f:
    train_data = pickle.load(f)

print(f"Total train windows in pkl: {len(train_data)}")

# Check label distribution
label_0_count = 0
label_1_count = 0
for seq in train_data:
    if isinstance(seq['Label'], list):
        label = max(seq['Label'])
    else:
        label = seq['Label']
    
    if label == 0:
        label_0_count += 1
    else:
        label_1_count += 1

print(f"Windows with label=0 (normal): {label_0_count}")
print(f"Windows with label>0 (anomalous): {label_1_count}")
print(f"\nPERCENTAGE with label=0: {100 * label_0_count / len(train_data):.2f}%")

# Show first few windows
print(f"\nFirst 3 windows:")
for i in range(min(3, len(train_data))):
    label = max(train_data[i]['Label']) if isinstance(train_data[i]['Label'], list) else train_data[i]['Label']
    print(f"Window {i}: Label={label}, Events={len(train_data[i]['EventId'])}")
