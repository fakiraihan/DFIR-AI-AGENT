import pickle
import pandas as pd

# Load data
train = pickle.load(open('output/EVTX/sliding/W10_S5_CFalse_train0.7/train.pkl', 'rb'))
test = pickle.load(open('output/EVTX/sliding/W10_S5_CFalse_train0.7/test.pkl', 'rb'))

print(f"Train sessions: {len(train)}")
print(f"Test sessions: {len(test)}")

# Check labels
train_df = pd.DataFrame(train)
print(f"\nTrain labels distribution:")
print(train_df['Label'].value_counts())

print(f"\nTest labels distribution:")
test_df = pd.DataFrame(test)
print(test_df['Label'].value_counts())

# Check session lengths
train_lengths = [len(s['EventId']) for s in train]
test_lengths = [len(s['EventId']) for s in test]

print(f"\nTrain session EventId counts:")
print(f"  Min: {min(train_lengths)}, Max: {max(train_lengths)}, Avg: {sum(train_lengths)/len(train_lengths):.2f}")

print(f"\nTest session EventId counts:")
print(f"  Min: {min(test_lengths)}, Max: {max(test_lengths)}, Avg: {sum(test_lengths)/len(test_lengths):.2f}")

print(f"\nSample train session:")
print(f"  SessionId: {train[0]['SessionId']}")
print(f"  EventId count: {len(train[0]['EventId'])}")
print(f"  First 3 EventIds: {train[0]['EventId'][:3]}")
print(f"  Label: {train[0]['Label']}")
