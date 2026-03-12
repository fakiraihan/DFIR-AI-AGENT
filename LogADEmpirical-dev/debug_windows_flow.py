import pandas as pd
from logadempirical.data.grouping import fixed_window
from sklearn.utils import shuffle

# Simulate the exact flow from data_loader.py
data_dir = "./dataset/Windows_EVTX_Combined"
log_file = "combined_dataset_structured"
window_size = 10
step_size = 5
train_size = 0.7
is_chronological = False

print("=" * 80)
print("STEP 1: Loading CSV")
print("=" * 80)
df = pd.read_csv(f'{data_dir}/{log_file}.csv')
print(f"Loaded DataFrame shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"First few rows:")
print(df.head(3))

print("\n" + "=" * 80)
print("STEP 2: Converting Label") 
print("=" * 80)
df["Label"] = df["Label"].apply(lambda x: int(x != "-"))
print(f"Label conversion done. Label value counts:")
print(df["Label"].value_counts())

print("\n" + "=" * 80)
print("STEP 3: Fixed window (BEFORE shuffle)")
print("=" * 80)
print(f"Input to fixed_window: df.shape = {df[['Label', 'EventId', 'EventTemplate', 'Content']].shape}")
window_df = fixed_window(
    df[["Label", "EventId", "EventTemplate", "Content"]],
    window_size=window_size,
    step_size=step_size
)
print(f"OUTPUT from fixed_window: {len(window_df)} windows generated")
print(f"Type: {type(window_df)}")
if len(window_df) > 0:
    print(f"First window: {window_df[0]}")
    print(f"Last window: {window_df[-1]}")

print("\n" + "=" * 80)
print("STEP 4: Shuffle")
print("=" * 80)
window_df = shuffle(window_df)
print(f"After shuffle: {len(window_df)} windows")

print("\n" + "=" * 80)
print("STEP 5: Train/Test Split")
print("=" * 80)
n_train = int(len(window_df) * train_size)
print(f"n_train = int({len(window_df)} * {train_size}) = {n_train}")
train_window = window_df[:n_train]
test_window = window_df[n_train:]
print(f"Train sequences: {len(train_window)}")
print(f"Test sequences: {len(test_window)}")

print("\n" + "=" * 80)
print("EXPECTED vs ACTUAL")
print("=" * 80)
expected_windows = (12939 - window_size) // step_size + 1
print(f"Expected windows: ~{expected_windows} (from 12,939 events with window_size={window_size}, step_size={step_size})")
print(f"Actual windows: {len(window_df)}")
print(f"Data loss: {100 * (1 - len(window_df) / expected_windows):.2f}%")
