import pandas as pd

# Check CSV data quality
df = pd.read_csv('dataset/Windows_EVTX_Combined/combined_dataset_structured.csv')
print(f'Total rows: {len(df)}')
print(f'Columns: {df.columns.tolist()}')
print(f'Null EventIds: {df["EventId"].isna().sum()}')
print(f'Empty EventIds: {(df["EventId"] == "").sum() if df["EventId"].dtype == object else 0}')
print(f'Valid EventIds: {df["EventId"].notna().sum()}')
print(f'\nFirst 10 EventIds:')
print(df["EventId"].head(10).tolist())
print(f'\nDataframe shape: {df.shape}')
print(f'\nEventId dtype: {df["EventId"].dtype}')
