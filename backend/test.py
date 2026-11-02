import pandas as pd
df = pd.read_csv("datasets/combined_emails.csv")
print(df['label'].value_counts().sort_index())