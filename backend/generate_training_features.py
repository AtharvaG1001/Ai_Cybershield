import os
import pandas as pd
from website_engine.url_analyzer import analyze_url

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE_DIR, "..", "datasets", "PhiUSIIL_Phishing_URL_Dataset.csv")
DST = os.path.join(BASE_DIR, "..", "datasets", "generated_training_dataset.csv")

print("Loading dataset...")
df = pd.read_csv(SRC, usecols=["URL", "label"], encoding="utf-8-sig")
print(f"Loaded {len(df)} URLs")

rows = []
for i, (url, label) in enumerate(zip(df["URL"], df["label"])):
    if i % 20000 == 0:
        print(f"Processed {i}/{len(df)}")
    try:
        features = analyze_url(str(url))
        features["label"] = label
        rows.append(features)
    except Exception as e:
        print(f"Error at row {i}: {e}")

feature_df = pd.DataFrame(rows)
feature_df.to_csv(DST, index=False)
print("\nDataset Generated Successfully!", feature_df.shape)
