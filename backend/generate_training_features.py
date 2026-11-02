import pandas as pd
from website_engine.url_analyzer import analyze_url

print("Loading dataset...")

df = pd.read_csv("datasets/PhiUSIIL_Phishing_URL_Dataset.csv")

print(f"Loaded {len(df)} URLs")

generated_features = []

for index, row in df.iterrows():

    if index % 1000 == 0:
        print(f"Processed {index}/{len(df)}")

    url = row["URL"]

    try:
        features = analyze_url(url)
        features["label"] = row["label"]
        generated_features.append(features)

    except Exception as e:
        print(f"Error at row {index}: {e}")

feature_df = pd.DataFrame(generated_features)

feature_df.to_csv(
    "datasets/generated_training_dataset.csv",
    index=False
)

print("\nDataset Generated Successfully!")
print(feature_df.head())
print(feature_df.shape)