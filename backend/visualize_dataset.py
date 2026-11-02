import pandas as pd

df = pd.read_csv("datasets/PhiUSIIL_Phishing_URL_Dataset.csv")

phishing = df[df["label"] == 1]

print(phishing["URL"].head(10))