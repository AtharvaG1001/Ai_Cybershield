import pandas as pd

# Load dataset
df = pd.read_csv("datasets\PhiUSIIL_Phishing_URL_Dataset.csv")   # Change filename if needed

print("=" * 50)
print("First 5 Rows")
print(df.head())

print("\n" + "=" * 50)
print("Dataset Information")
print(df.info())

print("\n" + "=" * 50)
print("Column Names")
print(df.columns)

print("\n" + "=" * 50)
print("Missing Values")
print(df.isnull().sum())

print("\n" + "=" * 50)
print("Duplicate Rows")
print(df.duplicated().sum())

print("\n" + "=" * 50)
print("Dataset Shape")
print(df.shape)