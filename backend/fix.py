#!/usr/bin/env python3
"""
=============================================================
QUICK FIX: Add missing PHISHING class to combined_emails.csv
=============================================================
Run this if your combined_emails.csv is missing label 3 (PHISHING)
"""

import pandas as pd
import os

DATASET_DIR = "datasets"

def fix_combined_dataset():
    print("=" * 60)
    print("AI SHIELD — Dataset Fix & Rebalance")
    print("=" * 60)

    # Load existing combined
    combined_path = os.path.join(DATASET_DIR, "combined_emails.csv")
    if not os.path.exists(combined_path):
        print(f"[!] {combined_path} not found!")
        return

    df = pd.read_csv(combined_path)
    print(f"[+] Loaded combined_emails.csv: {len(df)} samples")
    print(f"    Current labels: {sorted(df['label'].unique())}")

    # Check if phishing already exists
    if 3 in df['label'].values:
        print("[✓] PHISHING class (label 3) already exists. No fix needed.")
        return

    # Try to load phishing dataset with various possible filenames
    phishing_files = [
        "phishing_email.csv",
        "phishing_emails.csv", 
        "phishing_email_dataset.csv",
        "Phishing_email.csv"
    ]

    phishing_df = None
    for fname in phishing_files:
        fpath = os.path.join(DATASET_DIR, fname)
        if os.path.exists(fpath):
            print(f"[+] Found phishing dataset: {fname}")
            phishing_raw = pd.read_csv(fpath)

            # Auto-detect text column
            text_col = None
            possible_cols = ['Email Text', 'email', 'text', 'body', 'message', 'content', 'Email']
            for col in possible_cols:
                if col in phishing_raw.columns:
                    text_col = col
                    break

            if text_col is None:
                text_col = phishing_raw.columns[0]
                print(f"    Using first column as text: '{text_col}'")
            else:
                print(f"    Detected text column: '{text_col}'")

            phishing_df = pd.DataFrame({
                'text': phishing_raw[text_col].astype(str).str[:3000],
                'label': 3,  # PHISHING
                'source': 'phishing'
            })
            break

    if phishing_df is None:
        print("[!] ERROR: Could not find phishing dataset!")
        print("    Looked for:")
        for f in phishing_files:
            print(f"      - datasets/{f}")
        print("\n    Please ensure your phishing dataset is in the datasets/ folder.")
        return

    # Combine
    df_combined = pd.concat([df, phishing_df], ignore_index=True)
    print(f"\n[+] Added {len(phishing_df)} PHISHING samples")
    print(f"    New total: {len(df_combined)} samples")

    # Show distribution
    dist = df_combined['label'].value_counts().sort_index()
    print(f"\n    Class distribution:")
    label_names = {0: 'REAL', 1: 'BUSINESS', 2: 'ADVERTISEMENT', 3: 'PHISHING'}
    for label, count in dist.items():
        print(f"      {label_names.get(label, label)}: {count}")

    # Save
    df_combined.to_csv(combined_path, index=False)
    print(f"\n[✓] Saved to: {combined_path}")

    # Now rebalance
    print("\n" + "=" * 60)
    print("Rebalancing dataset...")
    print("=" * 60)

    TARGET_PER_CLASS = 5000
    frames = []

    for label in sorted(df_combined['label'].unique()):
        class_df = df_combined[df_combined['label'] == label].copy()
        current = len(class_df)
        name = label_names.get(label, f'Label {label}')

        if current > TARGET_PER_CLASS:
            class_df = class_df.sample(n=TARGET_PER_CLASS, random_state=42)
            print(f"\n    {name}: {current} → {TARGET_PER_CLASS} (DOWNSAMPLED)")
        elif current < TARGET_PER_CLASS:
            needed = TARGET_PER_CLASS - current
            originals = class_df['text'].tolist()
            new_samples = []

            for i in range(needed):
                original = str(random.choice(originals))
                # Simple augmentation
                words = original.split()
                if len(words) > 10 and i % 3 == 0:
                    # Shuffle some words
                    mid = words[3:-3]
                    random.shuffle(mid)
                    augmented = ' '.join(words[:3] + mid + words[-3:])
                else:
                    augmented = original
                new_samples.append(augmented)

            aug_df = pd.DataFrame({'text': new_samples, 'label': label})
            class_df = pd.concat([class_df, aug_df], ignore_index=True)
            print(f"\n    {name}: {current} → {len(class_df)} (AUGMENTED +{needed})")
        else:
            print(f"\n    {name}: {current} (PERFECT)")

        frames.append(class_df)

    balanced = pd.concat(frames, ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    balanced.to_csv(combined_path, index=False)

    print("\n" + "=" * 60)
    print("[✓] Dataset fixed & rebalanced!")
    print(f"    Total: {len(balanced)} samples")
    print("    Final distribution:")
    for label, count in balanced['label'].value_counts().sort_index().items():
        pct = count / len(balanced) * 100
        print(f"      {label_names.get(label, label):15s}: {count:5d} ({pct:5.1f}%)")
    print("=" * 60)
    print("\n[→] Now run: python email_detector.py")

if __name__ == "__main__":
    import random
    fix_combined_dataset()