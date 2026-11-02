"""
Model Evaluation Pipeline
=========================
Evaluates the trained phishing detection model on a held-out test set.
Results are stored in the database for display on the Model Evaluation page.

Run:  python evaluate_model.py

This script:
1. Loads the generated_training_dataset.csv
2. Splits it reproducibly (same seed as training)
3. Evaluates on the test split (never seen during training)
4. Saves metrics to the database
"""

import os
import sys
import json
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model_custom.pkl")
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, "models", "feature_names.json")
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "generated_training_dataset.csv")


def evaluate():
    print("=" * 60)
    print("AI CyberShield — Model Evaluation")
    print("=" * 60)

    # Load model
    if not os.path.exists(MODEL_PATH):
        print(f"ERROR: Model not found at {MODEL_PATH}")
        return

    model = joblib.load(MODEL_PATH)
    print(f"[+] Loaded model: {type(model).__name__}")

    # Load feature names
    if os.path.exists(FEATURE_NAMES_PATH):
        with open(FEATURE_NAMES_PATH) as f:
            feature_names = json.load(f)
    else:
        feature_names = None
        print("[!] feature_names.json not found — using DataFrame column order")

    # Load dataset
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        return

    print(f"[+] Loading dataset from {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Dataset shape: {df.shape}")

    X = df.drop("label", axis=1)
    y = df["label"]

    if feature_names:
        X = X[feature_names]

    print(f"[+] Label distribution:")
    for label, count in y.value_counts().items():
        name = "PHISHING" if label == 0 else "LEGITIMATE"
        print(f"    {name} (label={label}): {count:,} ({count/len(y)*100:.1f}%)")

    # Reproduce same split as training
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[+] Test set size: {len(X_test):,}")

    # Predict
    print("[+] Running predictions...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    # Classes: 0=phishing, 1=legitimate
    phishing_prob = y_prob[:, list(model.classes_).index(0)]

    # Metrics (positive class = 0 = phishing)
    # We binary_treat: 1 if phishing (label=0), 0 if legitimate (label=1)
    y_test_binary = (y_test == 0).astype(int)  # 1=phishing
    y_pred_binary = (y_pred == 0).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
    roc_auc = roc_auc_score(y_test_binary, phishing_prob)

    cm = confusion_matrix(y_test_binary, y_pred_binary)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print(f"\n{'='*60}")
    print("EVALUATION RESULTS (Test Set)")
    print(f"{'='*60}")
    print(f"  Accuracy              : {acc:.4f}")
    print(f"  Precision (phishing)  : {prec:.4f}")
    print(f"  Recall (phishing)     : {rec:.4f}")
    print(f"  F1-Score (phishing)   : {f1:.4f}")
    print(f"  ROC-AUC               : {roc_auc:.4f}")
    print(f"  False Positive Rate   : {fpr:.4f}")
    print(f"  False Negative Rate   : {fnr:.4f}")
    print(f"\nConfusion Matrix (positive=phishing):")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")

    print(f"\n{classification_report(y_test_binary, y_pred_binary, target_names=['LEGITIMATE', 'PHISHING'])}")

    # Save to database
    from database import SessionLocal, ModelEvaluation, create_tables
    create_tables()
    db = SessionLocal()
    try:
        record = ModelEvaluation(
            model_version="1.0.0",
            dataset_id="PhiUSIIL_Phishing_URL_Dataset",
            evaluated_at=datetime.utcnow(),
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            roc_auc=round(roc_auc, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            dataset_size=len(X_test),
            phishing_count=int((y_test == 0).sum()),
            legitimate_count=int((y_test == 1).sum()),
            confusion_matrix=json.dumps([[int(tn), int(fp)], [int(fn), int(tp)]]),
        )
        db.add(record)
        db.commit()
        print("[+] Evaluation results saved to database.")
    except Exception as e:
        print(f"[!] Failed to save to database: {e}")
    finally:
        db.close()

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "fnr": fnr,
    }


if __name__ == "__main__":
    evaluate()
