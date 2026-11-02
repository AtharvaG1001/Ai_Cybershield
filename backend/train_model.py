"""
Retrain the phishing detection model with improved settings.

Key improvements over original phising_model.py:
1. Uses HistGradientBoostingClassifier which handles data better
2. Saves feature_names.json for validation at inference time
3. Saves model_metadata.json with version and training config
4. Proper stratified split to prevent class imbalance issues
5. Evaluates on test set (not training set)
6. Saves evaluation metrics to database
"""

import os
import sys
import json
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "generated_training_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def train():
    print("=" * 60)
    print("AI CyberShield — Model Training")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        print("Run generate_training_features.py first.")
        return False

    print(f"[+] Loading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Dataset shape: {df.shape}")

    X = df.drop("label", axis=1)
    y = df["label"]
    feature_names = list(X.columns)

    print(f"[+] Feature count: {len(feature_names)}")
    print(f"[+] Label distribution:")
    for label, count in y.value_counts().items():
        name = "PHISHING" if label == 0 else "LEGITIMATE"
        print(f"    {name} (label={label}): {count:,} ({count/len(y)*100:.1f}%)")

    # Stratified split — same seed for reproducibility
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[+] Train size: {len(X_train):,}  Test size: {len(X_test):,}")

    # HistGradientBoosting handles missing values natively and is faster
    # than RF on large datasets, with better calibrated probabilities
    print("[+] Training HistGradientBoostingClassifier...")
    model = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.05,
        max_depth=6,
        min_samples_leaf=20,
        random_state=42,
    )
    model.fit(X_train, y_train)
    print("[+] Training complete.")

    # Evaluate on test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    # class 0 = phishing, class 1 = legitimate
    classes = list(model.classes_)
    phishing_idx = classes.index(0)
    phishing_prob = y_prob[:, phishing_idx]

    # Binary: 1=phishing, 0=legitimate
    y_test_binary = (y_test == 0).astype(int)
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
    print(f"  False Positive Rate   : {fpr:.4f}  (legit sites wrongly flagged)")
    print(f"  False Negative Rate   : {fnr:.4f}  (phishing sites missed)")
    print(f"\nConfusion Matrix (positive=phishing):")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")
    print(f"\n{classification_report(y_test_binary, y_pred_binary, target_names=['LEGITIMATE','PHISHING'])}")

    # Sanity check: test a clearly legitimate URL pattern
    from website_engine.url_analyzer import analyze_url
    google_feats = analyze_url("https://www.google.com")
    test_df = pd.DataFrame([google_feats])[feature_names]
    google_pred = model.predict(test_df)[0]
    google_prob = model.predict_proba(test_df)[0]
    google_phish_prob = google_prob[phishing_idx]
    print(f"\n[SANITY] google.com -> class {google_pred} "
          f"(0=phishing,1=legit), phishing_prob={google_phish_prob:.3f}")
    if google_phish_prob > 0.5:
        print("[WARNING] google.com has high phishing probability — model may overfit")

    # Save model
    model_path = os.path.join(MODEL_DIR, "phishing_model_custom.pkl")
    joblib.dump(model, model_path)
    print(f"\n[+] Model saved: {model_path}")

    # Save feature names
    feat_path = os.path.join(MODEL_DIR, "feature_names.json")
    with open(feat_path, "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"[+] Feature names saved: {feat_path}")

    # Save metadata
    meta = {
        "model_version": "2.0.0",
        "model_type": type(model).__name__,
        "n_features": len(feature_names),
        "dataset": "PhiUSIIL_Phishing_URL_Dataset",
        "label_mapping": {"0": "PHISHING", "1": "LEGITIMATE"},
        "trained_at": datetime.utcnow().isoformat(),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
        },
    }
    meta_path = os.path.join(MODEL_DIR, "model_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[+] Metadata saved: {meta_path}")

    # Save to database
    try:
        from database import SessionLocal, ModelEvaluation, create_tables
        create_tables()
        db = SessionLocal()
        record = ModelEvaluation(
            model_version="2.0.0",
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
        db.close()
        print("[+] Evaluation metrics saved to database.")
    except Exception as e:
        print(f"[!] Database save failed: {e}")

    return True


if __name__ == "__main__":
    success = train()
    if success:
        print("\n[✓] Training pipeline complete.")
        print("    Restart the FastAPI server to load the new model.")
    else:
        print("\n[✗] Training failed.")
        sys.exit(1)
