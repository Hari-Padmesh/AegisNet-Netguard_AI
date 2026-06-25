"""
evaluate.py
-----------
Rigorous evaluation for the trained NIDS model.

Why this exists separately from train.py: overall accuracy is close to
meaningless on this kind of data because the majority class (BENIGN)
dominates. What actually matters for an IDS:
  - Per-class precision/recall/F1 (especially recall on rare attacks)
  - False Positive Rate (FPR) — high FPR = alert fatigue = useless IDS
  - Confusion matrix (to see exactly which attacks get mistaken for what)
  - ROC-AUC per class (one-vs-rest)

Run from project root:
    python -m src.evaluate
"""

import json
import os
import pickle

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import label_binarize

MODEL_DIR = "models"
FIGURES_DIR = "reports/figures"


def load_artifacts():
    with open(os.path.join(MODEL_DIR, "best_model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    with open(os.path.join(MODEL_DIR, "metadata.json")) as f:
        metadata = json.load(f)
    return model, scaler, metadata


def compute_fpr_per_class(y_true, y_pred, classes):
    """
    False Positive Rate per class, treating each class as "positive" in turn
    (one-vs-rest). FPR = FP / (FP + TN) — i.e. of all traffic that is NOT
    this class, what fraction got misclassified AS this class.

    This is the metric that determines whether an IDS is actually usable
    in practice — high FPR on BENIGN-vs-attack means constant false alarms.
    """
    cm = confusion_matrix(y_true, y_pred, labels=range(len(classes)))
    fpr_per_class = {}
    for i, cls in enumerate(classes):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fpr_per_class[cls] = fpr
    return fpr_per_class, cm


def plot_confusion_matrix(cm, classes, save_path):
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", xticklabels=classes, yticklabels=classes
    )
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"Saved confusion matrix to {save_path}")


def plot_roc_curves(y_true, y_proba, classes, save_path):
    """One-vs-rest ROC curves, one line per class."""
    y_true_bin = label_binarize(y_true, classes=range(len(classes)))

    plt.figure(figsize=(8, 6))
    for i, cls in enumerate(classes):
        if y_true_bin[:, i].sum() == 0:
            continue  # class not present in this split
        fpr, tpr, _ = roc_curve(y_true_bin[:, i], y_proba[:, i])
        auc = roc_auc_score(y_true_bin[:, i], y_proba[:, i])
        plt.plot(fpr, tpr, label=f"{cls} (AUC={auc:.3f})")

    plt.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curves (One-vs-Rest)")
    plt.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"Saved ROC curves to {save_path}")


def main():
    os.makedirs(FIGURES_DIR, exist_ok=True)

    model, scaler, metadata = load_artifacts()
    classes = metadata["classes"]
    features = metadata["features"]

    test_path = os.path.join("data", "processed", "test_set.csv")
    test_df = pd.read_csv(test_path)
    y_test = test_df["label_encoded"]
    X_test = test_df[features]

    y_pred = model.predict(X_test)

    print("=" * 60)
    print("Classification Report (per-class precision/recall/F1)")
    print("=" * 60)
    report = classification_report(
        y_test, y_pred, target_names=classes, digits=3
    )
    print(report)

    print("=" * 60)
    print("False Positive Rate per class (one-vs-rest)")
    print("=" * 60)
    fpr_per_class, cm = compute_fpr_per_class(y_test, y_pred, classes)
    for cls, fpr in fpr_per_class.items():
        print(f"  {cls:15s}  FPR = {fpr:.4f}")

    plot_confusion_matrix(cm, classes, os.path.join(FIGURES_DIR, "confusion_matrix.png"))

    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)
        plot_roc_curves(y_test, y_proba, classes, os.path.join(FIGURES_DIR, "roc_curves.png"))
    else:
        print("Model has no predict_proba — skipping ROC curves.")

    # Save a results summary for the report/writeup
    summary = {
        "classification_report": classification_report(
            y_test, y_pred, target_names=classes, digits=3, output_dict=True
        ),
        "fpr_per_class": fpr_per_class,
    }
    with open(os.path.join(FIGURES_DIR, "..", "evaluation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved evaluation summary to reports/evaluation_summary.json")


if __name__ == "__main__":
    main()
