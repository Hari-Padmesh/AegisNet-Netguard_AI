"""
netguard/train.py
------------------
Trains and compares multiple models for network intrusion detection.

Can be invoked via CLI: netguard train
Or run directly: python -m netguard.train --data_dir data/raw/
"""

import argparse
import json
import os
import pickle
import time

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import f1_score
from xgboost import XGBClassifier

from netguard.preprocessing import load_and_clean, encode_labels
from netguard.features import split_data, scale_features, select_features_by_importance

MODEL_DIR = "models"


def build_models(random_state: int = 42) -> dict:
    """Return a dict of {name: model} to compare."""
    return {
        "logistic_regression": LogisticRegression(
            solver="lbfgs",
            max_iter=5000,
            class_weight="balanced",
            random_state=random_state,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=random_state,
            n_jobs=1,
            tree_method="hist",
            eval_metric="mlogloss",
        ),
    }


def run_cv_comparison(
    models: dict,
    X_train,
    y_train,
    cv_folds: int = 5,
    cv_jobs: int = -1,
) -> pd.DataFrame:
    """
    Run stratified k-fold CV for each model, scoring on macro-F1.
    Macro-F1 is used because accuracy would be dominated by the BENIGN class.
    """
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    results = []

    for name, model in models.items():
        print(f"\nRunning {cv_folds}-fold CV for: {name}")
        start = time.time()
        scores = cross_val_score(
            model, X_train, y_train,
            cv=skf, scoring="f1_macro", n_jobs=cv_jobs, verbose=0,
        )
        elapsed = time.time() - start
        print(f"  macro-F1 per fold: {np.round(scores, 4)}")
        print(f"  mean: {scores.mean():.4f}  std: {scores.std():.4f}  ({elapsed:.1f}s)")
        results.append({
            "model": name,
            "cv_f1_macro_mean": scores.mean(),
            "cv_f1_macro_std": scores.std(),
        })

    return pd.DataFrame(results).sort_values("cv_f1_macro_mean", ascending=False)


def train_pipeline(
    data_dir: str = "data/raw/",
    top_n_features: int = 20,
    cv_folds: int = 5,
    cv_jobs: int = 2,
    collapse_families: bool = True,
    model_dir: str = MODEL_DIR,
) -> dict:
    """
    Full training pipeline. Returns metadata dict.
    Can be called programmatically or via CLI.
    """
    os.makedirs(model_dir, exist_ok=True)

    print("=" * 60)
    print("STEP 1: Load and clean data")
    print("=" * 60)
    df = load_and_clean(data_dir)

    print("\n" + "=" * 60)
    print("STEP 2: Encode labels")
    print("=" * 60)
    df, classes = encode_labels(df, collapse_to_families=collapse_families)
    print(f"Classes ({len(classes)}): {classes}")

    print("\n" + "=" * 60)
    print("STEP 3: Train/test split")
    print("=" * 60)
    X_train, X_test, y_train, y_test = split_data(
        df, label_col="label_encoded", drop_cols=["Label"]
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    print("\n" + "=" * 60)
    print(f"STEP 4: Feature selection (top {top_n_features})")
    print("=" * 60)
    top_features = select_features_by_importance(X_train, y_train, top_n=top_n_features)
    print(f"Selected features: {top_features}")
    X_train = X_train[top_features]
    X_test = X_test[top_features]

    print("\n" + "=" * 60)
    print("STEP 5: Scale features")
    print("=" * 60)
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
    print("Scaling complete (StandardScaler fit on train only).")

    print("\n" + "=" * 60)
    print(f"STEP 6: Cross-validated model comparison ({cv_folds}-fold, macro-F1)")
    print("=" * 60)
    models = build_models()
    cv_results = run_cv_comparison(models, X_train_scaled, y_train, cv_folds=cv_folds, cv_jobs=cv_jobs)
    print("\nCV Results summary:")
    print(cv_results.to_string(index=False))

    best_model_name = cv_results.iloc[0]["model"]
    print(f"\nBest model by CV macro-F1: {best_model_name}")

    print("\n" + "=" * 60)
    print(f"STEP 7: Fit best model ({best_model_name}) on full train set")
    print("=" * 60)
    best_model = models[best_model_name]
    best_model.fit(X_train_scaled, y_train)

    test_preds = best_model.predict(X_test_scaled)
    test_f1_macro = f1_score(y_test, test_preds, average="macro")
    print(f"Held-out test macro-F1: {test_f1_macro:.4f}")

    print("\n" + "=" * 60)
    print("STEP 8: Save artifacts")
    print("=" * 60)
    with open(os.path.join(model_dir, "best_model.pkl"), "wb") as f:
        pickle.dump(best_model, f)
    with open(os.path.join(model_dir, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)

    metadata = {
        "model_name": best_model_name,
        "classes": classes,
        "features": top_features,
        "test_f1_macro": test_f1_macro,
        "cv_results": cv_results.to_dict(orient="records"),
    }
    with open(os.path.join(model_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    os.makedirs(os.path.join("data", "processed"), exist_ok=True)
    X_test_scaled.assign(label_encoded=y_test.values).to_csv(
        os.path.join("data", "processed", "test_set.csv"), index=False
    )

    print(f"Saved model, scaler, and metadata to {model_dir}/")
    print("Done.")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Train NIDS models on CICIDS2017-style data.")
    parser.add_argument("--data_dir", type=str, default="data/raw/")
    parser.add_argument("--top_n_features", type=int, default=20)
    parser.add_argument("--cv_folds", type=int, default=5)
    parser.add_argument("--cv_jobs", type=int, default=2)
    parser.add_argument("--collapse_families", action="store_true", default=True)
    args = parser.parse_args()

    train_pipeline(
        data_dir=args.data_dir,
        top_n_features=args.top_n_features,
        cv_folds=args.cv_folds,
        cv_jobs=args.cv_jobs,
        collapse_families=args.collapse_families,
    )


if __name__ == "__main__":
    main()
