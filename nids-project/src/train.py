"""
train.py
--------
Trains and compares multiple models for network intrusion detection.

Run from project root:
    python -m src.train --data_dir data/raw/ --top_n_features 20

This will:
  1. Load and clean CICIDS2017 CSVs from data_dir
  2. Encode labels (collapsed into attack families)
  3. Split train/test (stratified)
  4. Select top-N features by RF importance
  5. Scale features
  6. Train: Logistic Regression, Random Forest, XGBoost
  7. 5-fold stratified CV on each
  8. Save the best model + scaler + label list + feature list to models/
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

from src.preprocessing import load_and_clean, encode_labels
from src.features import split_data, scale_features, select_features_by_importance


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
    Run stratified k-fold CV for each model, scoring on macro-F1
    (macro, not weighted/micro — we care about rare attack classes,
    not just overall accuracy which 'Normal' would dominate).
    """
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    results = []

    for name, model in models.items():
        print(f"\nRunning {cv_folds}-fold CV for: {name}")
        start = time.time()
        scores = cross_val_score(
            model,
            X_train,
            y_train,
            cv=skf,
            scoring="f1_macro",
            n_jobs=cv_jobs,
            verbose=0,
        )
        elapsed = time.time() - start
        print(f"  macro-F1 per fold: {np.round(scores, 4)}")
        print(f"  mean: {scores.mean():.4f}  std: {scores.std():.4f}  ({elapsed:.1f}s)")
        results.append(
            {"model": name, "cv_f1_macro_mean": scores.mean(), "cv_f1_macro_std": scores.std()}
        )

    return pd.DataFrame(results).sort_values("cv_f1_macro_mean", ascending=False)


def main():
    parser = argparse.ArgumentParser(description="Train NIDS models on CICIDS2017-style data.")
    parser.add_argument("--data_dir", type=str, default="data/raw/",
                         help="Directory containing raw CSV files.")
    parser.add_argument("--top_n_features", type=int, default=20,
                         help="Number of top features to retain by RF importance.")
    parser.add_argument("--cv_folds", type=int, default=5,
                         help="Number of stratified CV folds.")
    parser.add_argument("--cv_jobs", type=int, default=2,
                         help="Number of threads to use for CV folds.")
    parser.add_argument("--collapse_families", action="store_true", default=True,
                         help="Collapse fine-grained attack labels into families.")
    args = parser.parse_args()

    os.makedirs(MODEL_DIR, exist_ok=True)

    print("=" * 60)
    print("STEP 1: Load and clean data")
    print("=" * 60)
    df = load_and_clean(args.data_dir)

    print("\n" + "=" * 60)
    print("STEP 2: Encode labels")
    print("=" * 60)
    df, classes = encode_labels(df, collapse_to_families=args.collapse_families)
    print(f"Classes ({len(classes)}): {classes}")

    print("\n" + "=" * 60)
    print("STEP 3: Train/test split")
    print("=" * 60)
    X_train, X_test, y_train, y_test = split_data(
        df, label_col="label_encoded", drop_cols=["Label"]
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    print("\n" + "=" * 60)
    print(f"STEP 4: Feature selection (top {args.top_n_features})")
    print("=" * 60)
    top_features = select_features_by_importance(
        X_train, y_train, top_n=args.top_n_features
    )
    print(f"Selected features: {top_features}")
    X_train = X_train[top_features]
    X_test = X_test[top_features]

    print("\n" + "=" * 60)
    print("STEP 5: Scale features")
    print("=" * 60)
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
    print("Scaling complete (StandardScaler fit on train only).")

    print("\n" + "=" * 60)
    print(f"STEP 6: Cross-validated model comparison ({args.cv_folds}-fold, macro-F1)")
    print("=" * 60)
    models = build_models()
    cv_results = run_cv_comparison(
        models,
        X_train_scaled,
        y_train,
        cv_folds=args.cv_folds,
        cv_jobs=args.cv_jobs,
    )
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
    with open(os.path.join(MODEL_DIR, "best_model.pkl"), "wb") as f:
        pickle.dump(best_model, f)
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODEL_DIR, "metadata.json"), "w") as f:
        json.dump(
            {
                "model_name": best_model_name,
                "classes": classes,
                "features": top_features,
                "test_f1_macro": test_f1_macro,
                "cv_results": cv_results.to_dict(orient="records"),
            },
            f,
            indent=2,
        )

    # Save test set for the evaluation script / demo to reuse
    X_test_scaled.assign(label_encoded=y_test.values).to_csv(
        os.path.join("data", "processed", "test_set.csv"), index=False
    )

    print(f"Saved model, scaler, and metadata to {MODEL_DIR}/")
    print("Done.")


if __name__ == "__main__":
    main()
