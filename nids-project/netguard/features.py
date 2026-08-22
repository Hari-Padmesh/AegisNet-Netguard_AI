"""
netguard/features.py
---------------------
Feature scaling and selection utilities.
"""

from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def split_data(
    df: pd.DataFrame,
    label_col: str = "label_encoded",
    drop_cols: Optional[List[str]] = None,
    test_size: float = 0.2,
    random_state: int = 42,
    stratify: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Split into train/test sets, stratified by label by default.
    """
    drop_cols = drop_cols or []
    drop_cols = list(set(drop_cols + [label_col]))

    feature_cols = [c for c in df.columns if c not in drop_cols]
    X = df[feature_cols]
    y = df[label_col]

    strat = y if stratify else None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=strat
    )

    return X_train, X_test, y_train, y_test


def scale_features(
    X_train: pd.DataFrame, X_test: pd.DataFrame
) -> Tuple[pd.DataFrame, pd.DataFrame, StandardScaler]:
    """
    Fit a StandardScaler on X_train only, apply to both train and test.
    Critical: never fit the scaler on test data (data leakage).
    """
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns, index=X_test.index
    )
    return X_train_scaled, X_test_scaled, scaler


def select_features_by_importance(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    top_n: int = 20,
    random_state: int = 42,
) -> List[str]:
    """
    Quick feature selection: fit a Random Forest, return the top_n
    most important features by Gini importance.
    """
    rf = RandomForestClassifier(
        n_estimators=100, random_state=random_state, n_jobs=-1, max_depth=15
    )
    rf.fit(X_train, y_train)

    importances = pd.Series(rf.feature_importances_, index=X_train.columns)
    top_features = importances.sort_values(ascending=False).head(top_n).index.tolist()

    return top_features
