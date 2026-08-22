"""
netguard/preprocessing.py
--------------------------
Cleaning and preparation utilities for CICIDS2017-style network flow data.

Handles known quirks of the CICIDS2017 dataset:
- Leading/trailing whitespace in column names
- Inf/NaN values in flow-byte/packet-rate columns
- Inconsistent label strings (e.g. "DoS Hulk" vs "DoS Hulk ")
- Zero-variance columns that add noise without signal
"""

import glob
import os
import re
from typing import Tuple, List

import numpy as np
import pandas as pd

# Standard attack-family collapsing map for CICIDS2017 fine-grained labels.
# Collapsing ~15 fine labels into families gives more samples per class,
# which matters a lot for the rare ones (Heartbleed, Infiltration, etc.)
ATTACK_FAMILY_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
}


def _clean_colname(col: str) -> str:
    """Strip whitespace and normalize a column name."""
    col = col.strip()
    col = re.sub(r"\s+", " ", col)
    return col


def _clean_label(label: str) -> str:
    """Strip whitespace and normalize a label string."""
    if not isinstance(label, str):
        return label
    return label.strip()


def load_and_clean(
    raw_dir: str,
    file_pattern: str = "*.csv",
    drop_zero_variance: bool = True,
    verbose: bool = True,
) -> pd.DataFrame:
    """
    Load all CSVs in raw_dir, concatenate, and clean.

    Steps:
      1. Concatenate all matching CSVs
      2. Strip whitespace from column names and label values
      3. Replace inf with NaN, then drop rows with NaN
      4. Drop exact duplicate rows
      5. Optionally drop zero-variance numeric columns
    """
    paths = sorted(glob.glob(os.path.join(raw_dir, file_pattern)))
    if not paths:
        raise FileNotFoundError(
            f"No files matching {file_pattern} found in {raw_dir}. "
            "Download CICIDS2017 CSVs and place them there first."
        )

    if verbose:
        print(f"Found {len(paths)} files:")
        for p in paths:
            print(f"  - {os.path.basename(p)}")

    frames = []
    for p in paths:
        df = pd.read_csv(p, low_memory=False)
        df.columns = [_clean_colname(c) for c in df.columns]
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)
    n_start = len(df)

    if "Label" not in df.columns:
        raise KeyError(
            "Expected a 'Label' column after cleaning column names. "
            f"Found columns: {list(df.columns)[:10]}..."
        )

    df["Label"] = df["Label"].apply(_clean_label)

    # Replace inf/-inf with NaN, then drop NaN rows
    numeric_cols = [col for col in df.columns if np.issubdtype(df[col].dtype, np.number)]
    for col in numeric_cols:
        df[col] = df[col].replace([np.inf, -np.inf], np.nan)
    n_before_dropna = len(df)
    df = df.dropna()
    n_after_dropna = len(df)

    # Drop exact duplicate rows
    n_before_dedup = len(df)
    df = df.drop_duplicates()
    n_after_dedup = len(df)

    zero_var_cols: List[str] = []
    if drop_zero_variance:
        variances = df[numeric_cols].var(numeric_only=True)
        zero_var_cols = variances[variances == 0].index.tolist()
        if zero_var_cols:
            df = df.drop(columns=zero_var_cols)

    if verbose:
        print(f"\nRows: {n_start} -> after dropna: {n_after_dropna} "
              f"(removed {n_before_dropna - n_after_dropna} with NaN/Inf)")
        print(f"Rows: {n_before_dedup} -> after dedup: {n_after_dedup} "
              f"(removed {n_before_dedup - n_after_dedup} duplicates)")
        if drop_zero_variance and zero_var_cols:
            print(f"Dropped {len(zero_var_cols)} zero-variance columns: {zero_var_cols}")
        print(f"\nFinal shape: {df.shape}")
        print(f"\nLabel distribution:\n{df['Label'].value_counts()}")

    return df.reset_index(drop=True)


def encode_labels(
    df: pd.DataFrame,
    collapse_to_families: bool = True,
    label_col: str = "Label",
) -> Tuple[pd.DataFrame, List[str]]:
    """
    Encode the label column into integer classes.

    Parameters
    ----------
    df : pd.DataFrame
    collapse_to_families : bool
        Collapse fine-grained attack types into families using ATTACK_FAMILY_MAP.
    label_col : str

    Returns
    -------
    df : pd.DataFrame with 'label_encoded' column added
    classes : ordered list of class name strings
    """
    df = df.copy()

    if collapse_to_families:
        df[label_col] = df[label_col].map(
            lambda x: ATTACK_FAMILY_MAP.get(x, x)
        )

    classes = sorted(df[label_col].unique())
    class_to_int = {c: i for i, c in enumerate(classes)}
    df["label_encoded"] = df[label_col].map(class_to_int)

    return df, classes
