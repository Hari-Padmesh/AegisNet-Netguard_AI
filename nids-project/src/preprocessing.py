"""
preprocessing.py
----------------
Cleaning and preparation utilities for CICIDS2017-style network flow data.

Designed to handle known quirks of the CICIDS2017 dataset:
- Leading/trailing whitespace in column names
- Inf/NaN values in flow-byte/packet-rate columns
- Inconsistent label strings (e.g. "DoS Hulk" vs "DoS Hulk ")
- Zero-variance columns that add noise without signal

Usage:
    from src.preprocessing import load_and_clean, encode_labels

    df = load_and_clean("data/raw/")
    df, label_encoder = encode_labels(df, collapse_to_families=True)
"""

import glob
import os
import re

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

    Parameters
    ----------
    raw_dir : str
        Directory containing the raw CICIDS2017 CSV files.
    file_pattern : str
        Glob pattern to match CSV files (default "*.csv").
    drop_zero_variance : bool
        If True, drop numeric columns with zero variance (no signal).
    verbose : bool
        If True, print progress and row-count diagnostics.

    Returns
    -------
    pd.DataFrame
        Cleaned dataframe with a normalized 'Label' column.
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
):
    """
    Encode the label column into integer classes.

    Parameters
    ----------
    df : pd.DataFrame
        Cleaned dataframe with a label column.
    collapse_to_families : bool
        If True, collapse fine-grained attack types into families
        using ATTACK_FAMILY_MAP (recommended — improves per-class sample
        counts for rare attack types).
    label_col : str
        Name of the label column.

    Returns
    -------
    df : pd.DataFrame
        Dataframe with an added 'label_encoded' integer column.
    classes : list
        Ordered list of class names corresponding to encoded integers.
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


if __name__ == "__main__":
    # Quick smoke test if run directly — expects CSVs in data/raw/
    df = load_and_clean("data/raw/")
    df, classes = encode_labels(df)
    print(f"\nClasses: {classes}")
