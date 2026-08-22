"""
streamlit_app.py
----------------
Interactive demo for the trained NIDS model.

Run from project root:
    streamlit run app/streamlit_app.py

Two modes:
  1. Upload a CSV of flow records -> get predictions + confidence for each row
  2. Manually adjust a handful of key features -> single live prediction

Both modes use the exact same model/scaler/feature-list artifacts produced
by src/train.py, so there is no train/serve skew.
"""

import json
import os
import sys
import pickle

import numpy as np
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "models"))

st.set_page_config(page_title="NIDS Demo", page_icon="🛰️", layout="wide")


@st.cache_resource
def load_artifacts():
    with open(os.path.join(MODEL_DIR, "best_model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    with open(os.path.join(MODEL_DIR, "metadata.json")) as f:
        metadata = json.load(f)
    return model, scaler, metadata


def predict(df_raw: pd.DataFrame, model, scaler, features, classes):
    """Apply the saved scaler + model to a dataframe of raw feature values."""
    missing = [f for f in features if f not in df_raw.columns]
    if missing:
        raise ValueError(f"Input is missing required features: {missing}")

    X = df_raw[features]
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled)

    pred_labels = [classes[p] for p in preds]

    result = df_raw.copy()
    result["prediction"] = pred_labels

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_scaled)
        result["confidence"] = probs.max(axis=1)

    return result


def main():
    st.title("Network Intrusion Detection — Demo")
    st.caption(
        "Trained on flow-level features (CICIDS2017-style). "
        "This is a research/portfolio demo, not a production IDS."
    )

    try:
        model, scaler, metadata = load_artifacts()
    except FileNotFoundError:
        st.error(
            "No trained model found in `models/`. "
            "Run `python -m src.train --data_dir data/raw/` first."
        )
        st.stop()
        return

    classes = metadata["classes"]
    features = metadata["features"]

    with st.sidebar:
        st.header("Model info")
        st.write(f"**Model**: {metadata['model_name']}")
        st.write(f"**Test macro-F1**: {metadata['test_f1_macro']:.3f}")
        st.write(f"**Classes**: {', '.join(classes)}")
        with st.expander("Features used"):
            st.write(features)

    tab1, tab2 = st.tabs(["📁 Upload CSV", "🎛️ Manual input"])

    with tab1:
        st.subheader("Batch prediction from CSV")
        st.write(
            "Upload a CSV containing flow-level features. "
            f"Required columns ({len(features)}): a superset including "
            f"{', '.join(features[:5])}..."
        )
        uploaded = st.file_uploader("Choose a CSV file", type="csv")

        if uploaded is not None:
            try:
                df_raw = pd.read_csv(uploaded)
                df_raw.columns = [c.strip() for c in df_raw.columns]
                result = predict(df_raw, model, scaler, features, classes)

                st.success(f"Scored {len(result)} flow records.")

                col1, col2 = st.columns([2, 1])
                with col1:
                    st.write("**Prediction distribution**")
                    st.bar_chart(result["prediction"].value_counts())
                with col2:
                    n_attacks = (result["prediction"] != "BENIGN").sum()
                    st.metric("Flagged as attack", n_attacks)
                    st.metric("Flagged as benign", len(result) - n_attacks)

                st.write("**Detailed predictions**")
                display_cols = features[:4] + ["prediction"]
                if "confidence" in result.columns:
                    display_cols.append("confidence")
                st.dataframe(result[display_cols], use_container_width=True)

                csv_out = result.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "Download full results as CSV",
                    csv_out,
                    "nids_predictions.csv",
                    "text/csv",
                )
            except ValueError as e:
                st.error(str(e))
            except Exception as e:
                st.error(f"Error processing file: {e}")

    with tab2:
        st.subheader("Single prediction — manual feature input")
        st.write(
            "Adjust values for the top features and get a live prediction. "
            "Defaults to 0 (roughly 'average' after scaling) for simplicity."
        )

        n_show = min(8, len(features))
        cols = st.columns(2)
        manual_values = {}
        for i, feat in enumerate(features[:n_show]):
            with cols[i % 2]:
                manual_values[feat] = st.number_input(feat, value=0.0, format="%.2f")

        # Remaining features default to 0
        for feat in features[n_show:]:
            manual_values[feat] = 0.0

        if st.button("Classify this flow", type="primary"):
            input_df = pd.DataFrame([manual_values])
            result = predict(input_df, model, scaler, features, classes)
            pred = result["prediction"].iloc[0]

            if pred == "BENIGN":
                st.success(f"Prediction: **{pred}**")
            else:
                st.error(f"Prediction: **{pred}** ⚠️")

            if "confidence" in result.columns:
                st.write(f"Confidence: {result['confidence'].iloc[0]:.1%}")

            if hasattr(model, "predict_proba"):
                X_scaled = scaler.transform(input_df[features])
                probs = model.predict_proba(X_scaled)[0]
                prob_df = pd.DataFrame({"class": classes, "probability": probs})
                st.bar_chart(prob_df.set_index("class"))


if __name__ == "__main__":
    main()
    for i in range(3,7):
        st.write("")  # add some spacing at the bottom  
        st.write("")
    