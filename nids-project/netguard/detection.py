"""
netguard/detection.py
----------------------
Real-time detection engine: loads trained artifacts and classifies flows.

The detection engine is stateless — it loads model artifacts once at startup
then exposes a single predict() method that accepts a feature dict
(from NetworkFlow.to_feature_vector()) and returns a PredictionResult.

Usage:
    engine = DetectionEngine()
    result = engine.predict(flow.to_feature_vector())
    print(result.label, result.confidence)
"""

import json
import os
import pickle
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

# Suppress noisy sklearn feature-name warnings (scaler was fit with
# DataFrame columns but inference uses plain numpy arrays — functionally OK).
warnings.filterwarnings("ignore", message="X does not have valid feature names")


def get_default_model_dir() -> str:
    """
    Locate model artifacts directory.
    Prefers package-bundled models first, then falls back to local './models'.
    """
    pkg_model_dir = os.path.join(os.path.dirname(__file__), "models")
    if os.path.exists(os.path.join(pkg_model_dir, "best_model.pkl")):
        return pkg_model_dir
    if os.path.exists(os.path.join("models", "best_model.pkl")):
        return "models"
    return pkg_model_dir


DEFAULT_MODEL_DIR = get_default_model_dir()


@dataclass
class PredictionResult:
    """
    Result of classifying a single network flow.

    Attributes
    ----------
    label : str
        Predicted class name (e.g. "BENIGN", "DDoS", "PortScan").
    label_index : int
        Integer index of the predicted class.
    confidence : float
        Probability of the predicted class (0.0 – 1.0).
    probabilities : dict
        Full class probability distribution {class_name: probability}.
    is_attack : bool
        True if the predicted label is not "BENIGN".
    flow_summary : str
        Optional human-readable flow description passed through for logging.
    """
    label: str
    label_index: int
    confidence: float
    probabilities: Dict[str, float]
    is_attack: bool
    flow_summary: str = ""

    def __str__(self) -> str:
        status = "⚠️  ATTACK" if self.is_attack else "✅ BENIGN"
        return (
            f"{status} | {self.label} ({self.confidence:.1%}) "
            f"| {self.flow_summary}"
        )


class DetectionEngine:
    """
    Loads the trained model artifacts and classifies network flows.

    Parameters
    ----------
    model_dir : str, optional
        Directory containing best_model.pkl, scaler.pkl, and metadata.json.
        Defaults to the bundled package models directory.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self._model_dir = model_dir if model_dir is not None else get_default_model_dir()
        self._model = None
        self._scaler = None
        self._classes: List[str] = []
        self._features: List[str] = []
        self._loaded = False

    def load(self) -> "DetectionEngine":
        """
        Load model artifacts from disk. Call this once before predict().
        Returns self for chaining: engine = DetectionEngine().load()

        Raises
        ------
        FileNotFoundError if model artifacts are missing.
        """
        model_path = os.path.join(self._model_dir, "best_model.pkl")
        scaler_path = os.path.join(self._model_dir, "scaler.pkl")
        meta_path = os.path.join(self._model_dir, "metadata.json")

        for path in [model_path, scaler_path, meta_path]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Model artifact not found: {path}\n"
                    "Run 'netguard train' first to generate model artifacts."
                )

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)
            with open(scaler_path, "rb") as f:
                self._scaler = pickle.load(f)
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self._classes = [c.replace("\ufffd", " - ") for c in meta["classes"]]
        self._features = meta["features"]
        self._loaded = True
        return self

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def classes(self) -> List[str]:
        return self._classes

    @property
    def features(self) -> List[str]:
        return self._features

    def predict(
        self,
        feature_dict: Dict[str, float],
        flow_summary: str = "",
    ) -> PredictionResult:
        """
        Classify a single network flow.

        Parameters
        ----------
        feature_dict : dict
            Feature values keyed by feature name.
            Must contain all keys in self.features.
            Missing keys are filled with 0.0 (graceful degradation).
        flow_summary : str
            Human-readable description of the flow (for logging).

        Returns
        -------
        PredictionResult
        """
        if not self._loaded:
            raise RuntimeError("DetectionEngine not loaded. Call engine.load() first.")

        # Build feature vector in the correct column order
        vector = np.array(
            [feature_dict.get(feat, 0.0) for feat in self._features],
            dtype=np.float64,
        ).reshape(1, -1)

        # Apply the same scaler used during training
        vector_scaled = self._scaler.transform(vector)

        # Predict class index
        label_index = int(self._model.predict(vector_scaled)[0])
        label = self._classes[label_index]

        # Get per-class probabilities if available
        if hasattr(self._model, "predict_proba"):
            probs = self._model.predict_proba(vector_scaled)[0]
            confidence = float(probs[label_index])
            probabilities = {cls: float(p) for cls, p in zip(self._classes, probs)}
        else:
            confidence = 1.0 if label != "BENIGN" else 0.0
            probabilities = {cls: (1.0 if cls == label else 0.0) for cls in self._classes}

        return PredictionResult(
            label=label,
            label_index=label_index,
            confidence=confidence,
            probabilities=probabilities,
            is_attack=(label != "BENIGN"),
            flow_summary=flow_summary,
        )

    def predict_batch(
        self, feature_dicts: List[Dict[str, float]]
    ) -> List[PredictionResult]:
        """Classify multiple flows in one vectorized call."""
        if not feature_dicts:
            return []

        matrix = np.array(
            [[fd.get(feat, 0.0) for feat in self._features] for fd in feature_dicts],
            dtype=np.float64,
        )
        matrix_scaled = self._scaler.transform(matrix)
        label_indices = self._model.predict(matrix_scaled).astype(int)

        if hasattr(self._model, "predict_proba"):
            proba_matrix = self._model.predict_proba(matrix_scaled)
        else:
            proba_matrix = None

        results = []
        for i, idx in enumerate(label_indices):
            label = self._classes[idx]
            if proba_matrix is not None:
                probs = proba_matrix[i]
                conf = float(probs[idx])
                prob_dict = {cls: float(p) for cls, p in zip(self._classes, probs)}
            else:
                conf = 1.0
                prob_dict = {cls: (1.0 if cls == label else 0.0) for cls in self._classes}

            results.append(PredictionResult(
                label=label,
                label_index=int(idx),
                confidence=conf,
                probabilities=prob_dict,
                is_attack=(label != "BENIGN"),
            ))
        return results
