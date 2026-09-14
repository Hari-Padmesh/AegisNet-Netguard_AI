"""
tests/test_detection.py
------------------------
Unit tests for the DetectionEngine.

Uses the real saved artifacts in models/ if available,
otherwise gracefully skips tests that require them.
"""

import os
import pytest

from netguard.detection import DetectionEngine, PredictionResult, get_default_model_dir
from netguard.flow_generator import FLOW_FEATURES

MODEL_DIR = get_default_model_dir()
ARTIFACTS_AVAILABLE = (
    os.path.exists(os.path.join(MODEL_DIR, "best_model.pkl")) and
    os.path.exists(os.path.join(MODEL_DIR, "scaler.pkl")) and
    os.path.exists(os.path.join(MODEL_DIR, "metadata.json"))
)

requires_model = pytest.mark.skipif(
    not ARTIFACTS_AVAILABLE,
    reason="Model artifacts not found. Run 'netguard train' first."
)


class TestDetectionEngine:

    @requires_model
    def test_load_succeeds(self):
        """Engine should load without errors when artifacts exist."""
        engine = DetectionEngine(model_dir=MODEL_DIR).load()
        assert engine.is_loaded
        assert len(engine.classes) > 0
        assert len(engine.features) > 0

    @requires_model
    def test_predict_returns_prediction_result(self):
        """predict() should return a PredictionResult with valid fields."""
        engine = DetectionEngine(model_dir=MODEL_DIR).load()
        fv = {feat: 0.0 for feat in engine.features}
        result = engine.predict(fv, flow_summary="test flow")

        assert isinstance(result, PredictionResult)
        assert result.label in engine.classes
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.is_attack, bool)
        assert result.flow_summary == "test flow"

    @requires_model
    def test_probabilities_sum_to_one(self):
        """Probability distribution over all classes should sum to ~1.0."""
        engine = DetectionEngine(model_dir=MODEL_DIR).load()
        fv = {feat: 0.0 for feat in engine.features}
        result = engine.predict(fv)
        total = sum(result.probabilities.values())
        assert total == pytest.approx(1.0, abs=1e-4)

    @requires_model
    def test_missing_features_handled_gracefully(self):
        """predict() should not raise when some features are missing (fills 0.0)."""
        engine = DetectionEngine(model_dir=MODEL_DIR).load()
        # Pass only one feature — the rest should silently default to 0.0
        result = engine.predict({"Destination Port": 80.0})
        assert isinstance(result, PredictionResult)

    @requires_model
    def test_predict_batch_consistency(self):
        """Batch predictions should match single predictions for the same input."""
        engine = DetectionEngine(model_dir=MODEL_DIR).load()
        fv = {feat: float(i * 10) for i, feat in enumerate(engine.features)}

        single = engine.predict(fv)
        batch  = engine.predict_batch([fv])[0]

        assert single.label == batch.label
        assert single.confidence == pytest.approx(batch.confidence, abs=1e-6)

    def test_load_raises_on_missing_artifacts(self, tmp_path):
        """Engine should raise FileNotFoundError if artifacts are missing."""
        engine = DetectionEngine(model_dir=str(tmp_path))
        with pytest.raises(FileNotFoundError):
            engine.load()

    def test_predict_raises_if_not_loaded(self):
        """predict() should raise RuntimeError if called before load()."""
        engine = DetectionEngine(model_dir=MODEL_DIR)
        with pytest.raises(RuntimeError, match="not loaded"):
            engine.predict({})
