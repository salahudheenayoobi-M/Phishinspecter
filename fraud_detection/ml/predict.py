import os
import joblib

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "upi_model.pkl")
VEC_PATH = os.path.join(BASE_DIR, "upi_vectorizer.pkl")

# Lazy-load to avoid slowing down startup, but cache it once loaded
_model = None
_vectorizer = None

def _load_model():
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
            _model = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VEC_PATH)
        else:
            return False
    return True

def predict_upi_fraud(upi_id: str) -> bool:
    """
    Predicts if a UPI ID is fraudulent using the dynamically trained DB ML model.
    Returns: True if spam, False if safe.
    """
    if not _load_model():
        return False  # Fail open if model hasn't been trained yet
    
    # Vectorize and predict
    vec = _vectorizer.transform([upi_id.lower()])
    prediction = _model.predict(vec)
    
    return bool(prediction[0] == 1)
