import joblib
import os

BASE_DIR = os.path.dirname(__file__)

model = joblib.load(os.path.join(BASE_DIR, "spam_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE_DIR, "vectorizer.pkl"))

def detect_scam(message):

    message_vec = vectorizer.transform([message])
    prediction = model.predict(message_vec)

    return prediction[0]