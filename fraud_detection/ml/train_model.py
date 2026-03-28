import os
import django
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

# ── 1. Setup Django Environment ──────────────────────────────────────────────
# We need this to access the database outside of a normal request
import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "malwaredetection.settings")
django.setup()

from fraud_detection.models import UPIID

# ── 2. Collect Data ──────────────────────────────────────────────────────────
print("Fetching UPI data from Database...")

# We pull all UPI IDs.
# If status is 'Fraud', or reported_count > 0 -> spam (1)
# Else status is 'Safe' -> ham (0)
db_records = UPIID.objects.all()

data = []
for record in db_records:
    is_spam = record.status == 'Fraud' or record.reported_count > 0
    data.append({
        'upi_id': record.upi_id,
        'label': 1 if is_spam else 0
    })

# Always include a cold-start base dataset so the model knows basic patterns
# even if the database is empty.
base_data = [
    {"upi_id": "sbi-refund@okicici", "label": 1},
    {"upi_id": "日常生活@paytm", "label": 1},  # random characters
    {"upi_id": "1248912489aa@sbi", "label": 1},
    {"upi_id": "paytm-support@ybl", "label": 1},
    {"upi_id": "cashback-offer@apl", "label": 1},
    {"upi_id": "8999999999@okaxis", "label": 1},
    {"upi_id": "kyc-update@hdfcbank", "label": 1},
    {"upi_id": "amit.kumar@okicici", "label": 0},
    {"upi_id": "priya.sharma99@oksbi", "label": 0},
    {"upi_id": "rahul.verma@paytm", "label": 0},
    {"upi_id": "shop.payments@ybl", "label": 0},
    {"upi_id": "anita.desai@axisbank", "label": 0},
]

# Combine Database data and base data
all_data = base_data + data
df = pd.DataFrame(all_data)

# Remove duplicates (DB might contain the same IDs as base_data)
df = df.drop_duplicates(subset=['upi_id'])

print(f"Total training samples: {len(df)} ({df['label'].sum()} spam, {len(df) - df['label'].sum()} safe)")

# ── 3. Feature Extraction (Character N-Grams) ────────────────────────────────
# For UPI IDs, the "words" don't matter as much as the character patterns.
# e.g., "sbi-refund" vs "amitkumar". Character n-grams are perfect for this.
X = df['upi_id']
y = df['label']

print("Training TF-IDF Vectorizer...")
# Extact sequences of 2 to 4 characters
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
X_vec = vectorizer.fit_transform(X)

# ── 4. Train Model ───────────────────────────────────────────────────────────
print("Training Random Forest Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_vec, y)

# ── 5. Save the Pipeline ─────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "upi_model.pkl")
VEC_PATH = os.path.join(os.path.dirname(__file__), "upi_vectorizer.pkl")

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VEC_PATH)

print(f"Successfully trained ML model on {len(df)} UPI IDs from the database.")
print(f"Saved to: {MODEL_PATH}")
