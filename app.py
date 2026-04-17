"""
app.py - Phishing Detection REST API Server

Pure offline Machine Learning phishing detection combining best models.
Highlights Stacking Ensemble (RF + XGBoost + MLP) logic.
API endpoints support prediction, dataset addition, and retraining.
"""

import os
import csv
import json
import logging
import subprocess
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature import FeatureExtractor
from external_checkers import MultiLayerChecker

# ──────────────────────────── App Setup ─────────────────────────────────

app = Flask(__name__)
CORS(app)

DISPLAYED_FOLDER = "displayed data"
PREPROCESSED_FOLDER = "preprocessed"
PROCESSED_FOLDER = "processed"
MODEL_PATH = "phishing_model.pkl"
FEATURES_PATH = "feature_names.pkl"
SCALER_PATH = "scaler.pkl"
REPORT_PATH = "training_report.json"
DATASET_PATH = os.path.join(DISPLAYED_FOLDER, "dataset_small.csv")

for d in (DISPLAYED_FOLDER, PREPROCESSED_FOLDER, PROCESSED_FOLDER):
    os.makedirs(d, exist_ok=True)

# Load model, extractor, APIs
extractor = FeatureExtractor()
multi_layer_checker = MultiLayerChecker()

def _load_model():
    """Load or reload the trained model from disk."""
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)

def _load_scaler():
    """Load the scaler if it exists."""
    if os.path.exists(SCALER_PATH):
        return joblib.load(SCALER_PATH)
    return None

def _load_report():
    """Load the training report."""
    if os.path.exists(REPORT_PATH):
        with open(REPORT_PATH) as f:
            return json.load(f)
    return {}

model = _load_model()
scaler = _load_scaler()
training_report = _load_report()


# ──────────────────────────── Helpers ───────────────────────────────────

def _sanitize_asn(value) -> float:
    """Convert ASN value to numeric, returning -1 for unknowns."""
    s = str(value)
    if s in ("Unknown", "unknown", ""):
        return -1.0
    try:
        return float(s)
    except ValueError:
        return -1.0

_known_urls: set | None = None

def _load_known_urls() -> set:
    """Load URLs already scanned (from tracking file)."""
    global _known_urls
    if _known_urls is not None:
        return _known_urls
    _known_urls = set()
    try:
        tracking = DATASET_PATH.replace(".csv", "_urls.txt")
        if os.path.isfile(tracking):
            with open(tracking, "r", encoding="utf-8") as f:
                _known_urls = set(line.strip() for line in f if line.strip())
    except Exception:
        pass
    return _known_urls


def _predict_url(url: str) -> dict:
    """
    Run URL prediction using pure ML model.
    """
    # ── Step 1: Feature extraction + ML prediction ──
    features = extractor.extract(url)
    features["asn_ip"] = _sanitize_asn(features["asn_ip"])
    arr = np.array([list(features.values())])

    # Check if model needs scaling
    needs_scaler = training_report.get("needs_scaler", False)
    if needs_scaler and scaler is not None:
        arr_for_predict = scaler.transform(arr)
    else:
        arr_for_predict = arr

    proba = model.predict_proba(arr_for_predict)[0]
    ml_phishing_score = float(proba[1]) if len(proba) > 1 else float(proba[0])

    # Get standard threshold (0.50) instead of highly strict optimal_threshold (0.29)
    # to avoid False Positives on valid domains that fail WHOIS checks.
    threshold = 0.50
    best_model_name = training_report.get("best_model", "Stacking_Ensemble")

    # ── Step 2: Explainable AI (XAI) - Anomalies detection ──
    # Compare against common heuristic thresholds for phishing URLs
    anomalies = []
    
    if features.get("length_url", 0) > 75:
        anomalies.append(f"Panjang URL sangat tidak wajar ({features['length_url']} karakter).")
    if features.get("qty_slash_url", 0) > 5:
        anomalies.append(f"Jumlah garis miring terlalu banyak ({features['qty_slash_url']} slash).")
    if features.get("qty_dot_domain", 0) > 3:
        anomalies.append(f"Format domain mencurigakan (memiliki {features['qty_dot_domain']} titik).")
    if features.get("directory_length", 0) > 40:
        anomalies.append(f"Struktur direktori sangat panjang ({features['directory_length']} karakter).")
    if features.get("qty_hyphen_directory", 0) >= 2:
        anomalies.append(f"Terlalu banyak tanda hubung di direktori ({features['qty_hyphen_directory']}).")
    if features.get("tld_present_params", 0) == 1:
        anomalies.append("Ditemukan ekstensi domain palsu (TLD) di dalam parameter URL.")
    if features.get("url_shortened", 0) == 1:
        anomalies.append("URL disembunyikan menggunakan layanan penyingkat (URL Shortener).")
    if features.get("time_domain_activation", 9999) < 30 and features.get("time_domain_activation", 0) != -1:
        anomalies.append(f"Domain sangat baru (umur = {features.get('time_domain_activation')} hari).")
    if features.get("tls_ssl_certificate", 1) == 0:
        anomalies.append("Tidak ada sertifikat keamanan / SSL (Bukan HTTPS).")
    if features.get("qty_redirects", 0) > 2:
        anomalies.append(f"URL melakukan redirect sebanyak {features['qty_redirects']} kali secara beruntun.")

    # ── Step 3: Run External APIs (VirusTotal & Safe Browsing) ──
    external_results = multi_layer_checker.check_all(url)

    # ── Step 4: Combine Scores (Weighted Vote) ──
    combined = multi_layer_checker.combine_scores(
        ml_phishing_score,
        external_results["virustotal"],
        external_results["safe_browsing"]
    )

    classification = combined["classification"]
    confidence = combined["confidence"]
    sources_used = combined["sources_used"]

    # ── Step 5: Adjust anomalies based on APIs ──
    if classification == "phishing" and ml_phishing_score < 0.50:
        # It was flagged by APIs but ML thought it was legitimate
        anomalies.append("Terdeteksi sebagai ancaman oleh Database Keamanan Global (VirusTotal / Safe Browsing).")
    elif classification == "phishing" and not anomalies:
        anomalies.append("AI Model mendeteksi kombinasi pola struktural yang sangat mirip dengan phishing.")
    elif classification == "legitimate":
        anomalies = []

    prediction = 1 if classification == "phishing" else 0

    # ── Auto-learn: save to dataset ──
    known = _load_known_urls()
    if url not in known:
        try:
            row = list(features.values()) + [prediction]
            file_exists = os.path.isfile(DATASET_PATH)
            with open(DATASET_PATH, "a", newline="") as f:
                writer = csv.writer(f)
                if not file_exists or os.path.getsize(DATASET_PATH) == 0:
                    writer.writerow(list(features.keys()) + ["phishing"])
                writer.writerow(row)

            tracking = DATASET_PATH.replace(".csv", "_urls.txt")
            with open(tracking, "a", encoding="utf-8") as f:
                f.write(url + "\n")
            known.add(url)

            logging.info("Auto-learn: added URL -> %s (%s)", url, classification)
        except Exception as exc:
            logging.warning("Auto-learn save failed: %s", exc)

    # ── Build response ──
    return {
        "url": url,
        "classification": classification,
        "confidence": confidence,
        "anomalies": anomalies,
        "sources": {
            "ml_model": {
                "verdict": "phishing" if ml_phishing_score >= 0.50 else "legitimate",
                "confidence": round(ml_phishing_score if ml_phishing_score >= 0.50 else 1.0 - ml_phishing_score, 4),
                "raw_score": round(ml_phishing_score, 4),
                "model": best_model_name,
                "threshold": round(threshold, 4),
            },
            "virustotal": external_results["virustotal"],
            "safe_browsing": external_results["safe_browsing"],
        },
        "sources_used": sources_used,
    }

# ──────────────────────────── Routes ───────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "service": "Phishing URL Detection API",
        "version": "2.0.0",
        "model": training_report.get("best_model", "Unknown"),
        "endpoints": {
            "GET  /api/health": "Health check",
            "GET  /api/stats": "Dataset statistics",
            "GET  /api/model/info": "Model and training info",
            "POST /api/predict": "Predict single URL",
            "POST /api/predict-batch": "Predict from CSV upload",
            "POST /api/dataset/add": "Add labeled URL to dataset",
            "POST /api/model/retrain": "Retrain the model",
        },
    })

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "model_name": training_report.get("best_model", "Unknown"),
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.route("/api/model/info")
def model_info():
    """Return detailed model training information."""
    if not training_report:
        return jsonify({"error": "No training report found. Run train_model.py first."}), 404

    return jsonify({
        "best_model": training_report.get("best_model"),
        "optimal_threshold": training_report.get("optimal_threshold"),
        "dataset_rows": training_report.get("dataset_rows"),
        "model_results": training_report.get("model_results"),
        "feature_importance": training_report.get("feature_importance"),
        "cv_f1_mean": training_report.get("cv_f1_mean"),
        "cv_f1_std": training_report.get("cv_f1_std"),
    })

@app.route("/api/stats")
def stats():
    try:
        df = pd.read_csv(DATASET_PATH)
        total = len(df)
        phishing = int(df["phishing"].sum())
        legitimate = total - phishing

        fast = int((df["time_response"] < 0.5).sum())
        medium = int(((df["time_response"] >= 0.5) & (df["time_response"] <= 2)).sum())
        slow = int((df["time_response"] > 2).sum())

        return jsonify({
            "total": total,
            "phishing": phishing,
            "legitimate": legitimate,
            "ssl_count": int(df["tls_ssl_certificate"].sum()),
            "domain_age": {
                "new": int((df["time_domain_activation"] < 365).sum()),
                "established": int((df["time_domain_activation"] >= 365).sum()),
            },
            "response_time": {"fast": fast, "medium": medium, "slow": slow},
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.route("/api/predict", methods=["POST"])
def predict():
    global model, scaler, training_report
    if model is None:
        model = _load_model()
        scaler = _load_scaler()
        training_report = _load_report()
    if model is None:
        return jsonify({"error": "Model not trained yet. Run train_model.py first."}), 503

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' field."}), 400

    try:
        result = _predict_url(url)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Prediction failed: {exc}"}), 500

@app.route("/api/predict-batch", methods=["POST"])
def predict_batch():
    global model
    if model is None:
        model = _load_model()
    if model is None:
        return jsonify({"error": "Model not trained yet."}), 503

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved = os.path.join(PREPROCESSED_FOLDER, f"{ts}_{file.filename}")
        file.save(saved)

        df = pd.read_csv(saved, encoding="utf-8-sig")
        results = []
        processed_rows = []

        for raw_url in df.iloc[:, 0].dropna():
            url = str(raw_url).strip()
            if not url or url.lower() == "url":
                continue
            try:
                features = extractor.extract(url)
                features["asn_ip"] = _sanitize_asn(features["asn_ip"])
                arr = np.array([list(features.values())])
                pred = int(model.predict(arr)[0])
                row = {k: v for k, v in features.items()}
                row["phishing"] = pred
                processed_rows.append(row)
                results.append({"url": url, "prediction": "phishing" if pred == 1 else "legitimate"})
            except Exception as exc:
                results.append({"url": url, "error": str(exc)})

        if processed_rows:
            out_df = pd.DataFrame(processed_rows)
            out_path = os.path.join(PROCESSED_FOLDER, f"processed_{ts}_{file.filename}")
            out_df.to_csv(out_path, index=False)

        return jsonify({"results": results})
    except Exception as exc:
        return jsonify({"error": f"Batch processing failed: {exc}"}), 500

@app.route("/api/dataset/add", methods=["POST"])
def dataset_add():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    label = data.get("label", "").strip().lower()

    if not url:
        return jsonify({"error": "Missing 'url' field."}), 400
    if label not in ("phishing", "legitimate"):
        return jsonify({"error": "Field 'label' must be 'phishing' or 'legitimate'."}), 400

    try:
        features = extractor.extract(url)
        features["asn_ip"] = _sanitize_asn(features["asn_ip"])
        is_phishing = 1 if label == "phishing" else 0

        row = list(features.values()) + [is_phishing]
        file_exists = os.path.isfile(DATASET_PATH)

        with open(DATASET_PATH, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(DATASET_PATH) == 0:
                writer.writerow(list(features.keys()) + ["phishing"])
            writer.writerow(row)

        return jsonify({
            "message": "Data added successfully.",
            "url": url,
            "label": label,
        })
    except Exception as exc:
        return jsonify({"error": f"Failed to add data: {exc}"}), 500

@app.route("/api/model/retrain", methods=["POST"])
def retrain():
    global model, scaler, training_report
    try:
        result = subprocess.run(
            [sys.executable, "train_model.py"],
            capture_output=True, text=True, timeout=900,
        )
        if result.returncode != 0:
            return jsonify({"error": "Training failed.", "details": result.stderr}), 500

        model = _load_model()
        scaler = _load_scaler()
        training_report = _load_report()

        return jsonify({
            "message": "Model retrained successfully.",
            "best_model": training_report.get("best_model"),
            "output": result.stdout[-3000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Training timed out."}), 504
    except Exception as exc:
        return jsonify({"error": f"Retrain failed: {exc}"}), 500

# ──────────────────────────── Error handlers ───────────────────────────

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found."}), 404

@app.errorhandler(500)
def internal_error(_):
    return jsonify({"error": "Internal server error."}), 500

if __name__ == "__main__":
    app.run(debug=True, port=8080, host="0.0.0.0")
