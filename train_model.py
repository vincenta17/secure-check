"""
train_model.py - Phishing URL Detection Model Training (v2 - Multi-Model)

Compares RandomForest, XGBoost, SVM, MLP Neural Network, and Stacking Ensemble.
Selects the best model automatically, performs feature importance analysis,
and saves the trained model.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve
)
from xgboost import XGBClassifier


# ---- Configuration ----

DATASET_PATH = os.path.join("displayed data", "dataset_small.csv")
MODEL_OUTPUT = "phishing_model.pkl"
FEATURES_OUTPUT = "feature_names.pkl"
SCALER_OUTPUT = "scaler.pkl"
REPORT_OUTPUT = "training_report.json"
TEST_SIZE = 0.20
RANDOM_STATE = 42


# ---- Helpers ----

def load_dataset(path: str) -> pd.DataFrame:
    """Load CSV dataset and perform basic cleaning."""
    print(f"[1/7] Loading dataset from '{path}' ...")
    df = pd.read_csv(path)
    print(f"       Rows: {len(df):,}  |  Columns: {df.shape[1]}")

    df.replace(["Unknown", "unknown", ""], -1, inplace=True)
    df.fillna(-1, inplace=True)

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df.fillna(-1, inplace=True)

    return df


def split_features_label(df: pd.DataFrame):
    """Split dataframe into feature matrix X and label vector y."""
    if "phishing" not in df.columns:
        print("ERROR: Column 'phishing' not found in dataset.")
        sys.exit(1)

    X = df.drop(columns=["phishing"])
    y = df["phishing"].astype(int)
    feature_names = list(X.columns)
    return X, y, feature_names


def build_models():
    """Build all candidate models."""
    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features="sqrt",
            n_jobs=-1,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1.0,
            n_jobs=-1,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            use_label_encoder=False,
        ),
        "SVM": SVC(
            kernel="rbf",
            C=10.0,
            gamma="scale",
            probability=True,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            max_iter=5000,
        ),
        "MLP_NeuralNet": MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            solver="adam",
            alpha=0.001,
            batch_size=256,
            learning_rate="adaptive",
            learning_rate_init=0.001,
            max_iter=200,
            random_state=RANDOM_STATE,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=15,
        ),
    }


def evaluate_model(name, model, X_test, y_test):
    """Evaluate a single model and return metrics."""
    y_pred = model.predict(X_test)
    y_proba = None
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    return {
        "name": name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm.tolist(),
        "y_pred": y_pred,
        "y_proba": y_proba,
    }


def find_optimal_threshold(model, X_test, y_test):
    """Find optimal classification threshold using ROC curve (Youden's J)."""
    if not hasattr(model, "predict_proba"):
        return 0.50
    y_proba = model.predict_proba(X_test)[:, 1]
    fpr, tpr, thresholds = roc_curve(y_test, y_proba)
    j_scores = tpr - fpr
    best_idx = np.argmax(j_scores)
    return float(thresholds[best_idx])


def feature_importance_analysis(model, feature_names, top_n=15):
    """Extract and display feature importance from the best model."""
    importances = None

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = np.abs(model.coef_[0])
    else:
        print("       (Model does not support feature importance)")
        return None

    indices = np.argsort(importances)[::-1][:top_n]

    print(f"\n  Top {top_n} Most Important Features:")
    print("  " + "-" * 50)
    ranking = []
    for rank, idx in enumerate(indices, 1):
        name = feature_names[idx]
        score = importances[idx]
        bar = "#" * int(score * 100)
        print(f"  {rank:>2}. {name:<35} {score:.4f} {bar}")
        ranking.append({"rank": rank, "feature": name, "importance": round(float(score), 6)})

    return ranking


def save_artifacts(model, feature_names, scaler, report, threshold):
    """Save model, feature names, scaler, and report to disk."""
    print("[7/7] Saving artifacts ...")
    joblib.dump(model, MODEL_OUTPUT)
    joblib.dump(feature_names, FEATURES_OUTPUT)
    if scaler is not None:
        joblib.dump(scaler, SCALER_OUTPUT)

    report["optimal_threshold"] = threshold
    with open(REPORT_OUTPUT, "w") as f:
        json.dump(report, f, indent=2, default=str)

    model_size = os.path.getsize(MODEL_OUTPUT) / (1024 * 1024)
    print(f"       Model saved          -> {MODEL_OUTPUT} ({model_size:.1f} MB)")
    print(f"       Feature names saved  -> {FEATURES_OUTPUT}")
    print(f"       Scaler saved         -> {SCALER_OUTPUT}")
    print(f"       Training report      -> {REPORT_OUTPUT}")
    print(f"       Optimal threshold    -> {threshold:.4f}")


# ---- Main ----

def main():
    print("=" * 60)
    print("  PHISHING URL DETECTION - MULTI-MODEL TRAINING PIPELINE")
    print("=" * 60)
    print()

    # 1. Load
    df = load_dataset(DATASET_PATH)

    # 2. Split
    print("[2/7] Splitting into train / test sets ...")
    X, y, feature_names = split_features_label(df)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"       Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    print(f"       Label distribution (train): legitimate={int((y_train == 0).sum()):,} | phishing={int((y_train == 1).sum()):,}")

    # 3. Scale features (needed for SVM and MLP)
    print("[3/7] Scaling features ...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("       StandardScaler fitted on training data")

    # 4. Train & Evaluate all models
    print("[4/7] Training and evaluating models ...")
    print()

    models = build_models()
    results = {}
    trained_models = {}

    for name, model in models.items():
        print(f"  --- {name} ---")
        start = time.time()

        # SVM and MLP need scaled data
        if name in ("SVM", "MLP_NeuralNet"):
            model.fit(X_train_scaled, y_train)
            elapsed = time.time() - start
            metrics = evaluate_model(name, model, X_test_scaled, y_test)
        else:
            model.fit(X_train, y_train)
            elapsed = time.time() - start
            metrics = evaluate_model(name, model, X_test, y_test)

        metrics["training_time"] = round(elapsed, 1)
        results[name] = metrics
        trained_models[name] = model

        cm = metrics["confusion_matrix"]
        print(f"  Accuracy : {metrics['accuracy']:.4f}  |  Precision: {metrics['precision']:.4f}")
        print(f"  Recall   : {metrics['recall']:.4f}  |  F1 Score : {metrics['f1']:.4f}")
        print(f"  TN={cm[0][0]:>6}  FP={cm[0][1]:>6}  |  FN={cm[1][0]:>6}  TP={cm[1][1]:>6}")
        print(f"  Training time: {elapsed:.1f}s")
        print()

    # 5. Build Stacking Ensemble (combine best models)
    print("  --- Stacking Ensemble (RF + XGBoost + MLP) ---")
    start = time.time()
    stacking = StackingClassifier(
        estimators=[
            ("rf", trained_models["RandomForest"]),
            ("xgb", trained_models["XGBoost"]),
            ("mlp", trained_models["MLP_NeuralNet"]),
        ],
        final_estimator=LogisticRegression(max_iter=1000, random_state=RANDOM_STATE),
        cv=3,
        n_jobs=-1,
        passthrough=False,
    )
    stacking.fit(X_train_scaled, y_train)
    elapsed = time.time() - start
    stack_metrics = evaluate_model("Stacking_Ensemble", stacking, X_test_scaled, y_test)
    stack_metrics["training_time"] = round(elapsed, 1)
    results["Stacking_Ensemble"] = stack_metrics
    trained_models["Stacking_Ensemble"] = stacking

    cm = stack_metrics["confusion_matrix"]
    print(f"  Accuracy : {stack_metrics['accuracy']:.4f}  |  Precision: {stack_metrics['precision']:.4f}")
    print(f"  Recall   : {stack_metrics['recall']:.4f}  |  F1 Score : {stack_metrics['f1']:.4f}")
    print(f"  TN={cm[0][0]:>6}  FP={cm[0][1]:>6}  |  FN={cm[1][0]:>6}  TP={cm[1][1]:>6}")
    print(f"  Training time: {elapsed:.1f}s")
    print()

    # 6. Comparison table
    print("[5/7] Model Comparison Results")
    print("=" * 80)
    print(f"  {'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Time':>8}")
    print("  " + "-" * 75)

    best_name = None
    best_f1 = 0

    for name, m in results.items():
        marker = ""
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_name = name

    for name, m in results.items():
        marker = " <-- BEST" if name == best_name else ""
        print(f"  {name:<25} {m['accuracy']:>10.4f} {m['precision']:>10.4f} "
              f"{m['recall']:>10.4f} {m['f1']:>10.4f} {m['training_time']:>6.1f}s{marker}")

    print("=" * 80)
    print(f"\n  >> Best model: {best_name} (F1 = {best_f1:.4f})")
    print()

    # 7. Feature importance for best model
    print("[6/7] Feature Importance Analysis (Best Model) ...")
    best_model = trained_models[best_name]
    importance_ranking = feature_importance_analysis(best_model, feature_names, top_n=15)

    # If best model doesn't support feature importance, try XGBoost
    if importance_ranking is None and "XGBoost" in trained_models:
        print("       Falling back to XGBoost for feature importance ...")
        importance_ranking = feature_importance_analysis(
            trained_models["XGBoost"], feature_names, top_n=15
        )

    # Optimal threshold
    print("\n  Finding optimal threshold (Youden's J statistic) ...")
    if best_name in ("SVM", "MLP_NeuralNet", "Stacking_Ensemble"):
        threshold = find_optimal_threshold(best_model, X_test_scaled, y_test)
    else:
        threshold = find_optimal_threshold(best_model, X_test, y_test)
    print(f"  Optimal threshold: {threshold:.4f} (vs default 0.50)")

    # Cross-validation on best model
    print(f"\n  Running 5-fold cross-validation on {best_name} ...")
    if best_name in ("SVM", "MLP_NeuralNet", "Stacking_Ensemble"):
        cv_scores = cross_val_score(best_model, X_train_scaled, y_train, cv=5, scoring="f1", n_jobs=-1)
    else:
        cv_scores = cross_val_score(best_model, X_train, y_train, cv=5, scoring="f1", n_jobs=-1)
    print(f"  CV F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Build report
    report = {
        "best_model": best_name,
        "dataset_rows": len(df),
        "dataset_columns": df.shape[1],
        "train_size": len(X_train),
        "test_size": len(X_test),
        "model_results": {
            name: {
                "accuracy": round(m["accuracy"], 4),
                "precision": round(m["precision"], 4),
                "recall": round(m["recall"], 4),
                "f1": round(m["f1"], 4),
                "training_time": m["training_time"],
                "confusion_matrix": m["confusion_matrix"],
            }
            for name, m in results.items()
        },
        "feature_importance": importance_ranking,
        "cv_f1_mean": round(cv_scores.mean(), 4),
        "cv_f1_std": round(cv_scores.std(), 4),
        "needs_scaler": best_name in ("SVM", "MLP_NeuralNet", "Stacking_Ensemble"),
    }

    # 8. Save
    save_artifacts(best_model, feature_names, scaler, report, threshold)

    print()
    print("=" * 60)
    print("  TRAINING PIPELINE COMPLETE!")
    print(f"  Best Model : {best_name}")
    print(f"  F1 Score   : {best_f1:.4f}")
    print(f"  Threshold  : {threshold:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
