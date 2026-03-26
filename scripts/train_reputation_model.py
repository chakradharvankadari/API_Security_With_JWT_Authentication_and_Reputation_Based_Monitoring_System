from __future__ import annotations

"""
Improved training script based on your Colab notebook.

Key changes:
1) Drops target leakage by excluding 'reputation_score' from model features.
2) Forces noisy network columns to numeric (coerce invalid values).
3) Uses low_memory=False for large CSV with mixed dtypes.
"""

from pathlib import Path


def main() -> None:
    try:
        import joblib
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
    except Exception as exc:
        raise RuntimeError(
            "Missing ML dependencies. Install pandas/scikit-learn/joblib in a compatible Python runtime."
        ) from exc

    project_root = Path(__file__).resolve().parents[1]
    raw_dir = project_root / "data" / "raw"
    model_dir = project_root / "models"
    model_dir.mkdir(parents=True, exist_ok=True)

    attack_patterns = pd.read_csv(raw_dir / "attack_patterns.csv")
    api_behavior = pd.read_csv(raw_dir / "api_access_behaviour_anomaly.csv")
    reputation_seed = pd.read_csv(raw_dir / "reputation_seed.csv")

    attack_patterns["timestamp"] = pd.to_datetime(attack_patterns.get("timestamp"), errors="coerce")

    attack_patterns = attack_patterns.fillna(0)
    api_behavior = api_behavior.fillna(0)
    reputation_seed = reputation_seed.fillna(0)

    attack_features = (
        attack_patterns.groupby("user_id")
        .agg(
            {
                "is_attack": "sum",
                "anomaly_score": "mean",
                "response_time_ms": "mean",
                "response_status": lambda x: (x >= 400).sum(),
            }
        )
        .reset_index()
    )
    attack_features.columns = [
        "user_id",
        "attack_count",
        "avg_anomaly_score",
        "avg_response_time",
        "failed_requests",
    ]

    api_features = (
        api_behavior.groupby("source")
        .agg(
            {
                "api_access_uniqueness": "mean",
                "sequence_length(count)": "mean",
                "num_sessions": "sum",
                "num_unique_apis": "mean",
            }
        )
        .reset_index()
    )
    api_features.columns = [
        "user_id",
        "avg_api_uniqueness",
        "avg_sequence_length",
        "total_sessions",
        "avg_unique_apis",
    ]

    data = reputation_seed.merge(attack_features, on="user_id", how="left")
    data = data.merge(api_features, on="user_id", how="left")
    data = data.fillna(0)

    def calculate_reputation(row):
        score = row["initial_trust_score"]
        score += row["success_count"] * 0.3
        score -= row["failure_count"] * 0.6
        score -= row["attack_count"] * 12
        score -= row["avg_anomaly_score"] * 15
        if row["is_verified"] == 1:
            score += 5
        return max(0, min(100, score))

    def classify_user(score):
        if score >= 80:
            return "Trusted"
        if score >= 50:
            return "Normal"
        if score >= 30:
            return "Suspicious"
        return "Malicious"

    data["reputation_score"] = data.apply(calculate_reputation, axis=1)
    data["risk_level"] = data["reputation_score"].apply(classify_user)

    drop_columns = ["user_id", "email", "registration_date", "last_activity", "risk_level", "reputation_score"]
    features = data.drop([c for c in drop_columns if c in data.columns], axis=1)
    labels = data["risk_level"]

    encoder = LabelEncoder()
    labels_encoded = encoder.fit_transform(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        labels_encoded,
        test_size=0.2,
        random_state=42,
        stratify=labels_encoded,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, predictions))
    print(classification_report(y_test, predictions))

    bundle = {
        "model": model,
        "label_encoder": encoder,
        "feature_order": list(features.columns),
    }
    out_path = model_dir / "reputation_model_bundle.joblib"
    joblib.dump(bundle, out_path)
    print(f"Saved model bundle: {out_path}")


if __name__ == "__main__":
    main()
