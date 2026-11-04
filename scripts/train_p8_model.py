import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensics.paths import REAL_P4_DB
from forensics.ml.features import extract_address_features, FEATURE_NAMES
from forensics.ml.dataset import chronological_split, RobustFeatureScaler
from forensics.ml.model import CompactAnomalyMLP, train_anomaly_detector
from forensics.ml.registry import save_model, verify_model_integrity
from forensics.ai.tools import get_ml_anomaly_analysis

def main():
    print("1. Extracting features from real_p4.db...")
    res = extract_address_features(REAL_P4_DB)
    print(f"Total extracted: {len(res.features)} addresses (positive alerts: {sum(res.labels)})")

    print("2. Performing chronological block-based split...")
    train_split, val_split, test_split = chronological_split(
        res.features, res.addresses, res.blocks, res.labels,
        train_ratio=0.70, val_ratio=0.15, test_ratio=0.15
    )
    print(f"Split sizes: Train={len(train_split)} (pos={sum(train_split.labels)}), "
          f"Val={len(val_split)} (pos={sum(val_split.labels)}), "
          f"Test={len(test_split)} (pos={sum(test_split.labels)})")

    print("3. Fitting RobustFeatureScaler on train set...")
    scaler = RobustFeatureScaler()
    X_train_scaled = scaler.fit_transform(train_split.features)
    X_val_scaled = scaler.transform(val_split.features)
    X_test_scaled = scaler.transform(test_split.features)

    print("4. Training CompactAnomalyMLP...")
    epochs = 50
    lr = 0.01
    pos_weight = 8.0
    random_seed = 42

    model, train_metrics = train_anomaly_detector(
        X_train_scaled,
        train_split.labels,
        epochs=epochs,
        lr=lr,
        pos_weight=pos_weight,
        batch_size=64,
        random_seed=random_seed,
    )
    print(f"Training completed. Final train loss: {train_metrics['final_train_loss']}")

    tau = 0.60
    def calc_metrics(X, y):
        preds = [model.predict_score(x) for x in X]
        tp = sum(1 for p, label in zip(preds, y) if p >= tau and label == 1)
        fp = sum(1 for p, label in zip(preds, y) if p >= tau and label == 0)
        fn = sum(1 for p, label in zip(preds, y) if p < tau and label == 1)
        tn = sum(1 for p, label in zip(preds, y) if p < tau and label == 0)
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        return round(p, 4), round(r, 4), round(f1, 4), tp, fp, fn, tn

    tr_p, tr_r, tr_f1, _, _, _, _ = calc_metrics(X_train_scaled, train_split.labels)
    val_p, val_r, val_f1, _, _, _, _ = calc_metrics(X_val_scaled, val_split.labels)
    te_p, te_r, te_f1, tp, fp, fn, tn = calc_metrics(X_test_scaled, test_split.labels)

    print(f"Train metrics (tau={tau}): Precision={tr_p}, Recall={tr_r}, F1={tr_f1}")
    print(f"Val metrics   (tau={tau}): Precision={val_p}, Recall={val_r}, F1={val_f1}")
    print(f"Test metrics  (tau={tau}): Precision={te_p}, Recall={te_r}, F1={te_f1} (TP={tp}, FP={fp}, FN={fn}, TN={tn})")

    models_dir = Path("D:/Projest/Blockchain/models")
    meta_payload = {
        "model_version": "1.0.0",
        "dataset_stats": {
            "total_samples": len(res.features),
            "train_samples": len(train_split),
            "val_samples": len(val_split),
            "test_samples": len(test_split),
            "positive_samples": sum(res.labels),
        },
        "hyperparameters": {
            "epochs": epochs,
            "learning_rate": lr,
            "batch_size": 64,
            "pos_weight": pos_weight,
            "random_seed": random_seed,
        },
        "metrics": {
            "train_loss": train_metrics["final_train_loss"],
            "test_precision": te_p,
            "test_recall": te_r,
            "test_f1": te_f1,
        },
        "features": FEATURE_NAMES,
        "scaler": scaler.to_dict(),
    }

    print("5. Exporting ONNX model and metadata JSON...")
    onnx_path, file_sha256 = save_model(
        model, "anomaly_detector_v1", meta_payload, models_dir=models_dir
    )
    print(f"ONNX exported to: {onnx_path}")
    print(f"Model SHA-256: {file_sha256}")

    print("6. Verifying model integrity...")
    assert verify_model_integrity("anomaly_detector_v1", models_dir=models_dir)
    print("Model integrity verification PASSED!")

    print("7. Evaluating real incident entities...")
    euler = "0xebc29199c817dc47ba12e3f86102564d640cbf99"
    curve = "0xb657b895b265c38c53fff00166cf7f6a3c70587d"
    res_euler = get_ml_anomaly_analysis(euler, db_path=REAL_P4_DB)
    res_curve = get_ml_anomaly_analysis(curve, db_path=REAL_P4_DB)

    print("=== EULER FRONT-RUN INCIDENT ===")
    print("Score:", res_euler["score"])
    print("Classification:", res_euler["classification"])
    print("Top features:", res_euler["top_features"])
    print("XAI Attributions:", json.dumps(res_euler["xai_attributions"], indent=2))
    print("MITRE Mappings:", [m["technique_id"] for m in res_euler["mitre_mappings"]])

    print("=== CURVE ATTACK CONTRACT INCIDENT ===")
    print("Score:", res_curve["score"])
    print("Classification:", res_curve["classification"])
    print("Top features:", res_curve["top_features"])
    print("XAI Attributions:", json.dumps(res_curve["xai_attributions"], indent=2))
    print("MITRE Mappings:", [m["technique_id"] for m in res_curve["mitre_mappings"]])

if __name__ == "__main__":
    main()
