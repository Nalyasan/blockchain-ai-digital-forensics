import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensics.paths import REAL_P4_DB
from forensics.ml.features import extract_address_features, FEATURE_NAMES
from forensics.ml.dataset import MLDatasetPipeline, verify_scaler_isolation
from forensics.ml.manifest import generate_dataset_manifest, validate_dataset_manifest
from forensics.ml.model import (
    CompactAnomalyMLP,
    train_anomaly_detector,
    check_active_neurons,
    HAS_TORCH,
)
from forensics.ml.registry import (
    save_model,
    verify_model_integrity,
    verify_pytorch_onnx_equivalence,
)
from forensics.ai.tools import get_ml_anomaly_analysis

if HAS_TORCH:
    from forensics.ml.model import PyTorchAnomalyMLP


def main():
    print("1. Extracting unit-safe features and decoupled labels from real_p4.db...")
    res = extract_address_features(REAL_P4_DB)
    print(f"Total extracted: {len(res.features)} addresses (positive ground truth labels: {sum(res.labels)})")

    print("2. Preparing dataset with chronological split and anti-leakage pipeline...")
    pipeline = MLDatasetPipeline(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
    prepared = pipeline.prepare(res.features, res.addresses, res.blocks, res.labels)
    train_split = prepared.train
    val_split = prepared.val
    test_split = prepared.test
    scaler = prepared.scaler

    print(f"Split sizes: Train={len(train_split)} (pos={sum(train_split.labels)}), "
          f"Val={len(val_split)} (pos={sum(val_split.labels)}), "
          f"Test={len(test_split)} (pos={sum(test_split.labels)})")

    print("3. Generating and validating models/dataset_manifest.json...")
    models_dir = Path(__file__).resolve().parent.parent / "models"
    manifest_p, manifest_sha256 = generate_dataset_manifest(
        REAL_P4_DB, prepared, output_path=models_dir / "dataset_manifest.json"
    )
    assert validate_dataset_manifest(manifest_p), "Dataset manifest validation failed"
    print(f"Dataset manifest generated: {manifest_p} (SHA-256: {manifest_sha256})")

    print("4. Training CompactAnomalyMLP with He/Kaiming initialization...")
    epochs = 60
    lr = 0.015
    pos_weight = 12.0
    random_seed = 42

    model, train_metrics = train_anomaly_detector(
        train_split.features,
        train_split.labels,
        epochs=epochs,
        lr=lr,
        pos_weight=pos_weight,
        batch_size=64,
        random_seed=random_seed,
        init_method="he",
    )
    print(f"Training completed. Final train loss: {train_metrics['final_train_loss']}")

    # Active neuron diagnostic
    active_diag = check_active_neurons(model, train_split.features)
    print(f"Active neuron diagnostic: {active_diag}")
    assert active_diag["is_healthy"], "Dying ReLU collapse detected!"

    tau = 0.50
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

    tr_p, tr_r, tr_f1, _, _, _, _ = calc_metrics(train_split.features, train_split.labels)
    val_p, val_r, val_f1, _, _, _, _ = calc_metrics(val_split.features, val_split.labels)
    te_p, te_r, te_f1, tp, fp, fn, tn = calc_metrics(test_split.features, test_split.labels)

    print(f"Train metrics (tau={tau}): Precision={tr_p}, Recall={tr_r}, F1={tr_f1}")
    print(f"Val metrics   (tau={tau}): Precision={val_p}, Recall={val_r}, F1={val_f1}")
    print(f"Test metrics  (tau={tau}): Precision={te_p}, Recall={te_r}, F1={te_f1} (TP={tp}, FP={fp}, FN={fn}, TN={tn})")

    meta_payload = {
        "model_version": "1.0.0",
        "init_method": "he",
        "dataset_manifest_sha256": manifest_sha256,
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
            "init_method": "he",
        },
        "metrics": {
            "train_loss": train_metrics["final_train_loss"],
            "test_precision": te_p,
            "test_recall": te_r,
            "test_f1": te_f1,
            "layer1_active_ratio": active_diag["layer1_active_ratio"],
            "layer2_active_ratio": active_diag["layer2_active_ratio"],
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

    if HAS_TORCH:
        print("6. Synchronizing and verifying PyTorch model and ONNX equivalence...")
        torch_model = PyTorchAnomalyMLP()
        torch_model.load_from_compact_mlp(model)
        pt_path = models_dir / "anomaly_detector_v1.pt"
        torch_model.save_pt(pt_path)
        print(f"PyTorch state_dict saved to: {pt_path}")

        test_vectors = test_split.features[:100] if len(test_split) >= 100 else test_split.features
        is_equiv, max_err = verify_pytorch_onnx_equivalence(
            torch_model, onnx_path, test_vectors, float_tolerance=1e-5
        )
        print(f"PyTorch vs ONNX numerical equivalence (<= 1e-5): {is_equiv} (max error: {max_err:.2e})")
        assert is_equiv, f"PyTorch and ONNX discrepancy exceeded tolerance: {max_err}"

    print("7. Verifying model integrity...")
    assert verify_model_integrity("anomaly_detector_v1", models_dir=models_dir)
    print("Model integrity verification PASSED!")

    print("8. Evaluating real incident entities with XAI and MITRE mappings...")
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
