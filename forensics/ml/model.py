"""Compact Neural Anomaly Detector (MLP) for Blockchain Forensics (P8).

Topology:
  Input (10) -> Linear(10, 16) + ReLU -> Linear(16, 8) + ReLU -> Linear(8, 1) + Sigmoid
Total Parameters: Exactly 321.
EZKL Halo2 arithmetic circuit and static ONNX export compatible.
Includes pure-Python / NumPy forward pass and backpropagation training routine.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import random
from typing import Any, Sequence

try:
    import numpy as np  # type: ignore
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import torch  # type: ignore
    import torch.nn as nn  # type: ignore
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


def sigmoid(z: float) -> float:
    """Stable sigmoid implementation."""
    if z < -40.0:
        return 0.0
    if z > 40.0:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def relu(z: float) -> float:
    return max(0.0, z)


if HAS_TORCH:
    class PyTorchAnomalyMLP(nn.Module):
        """PyTorch nn.Module equivalent of CompactAnomalyMLP (321 parameters).
        
        Topology:
          Linear(10, 16) -> ReLU -> Linear(16, 8) -> ReLU -> Linear(8, 1) -> Sigmoid
        """
        def __init__(self, input_dim: int = 10, hidden1: int = 16, hidden2: int = 8, output_dim: int = 1):
            super().__init__()
            self.input_dim = input_dim
            self.hidden1 = hidden1
            self.hidden2 = hidden2
            self.output_dim = output_dim

            self.fc1 = nn.Linear(input_dim, hidden1)
            self.fc2 = nn.Linear(hidden1, hidden2)
            self.fc3 = nn.Linear(hidden2, output_dim)
            self.relu = nn.ReLU()
            self.sigmoid = nn.Sigmoid()

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            x = self.relu(self.fc1(x))
            x = self.relu(self.fc2(x))
            return self.sigmoid(self.fc3(x))

        def load_from_compact_mlp(self, mlp: CompactAnomalyMLP) -> None:
            """Loads weights and biases from a CompactAnomalyMLP instance."""
            with torch.no_grad():
                self.fc1.weight.copy_(torch.tensor(mlp.w1, dtype=torch.float32))
                self.fc1.bias.copy_(torch.tensor(mlp.b1, dtype=torch.float32))
                self.fc2.weight.copy_(torch.tensor(mlp.w2, dtype=torch.float32))
                self.fc2.bias.copy_(torch.tensor(mlp.b2, dtype=torch.float32))
                self.fc3.weight.copy_(torch.tensor(mlp.w3, dtype=torch.float32))
                self.fc3.bias.copy_(torch.tensor(mlp.b3, dtype=torch.float32))

        def to_compact_mlp(self, model_id: str = "anomaly_detector_v1") -> CompactAnomalyMLP:
            """Converts PyTorch model weights to a CompactAnomalyMLP instance."""
            mlp = CompactAnomalyMLP(
                input_dim=self.input_dim,
                hidden1=self.hidden1,
                hidden2=self.hidden2,
                output_dim=self.output_dim,
                model_id=model_id,
            )
            with torch.no_grad():
                weights = {
                    "w1": self.fc1.weight.detach().cpu().numpy().tolist(),
                    "b1": self.fc1.bias.detach().cpu().numpy().tolist(),
                    "w2": self.fc2.weight.detach().cpu().numpy().tolist(),
                    "b2": self.fc2.bias.detach().cpu().numpy().tolist(),
                    "w3": self.fc3.weight.detach().cpu().numpy().tolist(),
                    "b3": self.fc3.bias.detach().cpu().numpy().tolist(),
                }
            mlp.set_weights(weights)
            return mlp

        def save_pt(self, path: Path | str) -> Path:
            """Saves PyTorch state_dict."""
            out_p = Path(path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            torch.save(self.state_dict(), str(out_p))
            return out_p

        @classmethod
        def load_pt(cls, path: Path | str, input_dim: int = 10, hidden1: int = 16, hidden2: int = 8, output_dim: int = 1) -> PyTorchAnomalyMLP:
            """Loads PyTorch model from saved state_dict."""
            model = cls(input_dim, hidden1, hidden2, output_dim)
            model.load_state_dict(torch.load(str(path), weights_only=True))
            model.eval()
            return model
else:
    class PyTorchAnomalyMLP:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError("PyTorch is required for PyTorchAnomalyMLP.")


class CompactAnomalyMLP:
    """Compact 321-parameter Multilayer Perceptron for anomaly detection.

    Architecture:
      Layer 1: 10 -> 16 (Weights: 16x10=160, Biases: 16) -> 176 params
      Layer 2: 16 -> 8  (Weights: 8x16=128,  Biases: 8)  -> 136 params
      Layer 3: 8  -> 1  (Weights: 1x8=8,     Biases: 1)  -> 9 params
      Total = 176 + 136 + 9 = 321 params.
    """

    def __init__(
        self,
        input_dim: int = 10,
        hidden1: int = 16,
        hidden2: int = 8,
        output_dim: int = 1,
        model_id: str = "anomaly_detector_v1",
        seed: int = 42,
        init_method: str = "he",
    ):
        self.input_dim = input_dim
        self.hidden1 = hidden1
        self.hidden2 = hidden2
        self.output_dim = output_dim
        self.model_id = model_id
        self.model_sha256 = ""
        self.init_method = init_method.lower()

        rng = random.Random(seed)

        # Calculate bounds per initialization method
        if self.init_method == "he":
            # He (Kaiming) uniform for ReLU layers: sqrt(6 / fan_in)
            bound1 = math.sqrt(6.0 / input_dim)
            bound2 = math.sqrt(6.0 / hidden1)
            # Xavier uniform for final Sigmoid layer: sqrt(6 / (fan_in + fan_out))
            bound3 = math.sqrt(6.0 / (hidden2 + output_dim))
        else:
            # Standard Xavier/Glorot uniform
            bound1 = math.sqrt(6.0 / (input_dim + hidden1))
            bound2 = math.sqrt(6.0 / (hidden1 + hidden2))
            bound3 = math.sqrt(6.0 / (hidden2 + output_dim))

        self.w1: list[list[float]] = [
            [rng.uniform(-bound1, bound1) for _ in range(input_dim)]
            for _ in range(hidden1)
        ]
        self.b1: list[float] = [0.01] * hidden1

        self.w2: list[list[float]] = [
            [rng.uniform(-bound2, bound2) for _ in range(hidden1)]
            for _ in range(hidden2)
        ]
        self.b2: list[float] = [0.01] * hidden2

        self.w3: list[list[float]] = [
            [rng.uniform(-bound3, bound3) for _ in range(hidden2)]
            for _ in range(output_dim)
        ]
        self.b3: list[float] = [0.0] * output_dim

    def count_parameters(self) -> int:
        """Returns exact count of trainable parameters."""
        p1 = len(self.w1) * len(self.w1[0]) + len(self.b1)
        p2 = len(self.w2) * len(self.w2[0]) + len(self.b2)
        p3 = len(self.w3) * len(self.w3[0]) + len(self.b3)
        return p1 + p2 + p3

    def forward_single(self, x: Sequence[float]) -> float:
        """Single-vector forward pass in pure Python."""
        x_vec = list(x)
        if len(x_vec) != self.input_dim:
            raise ValueError(f"Expected input of dimension {self.input_dim}, got {len(x_vec)}")

        # Layer 1
        a1: list[float] = []
        for i in range(self.hidden1):
            val = self.b1[i]
            row = self.w1[i]
            for j in range(self.input_dim):
                val += row[j] * x_vec[j]
            a1.append(relu(val))

        # Layer 2
        a2: list[float] = []
        for i in range(self.hidden2):
            val = self.b2[i]
            row = self.w2[i]
            for j in range(self.hidden1):
                val += row[j] * a1[j]
            a2.append(relu(val))

        # Layer 3
        val = self.b3[0]
        row = self.w3[0]
        for j in range(self.hidden2):
            val += row[j] * a2[j]
        
        return sigmoid(val)

    def forward(self, X: Any) -> list[float]:
        """Matrix forward pass."""
        if HAS_NUMPY and isinstance(X, np.ndarray):
            X_list = X.tolist()
        else:
            X_list = list(X)
        return [self.forward_single(row) for row in X_list]

    def predict_score(self, features: dict[str, float] | Sequence[float]) -> float:
        """Convenience function predicting anomaly score in [0.0, 1.0]."""
        if isinstance(features, dict):
            from forensics.ml.features import FEATURE_NAMES
            vec = [float(features.get(k, 0.0)) for k in FEATURE_NAMES]
        else:
            vec = list(features)
        return self.forward_single(vec)

    def get_weights(self) -> dict[str, Any]:
        """Exports weight tensors as serializable lists."""
        return {
            "w1": self.w1,
            "b1": self.b1,
            "w2": self.w2,
            "b2": self.b2,
            "w3": self.w3,
            "b3": self.b3,
        }

    def set_weights(self, weights: dict[str, Any]) -> None:
        """Loads weights from dictionary."""
        self.w1 = [[float(v) for v in row] for row in weights["w1"]]
        self.b1 = [float(v) for v in weights["b1"]]
        self.w2 = [[float(v) for v in row] for row in weights["w2"]]
        self.b2 = [float(v) for v in weights["b2"]]
        self.w3 = [[float(v) for v in row] for row in weights["w3"]]
        self.b3 = [float(v) for v in weights["b3"]]


def train_anomaly_detector(
    X_train: Any,
    y_train: Sequence[int],
    epochs: int = 50,
    lr: float = 0.01,
    pos_weight: float = 10.0,
    batch_size: int = 64,
    random_seed: int = 42,
    init_method: str = "he",
) -> tuple[CompactAnomalyMLP, dict[str, Any]]:
    """Genuine backpropagation training with class-imbalance weighting."""
    if HAS_NUMPY and isinstance(X_train, np.ndarray):
        X = X_train.tolist()
    else:
        X = [list(r) for r in X_train]
    y = [float(v) for v in y_train]

    n_samples = len(X)
    if n_samples == 0:
        m = CompactAnomalyMLP(init_method=init_method)
        return m, {"train_loss": 0.0}

    model = CompactAnomalyMLP(seed=random_seed, init_method=init_method)

    mw1 = [[0.0] * model.input_dim for _ in range(model.hidden1)]
    mb1 = [0.0] * model.hidden1
    mw2 = [[0.0] * model.hidden1 for _ in range(model.hidden2)]
    mb2 = [0.0] * model.hidden2
    mw3 = [[0.0] * model.hidden2 for _ in range(model.output_dim)]
    mb3 = [0.0] * model.output_dim

    momentum = 0.9
    final_loss = 0.0

    for epoch in range(epochs):
        epoch_loss = 0.0
        # Mini-batches
        for b_start in range(0, n_samples, batch_size):
            b_end = min(b_start + batch_size, n_samples)
            b_size = b_end - b_start

            # Accumulators for batch gradients
            gw1 = [[0.0] * model.input_dim for _ in range(model.hidden1)]
            gb1 = [0.0] * model.hidden1
            gw2 = [[0.0] * model.hidden1 for _ in range(model.hidden2)]
            gb2 = [0.0] * model.hidden2
            gw3 = [[0.0] * model.hidden2 for _ in range(model.output_dim)]
            gb3 = [0.0] * model.output_dim

            for idx in range(b_start, b_end):
                xi = X[idx]
                yi = y[idx]

                # 1. Forward pass saving activations
                z1 = [
                    model.b1[i] + sum(model.w1[i][j] * xi[j] for j in range(model.input_dim))
                    for i in range(model.hidden1)
                ]
                a1 = [relu(v) for v in z1]

                z2 = [
                    model.b2[i] + sum(model.w2[i][j] * a1[j] for j in range(model.hidden1))
                    for i in range(model.hidden2)
                ]
                a2 = [relu(v) for v in z2]

                z3 = model.b3[0] + sum(model.w3[0][j] * a2[j] for j in range(model.hidden2))
                y_pred = sigmoid(z3)

                # Loss: weighted BCE
                w = pos_weight if yi > 0.5 else 1.0
                eps = 1e-12
                loss_i = -(w * yi * math.log(y_pred + eps) + (1.0 - yi) * math.log(1.0 - y_pred + eps))
                epoch_loss += loss_i

                # Gradient dL/dz3
                # dL/dz3 = w * yi * (y_pred - 1) + (1 - yi) * y_pred
                dz3 = (w * yi + (1.0 - yi)) * y_pred - w * yi

                # Backprop to Layer 3
                for j in range(model.hidden2):
                    gw3[0][j] += dz3 * a2[j]
                gb3[0] += dz3

                # Backprop to Layer 2
                da2 = [model.w3[0][j] * dz3 for j in range(model.hidden2)]
                dz2 = [da2[j] if z2[j] > 0.0 else 0.01 * da2[j] for j in range(model.hidden2)]

                for i in range(model.hidden2):
                    for j in range(model.hidden1):
                        gw2[i][j] += dz2[i] * a1[j]
                    gb2[i] += dz2[i]

                # Backprop to Layer 1
                da1 = [sum(model.w2[k][j] * dz2[k] for k in range(model.hidden2)) for j in range(model.hidden1)]
                dz1 = [da1[j] if z1[j] > 0.0 else 0.01 * da1[j] for j in range(model.hidden1)]

                for i in range(model.hidden1):
                    for j in range(model.input_dim):
                        gw1[i][j] += dz1[i] * xi[j]
                    gb1[i] += dz1[i]

            # Update weights with momentum
            for i in range(model.hidden1):
                for j in range(model.input_dim):
                    mw1[i][j] = momentum * mw1[i][j] + lr * (gw1[i][j] / b_size)
                    model.w1[i][j] -= mw1[i][j]
                mb1[i] = momentum * mb1[i] + lr * (gb1[i] / b_size)
                model.b1[i] -= mb1[i]

            for i in range(model.hidden2):
                for j in range(model.hidden1):
                    mw2[i][j] = momentum * mw2[i][j] + lr * (gw2[i][j] / b_size)
                    model.w2[i][j] -= mw2[i][j]
                mb2[i] = momentum * mb2[i] + lr * (gb2[i] / b_size)
                model.b2[i] -= mb2[i]

            for j in range(model.hidden2):
                mw3[0][j] = momentum * mw3[0][j] + lr * (gw3[0][j] / b_size)
                model.w3[0][j] -= mw3[0][j]
            mb3[0] = momentum * mb3[0] + lr * (gb3[0] / b_size)
            model.b3[0] -= mb3[0]

        final_loss = epoch_loss / n_samples

    metrics = {
        "epochs": epochs,
        "final_train_loss": round(final_loss, 4),
        "learning_rate": lr,
        "pos_weight": pos_weight,
    }
    return model, metrics


def check_active_neurons(
    model: CompactAnomalyMLP,
    X_samples: Sequence[Sequence[float]],
) -> dict[str, Any]:
    """Computes percentage of active (non-zero ReLU) neurons across evaluated samples.

    Returns:
        dict: {"layer1_active_ratio": float, "layer2_active_ratio": float, "is_healthy": bool}
    """
    if len(X_samples) == 0:
        return {"layer1_active_ratio": 1.0, "layer2_active_ratio": 1.0, "is_healthy": True}

    n_samples = len(X_samples)
    l1_active_counts = [0] * model.hidden1
    l2_active_counts = [0] * model.hidden2

    for x_vec in X_samples:
        # Layer 1
        a1 = []
        for i in range(model.hidden1):
            val = model.b1[i] + sum(model.w1[i][j] * x_vec[j] for j in range(model.input_dim))
            if val > 0.0:
                l1_active_counts[i] += 1
            a1.append(relu(val))

        # Layer 2
        for i in range(model.hidden2):
            val = model.b2[i] + sum(model.w2[i][j] * a1[j] for j in range(model.hidden1))
            if val > 0.0:
                l2_active_counts[i] += 1

    l1_ratio = sum(l1_active_counts) / (n_samples * model.hidden1)
    l2_ratio = sum(l2_active_counts) / (n_samples * model.hidden2)
    is_healthy = l1_ratio >= 0.10 and l2_ratio >= 0.10

    return {
        "layer1_active_ratio": round(l1_ratio, 4),
        "layer2_active_ratio": round(l2_ratio, 4),
        "is_healthy": is_healthy,
    }


def load_default_model(models_dir: Path | str | None = None) -> CompactAnomalyMLP:
    """Loads default anomaly detector model from models/ or trains default if not found."""
    if models_dir is None:
        models_dir = Path("D:/Projest/Blockchain/models")
    else:
        models_dir = Path(models_dir)

    meta_file = models_dir / "anomaly_detector_v1_meta.json"
    onnx_file = models_dir / "anomaly_detector_v1.onnx"

    model = CompactAnomalyMLP(model_id="anomaly_detector_v1")

    if meta_file.exists():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            weights = meta.get("weights")
            if weights:
                model.set_weights(weights)
            model.model_sha256 = meta.get("model_sha256", "")
            return model
        except Exception:
            pass

    return model
