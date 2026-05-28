from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np


def _activation_name(layer) -> str:
    act = getattr(layer, "activation", None)
    return getattr(act, "__name__", str(act or "linear"))


def _forward(layers, x):
    out = np.asarray(x, dtype=np.float32)
    for layer in layers:
        out = out @ layer["W"] + layer["b"]
        act = layer["activation"].lower()
        if act == "relu":
            out = np.maximum(out, 0.0)
        elif act == "sigmoid":
            out = 1.0 / (1.0 + np.exp(-np.clip(out, -60.0, 60.0)))
        elif act in {"linear", "none"}:
            pass
        elif act == "tanh":
            out = np.tanh(out)
        else:
            raise ValueError(f"Unsupported activation for NumPy export: {act}")
    return out.astype(np.float32)


def main() -> int:
    root = Path.cwd()
    pkl_path = root / "models" / "autoencoder.pkl"
    if not pkl_path.exists():
        raise FileNotFoundError(f"Missing {pkl_path}")

    with pkl_path.open("rb") as f:
        meta = pickle.load(f)

    if "keras_filename" in meta:
        keras_path = pkl_path.parent / meta["keras_filename"]
    elif "keras_path" in meta:
        old = Path(meta["keras_path"])
        keras_path = old if old.exists() else pkl_path.parent / old.name
    else:
        keras_path = pkl_path.with_suffix(".keras")

    if not keras_path.exists():
        raise FileNotFoundError(f"Missing Keras model: {keras_path}")

    import tensorflow as tf

    model = tf.keras.models.load_model(keras_path, compile=False)
    layers = []
    for layer in model.layers:
        weights = layer.get_weights()
        if len(weights) == 2:
            W, b = weights
            layers.append({
                "name": layer.name,
                "activation": _activation_name(layer),
                "W": np.asarray(W, dtype=np.float32),
                "b": np.asarray(b, dtype=np.float32),
            })

    if not layers:
        raise RuntimeError("No Dense weight layers were found in the Keras autoencoder.")

    n_features = int(meta.get("n_features", model.input_shape[-1]))
    rng = np.random.default_rng(42)
    sample = rng.random((4, n_features), dtype=np.float32)

    tf_pred = model.predict(sample, verbose=0).astype(np.float32)
    np_pred = _forward(layers, sample)
    max_abs_diff = float(np.max(np.abs(tf_pred - np_pred)))

    if max_abs_diff > 1e-4:
        raise RuntimeError(
            f"NumPy autoencoder verification failed: max abs diff {max_abs_diff:.8f} > 1e-4"
        )

    out = pkl_path.parent / "autoencoder_numpy_runtime.npz"
    payload = {
        "n_layers": np.array(len(layers), dtype=np.int32),
        "n_features": np.array(n_features, dtype=np.int32),
        "max_abs_diff": np.array(max_abs_diff, dtype=np.float32),
    }
    for i, layer in enumerate(layers):
        payload[f"layer_{i}_name"] = np.array(layer["name"])
        payload[f"layer_{i}_activation"] = np.array(layer["activation"])
        payload[f"layer_{i}_W"] = layer["W"]
        payload[f"layer_{i}_b"] = layer["b"]

    np.savez_compressed(out, **payload)
    print(f"[RAMDetect] Exported NumPy AE runtime: {out}")
    print(f"[RAMDetect] Layers: {len(layers)}")
    print(f"[RAMDetect] Verification max abs diff: {max_abs_diff:.8f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
