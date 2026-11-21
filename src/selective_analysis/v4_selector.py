"""Learned structural selector L for Route B v4, exactly as fixed in the pre-registration.

Features: structural_features v1 vector, standardized with development mean and standard deviation,
zero-variance features dropped. Per backend: L2 logistic regression (lambda 1.0, Newton iterations
to a 1e-10 gradient norm, zero initialization) for P(decisive within budget), and ridge regression
(lambda 1.0) on log charged seconds. Order rule: choose the order with the smaller expected time
E = min(t_first, B) + (1 - p_first) * min(t_second, B); a tie selects F (symbolic first).
The intercepts are not penalized. Numpy only.
"""
import math

import numpy as np

BACKENDS = ("symbolic_certificate", "concrete_enumeration")
F_ORDER = ("symbolic_certificate", "concrete_enumeration")
C_ORDER = ("concrete_enumeration", "symbolic_certificate")
LAMBDA = 1.0
GRADIENT_TOLERANCE = 1e-10
BUDGET_SECONDS = 3.0
MODEL_SCHEMA = "symbai.route_b_v4_selector.v1"


def standardizer(rows):
    x = np.asarray(rows, dtype=np.float64)
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    keep = [i for i in range(x.shape[1]) if std[i] > 0]
    return {"mean": mean[keep].tolist(), "std": std[keep].tolist(), "keep": keep}


def transform(rows, scale):
    x = np.asarray(rows, dtype=np.float64)[:, scale["keep"]]
    z = (x - np.asarray(scale["mean"])) / np.asarray(scale["std"])
    return np.hstack([np.ones((z.shape[0], 1)), z])


def fit_logistic(z, y, lam=LAMBDA, tolerance=GRADIENT_TOLERANCE, max_iterations=200):
    y = np.asarray(y, dtype=np.float64)
    w = np.zeros(z.shape[1])
    penalty = np.full(z.shape[1], lam)
    penalty[0] = 0.0
    for _ in range(max_iterations):
        p = 1.0 / (1.0 + np.exp(-(z @ w)))
        gradient = z.T @ (p - y) + penalty * w
        if np.linalg.norm(gradient) <= tolerance:
            break
        hessian = (z * (p * (1 - p))[:, None]).T @ z + np.diag(penalty)
        w = w - np.linalg.solve(hessian, gradient)
    else:
        raise ValueError("Logistic regression did not converge")
    return w.tolist()


def fit_ridge(z, target, lam=LAMBDA):
    penalty = np.full(z.shape[1], lam)
    penalty[0] = 0.0
    return np.linalg.solve(z.T @ z + np.diag(penalty), z.T @ np.asarray(target, dtype=np.float64)).tolist()


def fit(feature_rows, labels):
    """labels: per row {backend: {"decisive": bool, "seconds": float}} (one entry per run)."""
    scale = standardizer(feature_rows)
    z = transform(feature_rows, scale)
    model = {"schema": MODEL_SCHEMA, "lambda": LAMBDA, "budget_seconds": BUDGET_SECONDS, "scale": scale,
             "backends": {}}
    for backend in BACKENDS:
        y = [1.0 if row[backend]["decisive"] else 0.0 for row in labels]
        t = [math.log(max(row[backend]["seconds"], 1e-6)) for row in labels]
        model["backends"][backend] = {"logistic": fit_logistic(z, y), "ridge_log_seconds": fit_ridge(z, t),
                                      "positives": int(sum(y)), "rows": len(y)}
    return model


def predict(model, features):
    z = transform([features], model["scale"])[0]
    out = {}
    for backend, params in model["backends"].items():
        p = 1.0 / (1.0 + math.exp(-float(z @ np.asarray(params["logistic"]))))
        t = math.exp(float(z @ np.asarray(params["ridge_log_seconds"])))
        out[backend] = {"p_decisive": p, "seconds": t}
    return out


def expected_seconds(prediction, order, budget=BUDGET_SECONDS):
    first, second = order
    return (min(prediction[first]["seconds"], budget)
            + (1 - prediction[first]["p_decisive"]) * min(prediction[second]["seconds"], budget))


def choose_order(model, features):
    prediction = predict(model, features)
    f, c = expected_seconds(prediction, F_ORDER), expected_seconds(prediction, C_ORDER)
    return (C_ORDER if c < f else F_ORDER), {"prediction": prediction, "expected_F": f, "expected_C": c}
