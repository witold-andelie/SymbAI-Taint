"""Synthetic checks of the frozen Route B v4 selector L (numpy only)."""
import math

from src.selective_analysis import v4_selector as sel


def data():
    # Feature 0 separates "symbolic works" from "symbolic fails"; feature 1 is constant (dropped).
    rows, labels = [], []
    for i in range(40):
        good = i % 2 == 0
        rows.append([1.0 if good else 0.0, 5.0, float(i % 7)])
        labels.append({"symbolic_certificate": {"decisive": good, "seconds": 0.2 if good else 3.0},
                       "concrete_enumeration": {"decisive": True, "seconds": 1.5}})
    return rows, labels


def test_fit_drops_constant_features_and_converges():
    rows, labels = data()
    model = sel.fit(rows, labels)
    assert model["scale"]["keep"] == [0, 2]
    for params in model["backends"].values():
        assert len(params["logistic"]) == 3 and len(params["ridge_log_seconds"]) == 3


def test_orders_follow_expected_time():
    rows, labels = data()
    model = sel.fit(rows, labels)
    order_good, info = sel.choose_order(model, [1.0, 5.0, 3.0])
    order_bad, _ = sel.choose_order(model, [0.0, 5.0, 3.0])
    assert order_good == sel.F_ORDER and order_bad == sel.C_ORDER
    assert math.isclose(info["expected_F"], sel.expected_seconds(info["prediction"], sel.F_ORDER))


def test_tie_selects_symbolic_first():
    prediction = {b: {"p_decisive": 0.5, "seconds": 1.0} for b in sel.BACKENDS}
    assert sel.expected_seconds(prediction, sel.F_ORDER) == sel.expected_seconds(prediction, sel.C_ORDER)
    model = {"scale": {"mean": [0.0], "std": [1.0], "keep": [0]},
             "backends": {b: {"logistic": [0.0, 0.0], "ridge_log_seconds": [0.0, 0.0]} for b in sel.BACKENDS}}
    assert sel.choose_order(model, [3.0])[0] == sel.F_ORDER


def test_expected_seconds_caps_at_budget():
    prediction = {"symbolic_certificate": {"p_decisive": 0.0, "seconds": 50.0},
                  "concrete_enumeration": {"p_decisive": 1.0, "seconds": 50.0}}
    assert sel.expected_seconds(prediction, sel.F_ORDER) == 2 * sel.BUDGET_SECONDS
