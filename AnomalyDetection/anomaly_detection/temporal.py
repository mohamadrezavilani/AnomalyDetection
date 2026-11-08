"""Automatic forecasting from owned complete aggregate history; no alert publisher.

Predictive bands are empirical residuals, not fraud probabilities or proof of
production precision. Internal policies require no operator model settings.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from statistics import median
from zoneinfo import ZoneInfo

BUCKET_NS = 300_000_000_000
TIMEZONE = ZoneInfo("Asia/Tehran")
PERIODS = {"hourly": 12, "daily": 288, "weekly": 2016}


@dataclass(frozen=True)
class Point:
    at_ns: int
    value: float | None
    coverage_complete: bool = False
    population_complete: bool = False


def phase(at_ns, period):
    value = datetime.fromtimestamp(at_ns // 1_000_000_000, timezone.utc).astimezone(TIMEZONE)
    within_day = value.hour * 12 + value.minute // 5
    return (value.minute // 5 if period == "hourly" else within_day if period == "daily"
            else value.weekday() * 288 + within_day)


def quantile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def profile(points, period):
    groups = {}
    for point in points:
        groups.setdefault(phase(point.at_ns, period), []).append(math.log1p(point.value))
    return {key: median(values) for key, values in groups.items()}, groups


def fit(points, *, before_ns):
    """Choose rolling/hourly/daily/weekly automatically on a temporal holdout.

    Constants below are internal model policies, not operator settings.
    Held-out prediction error measures forecasting fit, not alert precision.
    """
    if type(before_ns) is not int or before_ns % BUCKET_NS:
        raise ValueError("aligned cutoff required")
    points = list(points)
    if len(points) > 50_000:
        raise ValueError("baseline input budget exceeded")
    times = [point.at_ns for point in points]
    if any(type(at) is not int or at % BUCKET_NS for at in times) or len(set(times)) != len(times):
        raise ValueError("unique aligned timestamps required")
    usable = sorted([point for point in points if point.at_ns < before_ns and
        point.coverage_complete is True and point.population_complete is True and
        type(point.value) in (int, float) and math.isfinite(point.value) and point.value >= 0], key=lambda point: point.at_ns)
    basic = {"version": "automatic-baseline-1", "cutoff_ns": before_ns, "observations": len(usable),
             "operator_parameters_required": False, "integration": "owned_summary_shadow_forecasting", "operator_alert": False,
             "alert_precision": "NOT_MEASURED", "seasonality_timezone": "Asia/Tehran"}
    if len(usable) < 60:
        return dict(basic, status="WARMING_UP", reason="insufficient_complete_series_history")
    if usable[-1].at_ns < before_ns - 2 * BUCKET_NS:
        return dict(basic, status="INSUFFICIENT_RECENT_COVERAGE", reason="recent_complete_history_missing")
    slots = (usable[-1].at_ns - usable[0].at_ns) // BUCKET_NS + 1
    coverage = len(usable) / slots
    if coverage < 0.80:
        return dict(basic, status="INSUFFICIENT_COVERAGE", coverage=coverage)
    cut = max(30, int(len(usable) * 0.75))
    train, validation = usable[:cut], usable[cut:]
    running = [math.log1p(point.value) for point in train]
    residuals = []
    for point in validation:
        predicted = median(running[-24:])
        observed = math.log1p(point.value)
        residuals.append(observed - predicted)
        running.append(observed)
    baseline_error = sum(abs(value) for value in residuals) / len(residuals)
    candidates = [{"family": "rolling", "validation_log_mae": baseline_error}]
    chosen = "rolling"
    best_error = baseline_error
    chosen_residuals = residuals
    span_slots = (usable[-1].at_ns - usable[0].at_ns) // BUCKET_NS + 1
    for period, slots_per_cycle in PERIODS.items():
        if span_slots < 3 * slots_per_cycle or len(usable) < 3 * slots_per_cycle * 0.90:
            continue
        fitted, groups = profile(train, period)
        if sum(len(values) >= 2 for values in groups.values()) < slots_per_cycle * 0.90:
            continue
        if not all(phase(point.at_ns, period) in fitted for point in validation):
            continue
        errors = [math.log1p(point.value) - fitted[phase(point.at_ns, period)] for point in validation]
        error = sum(abs(value) for value in errors) / len(errors)
        candidates.append({"family": period, "validation_log_mae": error})
        if error < best_error and error <= baseline_error * 0.75:
            chosen, best_error, chosen_residuals = period, error, errors
    fitted = profile(usable, chosen)[0] if chosen != "rolling" else {}
    result = dict(basic, status="READY_BASELINE", family=chosen, coverage=coverage,
                  candidates=candidates, validation_samples=len(validation), validation_log_mae=best_error,
                  train_last_ns=usable[-1].at_ns, profile={str(key): value for key, value in fitted.items()},
                  rolling_log_median=median(math.log1p(point.value) for point in usable[-24:]),
                  residual_low=quantile(chosen_residuals, 0.005), residual_high=quantile(chosen_residuals, 0.995),
                  calibration_scope="empirical_forecast_residuals_not_fraud_or_false_positive_probability",
                  source_digest=hashlib.sha256(json.dumps([(p.at_ns, p.value) for p in usable], separators=(",", ":")).encode()).hexdigest())
    result["model_id"] = "abp1:" + hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def predict(model, at_ns):
    if model.get("status") != "READY_BASELINE":
        return {"status": "NOT_READY", "operator_alert": False}
    if at_ns < model["cutoff_ns"] or at_ns % BUCKET_NS:
        raise ValueError("future aligned prediction required")
    family = model["family"]
    log_expected = model["rolling_log_median"] if family == "rolling" else model["profile"].get(str(phase(at_ns, family)))
    if log_expected is None:
        return {"status": "UNKNOWN_PHASE", "operator_alert": False}
    return {"status": "PREDICTION_ONLY", "family": family,
            "expected": max(0, math.expm1(log_expected)),
            "lower": max(0, math.expm1(log_expected + model["residual_low"])),
            "upper": max(0, math.expm1(log_expected + model["residual_high"])),
            "operator_alert": False,
            "reason": "forecast_is_not_a_published_customer_suspicion_alert"}
