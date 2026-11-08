from datetime import datetime, timezone
import unittest

from anomaly_detection.temporal import Point, fit, predict, phase, BUCKET_NS

START = int(datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()) * 1_000_000_000


def series(count, function):
    return [Point(START + index * BUCKET_NS, function(START + index * BUCKET_NS), True, True) for index in range(count)]


class AutomaticBaselineTests(unittest.TestCase):
    def test_day_night_pattern_is_selected_without_a_period_parameter(self):
        rows = series(288 * 6, lambda at: 100 if 96 <= phase(at, "daily") < 240 else 10)
        model = fit(rows, before_ns=START + len(rows) * BUCKET_NS)
        self.assertEqual(model["family"], "daily")
        future = START + len(rows) * BUCKET_NS
        for offset in range(288):
            at = future + offset * BUCKET_NS
            prediction = predict(model, at)
            expected = 100 if 96 <= phase(at, "daily") < 240 else 10
            self.assertAlmostEqual(prediction["expected"], expected)
            self.assertFalse(prediction["operator_alert"])

    def test_weekly_pattern_requires_repeated_week_history_and_is_selected_automatically(self):
        rows = series(2016 * 5, lambda at: 20 if phase(at, "weekly") // 288 in (4, 5) else 100)
        model = fit(rows, before_ns=START + len(rows) * BUCKET_NS)
        self.assertEqual(model["family"], "weekly")

    def test_short_history_does_not_claim_weekly_or_daily_learning(self):
        rows = series(100, lambda _: 10)
        model = fit(rows, before_ns=START + len(rows) * BUCKET_NS)
        self.assertEqual(model["family"], "rolling")
        self.assertFalse(any(row["family"] in ("daily", "weekly") for row in model["candidates"]))

    def test_twenty_five_valid_windows_are_warming_up_not_normal(self):
        rows = series(25, lambda _: 10)
        model = fit(rows, before_ns=START + len(rows) * BUCKET_NS)
        self.assertEqual(model["status"], "WARMING_UP")
        self.assertEqual(predict(model, START + len(rows) * BUCKET_NS)["status"], "NOT_READY")

    def test_incomplete_population_is_never_used_as_training_history(self):
        rows = [Point(START + index * BUCKET_NS, 10, True, False) for index in range(100)]
        self.assertEqual(fit(rows, before_ns=START + 100 * BUCKET_NS)["observations"], 0)

    def test_large_missing_ranges_are_not_zero_filled(self):
        rows = series(200, lambda _: 10)[::2]
        model = fit(rows, before_ns=START + 200 * BUCKET_NS)
        self.assertEqual(model["status"], "INSUFFICIENT_COVERAGE")

    def test_future_observations_do_not_leak_into_selection_or_fit(self):
        rows = series(100, lambda _: 10)
        cutoff = START + len(rows) * BUCKET_NS
        expected = fit(rows, before_ns=cutoff)
        actual = fit(rows + [Point(cutoff, 100000, True, True)], before_ns=cutoff)
        self.assertEqual(expected["model_id"], actual["model_id"])

    def test_duplicate_timestamp_cannot_inflate_observation_count(self):
        rows = series(100, lambda _: 10)
        with self.assertRaises(ValueError):
            fit(rows + [rows[0]], before_ns=START + 100 * BUCKET_NS)

    def test_stable_metric_does_not_force_a_seasonal_model(self):
        rows = series(288 * 4, lambda _: 10)
        self.assertEqual(fit(rows, before_ns=START + len(rows) * BUCKET_NS)["family"], "rolling")

    def test_old_history_cannot_claim_a_ready_current_forecast_after_a_long_gap(self):
        rows=series(100,lambda _:10)
        self.assertEqual(fit(rows,before_ns=START+200*BUCKET_NS)["status"],"INSUFFICIENT_RECENT_COVERAGE")


if __name__ == "__main__":
    unittest.main()
