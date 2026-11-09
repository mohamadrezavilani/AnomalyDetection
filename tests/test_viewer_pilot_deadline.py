"""Wall-clock deadline reaches active SQL and the next CPU progress check."""
import unittest
from unittest.mock import Mock
from tools.run_viewer_pilot import PilotDeadline,PilotBudgetExceeded


class PilotDeadlineTests(unittest.TestCase):
    def test_expiry_cancels_current_connection_and_stops_cpu_work(self):
        budget=PilotDeadline(60);budget.connection=Mock()
        budget.check();budget.expire()
        budget.connection.cancel_safe.assert_called_once_with()
        with self.assertRaisesRegex(PilotBudgetExceeded,'pilot_time_budget_exceeded'):budget.check()

    def test_closed_connection_cannot_disable_the_budget(self):
        budget=PilotDeadline(60);budget.connection=Mock()
        budget.connection.cancel_safe.side_effect=OSError('closed')
        budget.expire()
        with self.assertRaises(PilotBudgetExceeded):budget.check()

    def test_viewer_progress_does_not_swallow_budget_expiry_as_console_io(self):
        from p24_foundation.viewer_data import ViewerDB
        db=object.__new__(ViewerDB);budget=PilotDeadline(60)
        db.progress_callback=lambda event:budget.check()
        budget.expire()
        with self.assertRaises(PilotBudgetExceeded):db.progress('semantic_index',processed=7500)


if __name__=='__main__':unittest.main()
