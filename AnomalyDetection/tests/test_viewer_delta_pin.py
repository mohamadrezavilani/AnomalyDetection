"""R3.2 is an exact release pin; historical overlays cannot admit mixed trees."""
import unittest
from anomaly_detection.source_profiles import (R3_RUNTIME,R31_RUNTIME,R32_RUNTIME,R32_FILES,
    R31_VIEWER_DATA,r31_overlay_allowed,r32_release_allowed,SUPPORTED_RUNTIMES)


class ViewerDeltaPinTests(unittest.TestCase):
    def test_exact_new_manifest_runtime_and_inventory_are_required(self):
        self.assertIn(R32_RUNTIME,SUPPORTED_RUNTIMES)
        self.assertTrue(r32_release_allowed(R32_RUNTIME,R32_RUNTIME,R32_FILES))
        for declared,actual,count in ((R3_RUNTIME,R32_RUNTIME,R32_FILES),
                (R31_RUNTIME,R32_RUNTIME,R32_FILES),(R32_RUNTIME,R31_RUNTIME,R32_FILES),
                (R32_RUNTIME,'0'*64,R32_FILES),(R32_RUNTIME,R32_RUNTIME,R32_FILES+1)):
            self.assertFalse(r32_release_allowed(declared,actual,count))

    def test_new_manifest_cannot_borrow_historical_overlay_exception(self):
        self.assertFalse(r31_overlay_allowed(R32_RUNTIME,R31_RUNTIME,180,R31_VIEWER_DATA))
        self.assertFalse(r31_overlay_allowed(R3_RUNTIME,R32_RUNTIME,180,R31_VIEWER_DATA))


if __name__=='__main__':unittest.main()
