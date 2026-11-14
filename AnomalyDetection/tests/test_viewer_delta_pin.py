"""R3.2 is an exact release pin; historical overlays cannot admit mixed trees."""
import unittest
from anomaly_detection.source_profiles import (R3_RUNTIME,R31_RUNTIME,R32_RUNTIME,R32_FILES,
    R31_VIEWER_DATA,r31_overlay_allowed,r32_release_allowed,SUPPORTED_RUNTIMES,
    R33_RUNTIME,R33_FILES,r33_release_allowed,R34_RUNTIME,R34_FILES,r34_release_allowed,
    R35_RUNTIME,R35_FILES,r35_release_allowed,R36_RUNTIME,R36_FILES,r36_release_allowed)


class ViewerDeltaPinTests(unittest.TestCase):
    def test_binary_origin_runtime_requires_exact_manifest_source_and_inventory(self):
        self.assertIn(R36_RUNTIME,SUPPORTED_RUNTIMES)
        self.assertTrue(r36_release_allowed(R36_RUNTIME,R36_RUNTIME,R36_FILES))
        for declared,actual,count in ((R35_RUNTIME,R36_RUNTIME,R36_FILES),
                (R36_RUNTIME,R35_RUNTIME,R36_FILES),(R36_RUNTIME,'0'*64,R36_FILES),
                (R36_RUNTIME,R36_RUNTIME,R36_FILES-1),(R36_RUNTIME,R36_RUNTIME,R36_FILES+1)):
            self.assertFalse(r36_release_allowed(declared,actual,count))

    def test_compact_storage_runtime_rejects_mixed_trees(self):
        self.assertIn(R35_RUNTIME,SUPPORTED_RUNTIMES)
        self.assertTrue(r35_release_allowed(R35_RUNTIME,R35_RUNTIME,R35_FILES))
        self.assertFalse(r35_release_allowed(R34_RUNTIME,R35_RUNTIME,R35_FILES))
        self.assertFalse(r35_release_allowed(R35_RUNTIME,R34_RUNTIME,R35_FILES))
        self.assertFalse(r35_release_allowed(R35_RUNTIME,R35_RUNTIME,R35_FILES-1))

    def test_lan_runtime_has_its_own_exact_manifest_and_file_count(self):
        self.assertIn(R34_RUNTIME,SUPPORTED_RUNTIMES)
        self.assertTrue(r34_release_allowed(R34_RUNTIME,R34_RUNTIME,R34_FILES))
        self.assertFalse(r34_release_allowed(R33_RUNTIME,R34_RUNTIME,R34_FILES))
        self.assertFalse(r34_release_allowed(R34_RUNTIME,R33_RUNTIME,R34_FILES))
        self.assertFalse(r34_release_allowed(R34_RUNTIME,R34_RUNTIME,R34_FILES+1))
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

    def test_scoped_input_release_requires_its_own_exact_bytes(self):
        self.assertTrue(r33_release_allowed(R33_RUNTIME,R33_RUNTIME,R33_FILES))
        self.assertIn(R33_RUNTIME,SUPPORTED_RUNTIMES)
        self.assertFalse(r33_release_allowed(R32_RUNTIME,R33_RUNTIME,R33_FILES))
        self.assertFalse(r33_release_allowed(R33_RUNTIME,R32_RUNTIME,R33_FILES))
        self.assertFalse(r33_release_allowed(R33_RUNTIME,R33_RUNTIME,R33_FILES+1))


if __name__=='__main__':unittest.main()
