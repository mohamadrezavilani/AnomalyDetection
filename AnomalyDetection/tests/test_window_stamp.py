"""A reader restarts for relevant evidence, never unrelated publication churn."""
import unittest
from anomaly_detection.window_stamp import stamp,CONTRACT


class WindowStampTests(unittest.TestCase):
    def test_only_relevant_epoch_maintenance_catalog_or_receipt_changes_restart(self):
        window={'start_ns':1,'end_ns':2,'generation':3,'last_publish_ns':4}
        meta={'generation':10,'semantic_generation':10,'catalog_fingerprint':'catalog',
              'window_epoch_contract':{'contract':CONTRACT,'maintenance_epoch':0}}
        version=7
        def q(*args,**kwargs):return [{'revision':version}]
        original=stamp(q,meta,window)
        meta.update(generation=1000,semantic_generation=1000)
        self.assertEqual(stamp(q,meta,window),original)
        version=8;self.assertNotEqual(stamp(q,meta,window),original);version=7
        meta['window_epoch_contract']['maintenance_epoch']=1
        self.assertNotEqual(stamp(q,meta,window),original)
        meta['window_epoch_contract']['maintenance_epoch']=0;meta['catalog_fingerprint']='changed'
        self.assertNotEqual(stamp(q,meta,window),original)
        meta['catalog_fingerprint']='catalog';window['generation']=4
        self.assertNotEqual(stamp(q,meta,window),original)

    def test_legacy_source_keeps_global_fence(self):
        meta={'generation':1,'semantic_generation':1,'catalog_fingerprint':'catalog'}
        def no_query(*args,**kwargs):raise AssertionError('legacy source has no epoch table')
        first=stamp(no_query,meta,{'start_ns':1})
        meta.update(generation=2,semantic_generation=2)
        self.assertNotEqual(stamp(no_query,meta,{'start_ns':1}),first)


if __name__=='__main__':unittest.main()
