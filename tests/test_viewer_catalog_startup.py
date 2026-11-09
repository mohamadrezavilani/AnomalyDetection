"""Small catalog upgrades preserve selected services and avoid unchanged writes."""
import unittest

from tests import test_viewer_service_dispatch as dispatch_fixture
from tests.test_viewer_source_catalog import snapshot
from tests.test_viewer_online import verified_file, START, FIVE_NS
from p24_foundation.viewer_online import publish_capture, iso


class CatalogStartupTests(unittest.TestCase):
    setUp = dispatch_fixture.ServiceDispatchTests.setUp
    row = dispatch_fixture.ServiceDispatchTests.row
    provider = dispatch_fixture.ServiceDispatchTests.provider
    flow = dispatch_fixture.ServiceDispatchTests.flow
    publish = dispatch_fixture.ServiceDispatchTests.publish

    def audit_updates(self):
        self.db.sql('CREATE TABLE catalog_test_writes(action_key TEXT NOT NULL)')
        self.db.sql('''CREATE TRIGGER catalog_test_action_update AFTER UPDATE ON viewer_actions
            BEGIN INSERT INTO catalog_test_writes VALUES(NEW.action_key); END''')
        self.db.conn.commit()

    def pending_catalog(self):
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='parent_catalog'")
        self.db.conn.commit()

    def writes(self):
        return [r['action_key'] for r in self.db.all('SELECT action_key FROM catalog_test_writes')]

    def test_catalog_refresh_never_applies_transport_role_to_selected_services(self):
        self.publish(self.flow('otp', '1'*32, 'otp') + self.flow('result', '2'*32, 'result'))
        before = snapshot(self.db)
        self.audit_updates(); self.pending_catalog()
        result = self.db.sync_service_catalog()
        after = snapshot(self.db)
        self.assertEqual(result['changed_actions'], 0)
        self.assertEqual(result['dispatch_requests'], 0)
        self.assertEqual(self.writes(), [])
        for table in before:
            if table != 'viewer_service_catalog_state':
                self.assertEqual(before[table], after[table], table)
        self.assertEqual(self.db.service_catalog_status()['status'], 'CURRENT')

    def test_legacy_transport_overwrite_is_repaired_without_relabeling_otp_attempts(self):
        self.publish(self.flow('otp', '1'*32, 'otp') + self.flow('result', '2'*32, 'result'))
        key = self.db.lookup_request('result')['request_key']
        before = snapshot(self.db)
        self.db.sql("UPDATE viewer_actions SET category='support',initiation='confirmed_automatic' WHERE action_key=?", (key,))
        self.db.conn.commit()
        self.audit_updates(); self.pending_catalog()
        result = self.db.sync_service_catalog()
        self.assertEqual(result['changed_actions'], 0)
        self.assertEqual(result['dispatch_requests'], 1)
        self.assertEqual(self.writes(), [key])
        after = snapshot(self.db)
        for table in before:
            if table != 'viewer_service_catalog_state':
                self.assertEqual(before[table], after[table], table)

    def test_dispatch_repair_failure_rolls_back_the_entire_upgrade(self):
        self.publish(self.flow('result', '2'*32, 'result'))
        key = self.db.lookup_request('result')['request_key']
        self.db.sql("UPDATE viewer_actions SET category='support',initiation='confirmed_automatic' WHERE action_key=?", (key,))
        self.db.conn.commit(); self.pending_catalog()
        before = snapshot(self.db)
        def fail(stage):
            if stage == 'catalog_sync_after_semantics':
                raise RuntimeError('controlled_catalog_dispatch_failure')
        with self.assertRaisesRegex(RuntimeError, 'controlled_catalog_dispatch_failure'):
            self.db.sync_service_catalog(fault=fail)
        self.assertEqual(before, snapshot(self.db))

    def test_widget_change_updates_exact_action_keys_including_noncanonical_legacy_key(self):
        rows = [self.row('widget', 'Core.v1/UserWidgetsSetDefault Line:1', 'POST (G00000 | successful)')]
        rows += [self.row('other_'+str(n), 'Services.v1/WaterBills Line:1', 'POST (G00000 | successful)') for n in range(1200)]
        for n,row in enumerate(rows):
            row['@timestamp'] = iso(START + (n+1)*1000000)
        publish_capture(self.db, verified_file(self.root/'scoped.gz', rows), START, START+FIVE_NS)
        key = self.db.lookup_request('widget')['request_key']
        self.db.sql("UPDATE viewer_service_roles SET role='user_management',source='source_backed',reviewed=0 WHERE service_path='Core.v1/UserWidgetsSetDefault'")
        self.db.sql("UPDATE viewer_actions SET category='user_management' WHERE action_key=?", (key,))
        legacy_key = 'f'*64
        self.db.sql('''INSERT INTO viewer_actions
            SELECT ?,session_key,label,name,category,initiation,at_ns,current_outcome,
                   root_request_key,target_type,target_key,workflow_key,evidence
            FROM viewer_actions WHERE action_key=?''', (legacy_key, key))
        self.db.conn.commit()
        before = snapshot(self.db)
        self.audit_updates(); self.pending_catalog()
        result = self.db.sync_service_catalog()
        self.assertEqual(result['changed_requests'], 1)
        self.assertEqual(result['changed_actions'], 2)
        self.assertEqual(set(self.writes()), {key, legacy_key})
        after = snapshot(self.db)
        for table in ('viewer_events','viewer_raw_events','viewer_requests',
                      'viewer_live_state','viewer_live_receipts',
                      'viewer_contract_identifiers','viewer_contract_edges','viewer_contract_observations'):
            self.assertEqual(before[table], after[table], table)
        self.assertEqual(self.db.one('SELECT category FROM viewer_actions WHERE action_key=?', (legacy_key,))['category'], 'support')

    def test_semantic_only_wallet_refresh_does_not_rewrite_unchanged_actions(self):
        self.publish([self.row('wallet', 'Core.v1/UserWalletCharge Line:1', 'POST (G00000 | successful)')])
        key = self.db.lookup_request('wallet')['request_key']
        before = snapshot(self.db)
        self.audit_updates(); self.pending_catalog()
        result = self.db.sync_service_catalog()
        self.assertEqual(result['changed_requests'], 1)
        self.assertEqual(result['changed_actions'], 0)
        self.assertEqual(self.writes(), [])
        after = snapshot(self.db)
        for table in before:
            if table != 'viewer_service_catalog_state':
                self.assertEqual(before[table], after[table], table)
        self.assertEqual(self.db.one('SELECT kind FROM viewer_semantic_occurrences WHERE request_key=?', (key,))['kind'], 'wallet_funding_execution')


if __name__ == '__main__':
    unittest.main()
