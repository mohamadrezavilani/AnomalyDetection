import unittest
from compact_behavior import FIVE
from compact_behavior.extract import materialize, iso
from compact_ad.engine import summarize, evaluate
from tests.test_compact_extract import row, extract, T


def behavior(
    key,
    session,
    *,
    amount=10,
    code="G00000",
    target=None,
    shape=False,
    broken=False,
    api="Services.v1/WaterBills",
    start=T
):
    records = [
        row(
            key,
            session,
            path=api,
            message="POST https://example.test/test HTTP/1.1 ("
            + code
            + " | "
            + ("successful" if code == "G00000" else "other")
            + ")",
            at=iso(start + 10**9),
        ),
        row(
            key,
            session,
            path=api,
            message='Input:{"Identifier":"'
            + str(target or key)
            + '"} Output:'
            + ('{"new_field":10}' if shape else '{"Amount":' + str(amount) + "}"),
            at=iso(start + 10**9),
        ),
    ]
    if broken:
        records.append(
            row(key, session, path=api, message="Output:[broken", at=iso(start + 10**9))
        )
    b = materialize("test", extract(records)[key])
    b["kind"] = "observed_api_operation"
    return b


def window(start=T, *, n=20, actor_size=2, **kw):
    rows = [
        behavior(str(i), "s" + str(i // actor_size), start=start, **kw)
        for i in range(n)
    ]
    return summarize(rows)


def reference():
    return [
        dict(start_ns=T + i * FIVE, summary=window(T + i * FIVE)[0]) for i in range(12)
    ]


class CompactADTests(unittest.TestCase):
    def test_owner_confirmed_auxiliary_roots_do_not_enter_user_models(self):
        from compact_behavior.services import independent_operations,operation_role
        auxiliary=[p for p in independent_operations() if operation_role(p) in ('system','support')]
        rows=[behavior(str(i),'s'+str(i),api=p) for i,p in enumerate(auxiliary)]
        self.assertEqual(summarize(rows),summarize([]))
        user_paths=[p for p in independent_operations() if operation_role(p) in ('business','user_management')]
        summary,services,actors=summarize([behavior(str(i),'s'+str(i),api=p) for i,p in enumerate(user_paths)])
        self.assertEqual(set(services),set(user_paths))
        self.assertEqual(len(actors),len(user_paths))

    def test_two_independent_inquiry_patterns(self):
        from compact_product.cases import select_cases
        def classify(targets, *, failed=False, heavy_peers=False):
            rows = [behavior('req'+str(i),'actor',target=t,
                             code='GR0010' if failed and i==0 else 'G00000') for i,t in enumerate(targets)]
            for n in range(21):
                for i in range(16 if heavy_peers else 1):
                    rows.append(behavior(f'p{n}-{i}',f'peer{n}',target='same'))
            summary, services, actors = summarize(rows)
            findings = [dict(method=r['method'], result=r, service=r['service'], session_id=r['session_id'],
                             start_ns=T, finding_id=r['method']) for r in evaluate(T,summary,services,actors,[])
                        if r['session_id']=='actor' and (r.get('inquiry_pattern_policy') or r.get('inquiry_breadth_policy')) and r['status']=='ANOMALY']
            return [r for case in select_cases(findings) for r in case['findings']]
        concentrated = ['a']*10+['b']*8+['c']*7+['d']*5
        repeat, = classify(concentrated)
        self.assertEqual(repeat['method'],'repeated_target')
        self.assertEqual([repeat['result'][k] for k in ('distinct_targets','most_frequent_count','peer_mean_requests')],[4,10,1])
        broad, = classify(['id'+str(n) for n in range(12)])
        self.assertEqual(broad['method'],'target_diversity')
        self.assertEqual(classify(concentrated,failed=True),[])
        self.assertEqual(classify(concentrated,heavy_peers=True),[])
        self.assertEqual(classify(concentrated[:8]),[])

    def result(self, method, **kw):
        summary, services, actors = window(T + 12 * FIVE, **kw)
        return [
            r
            for r in evaluate(T + 12 * FIVE, summary, services, actors, reference())
            if r["method"] == method
        ]

    def test_normal_and_insufficient_are_distinct(self):
        for method in [
            "service_rate",
            "actor_rate",
            "reported_result",
            "response_shape",
            "response_numeric",
            "repeated_target",
            "target_diversity",
        ]:
            self.assertTrue(
                all(r["status"] == "NORMAL" for r in self.result(method)), method
            )
        s, a, b = window()
        r = evaluate(T, s, a, b, [])
        self.assertEqual({v["status"] for v in r}, {"INSUFFICIENT_DATA"})

    def test_rate_spike_and_peer_actor_spike(self):
        self.assertEqual(self.result("service_rate", n=100)[0]["status"], "ANOMALY")
        self.assertTrue(
            any(
                r["status"] == "ANOMALY"
                for r in self.result("actor_rate", n=50, actor_size=50)
            )
        )

    def test_target_repeat_and_diversity_are_request_based(self):
        self.assertTrue(
            any(
                r["status"] == "ANOMALY"
                for r in self.result(
                    "repeated_target", n=50, actor_size=50, target="same"
                )
            )
        )
        self.assertTrue(
            any(
                r["status"] == "ANOMALY"
                for r in self.result("target_diversity", n=50, actor_size=50)
            )
        )

    def test_response_shape_numeric_and_reported_result_change(self):
        for method, kw in [
            ("response_shape", dict(shape=True)),
            ("response_numeric", dict(amount=1000)),
            ("reported_result", dict(code="F99999")),
        ]:
            self.assertEqual(self.result(method, **kw)[0]["status"], "ANOMALY")

    def test_invalid_output_cannot_suppress_valid_rate(self):
        self.assertEqual(
            self.result("response_shape", broken=True)[0]["status"], "INVALID_INPUT"
        )
        self.assertEqual(
            self.result("service_rate", broken=True)[0]["status"], "NORMAL"
        )

    def test_service_mix_normal_and_new_rare_service(self):
        self.assertEqual(
            self.result("service_mix", n=20, actor_size=20)[0]["status"], "NORMAL"
        )
        self.assertEqual(
            self.result("service_mix", n=20, actor_size=20, api="Services.v1/GasBills")[
                0
            ]["status"],
            "ANOMALY",
        )

    def test_unassigned_session_is_partial_actor_coverage_not_all_healthy(self):
        rows = [behavior(str(i), "s0") for i in range(20)] + [
            behavior("missing", "N/A")
        ]
        summary, services, actors = summarize(rows)
        results = evaluate(T + 12 * FIVE, summary, services, actors, reference())
        self.assertEqual(
            next(r for r in results if r["method"] == "service_rate")["status"],
            "NORMAL",
        )
        self.assertTrue(
            any(
                r["method"] == "actor_rate" and r["status"] == "INVALID_INPUT"
                for r in results
            )
        )

    def test_unverified_execution_time_is_not_a_response_numeric_model(self):
        b = behavior("a", "s")
        b["features"]["output"]["numeric"]["ExecutionTime"] = {"mean": 5000, "count": 1}
        summary, services, actors = summarize([b])
        self.assertNotIn("ExecutionTime", services[b["service_key"]]["numeric"])

    def test_future_reference_is_rejected_by_cutoff(self):
        s, a, b = window(T + 12 * FIVE, n=100)
        refs = reference()
        before = evaluate(T + 12 * FIVE, s, a, b, refs)
        refs.append(dict(start_ns=T + 13 * FIVE, summary=window(n=10000)[0]))
        self.assertEqual(before, evaluate(T + 12 * FIVE, s, a, b, refs))
        self.assertTrue(all(r['reference_cutoff_ns'] is None and r['reference_windows']==0
                            or r['reference_cutoff_ns'] <= T + 12 * FIVE for r in before))

    def test_old_feature_version_is_invalid_not_healthy(self):
        b = behavior("r", "s")
        b["features"]["version"] = "compact-features-1"
        s, a, c = summarize([b])
        results = evaluate(T + 12 * FIVE, s, a, c, reference())
        self.assertEqual({r["status"] for r in results}, {"INVALID_INPUT"})

    def test_future_content_is_not_used_in_past_window(self):
        b = behavior("a", "s")
        b["features"]["output_asof_ns"] = T + FIVE + 1
        s, a, c = summarize([b], cutoff_ns=T + FIVE)
        results = evaluate(T, s, a, c, [])
        self.assertEqual(
            next(r for r in results if r["method"] == "response_shape")["status"],
            "INVALID_INPUT",
        )
        self.assertEqual(
            next(r for r in results if r["method"] == "service_rate")["status"],
            "INSUFFICIENT_DATA",
        )

    def test_resource_limit_invalidates_content_without_truncating_rate(self):
        s, a, c = summarize(
            [behavior("a", "s"), behavior("b", "s")], max_feature_bytes=1
        )
        results = evaluate(T + 12 * FIVE, s, a, c, reference())
        self.assertEqual(
            next(r for r in results if r["method"] == "service_rate")["status"],
            "NORMAL",
        )
        self.assertEqual(
            next(r for r in results if r["method"] == "response_shape")["status"],
            "INVALID_INPUT",
        )


if __name__ == "__main__":
    unittest.main()
