"""Source-scoped reconciliation of request, route, and outcome candidates.

This is an evidence alignment view only. It does not assign service meaning,
causality, execution, finality, or authoritative code semantics.
"""
from __future__ import annotations

EVIDENCE_MATRIX_VERSION = "p24-evidence-matrix-candidate.1"


def _source_index(document, key):
    result = {}
    for source in document.get("sources", []):
        identity = source.get(key)
        digest = source.get("source_sha256")
        if not isinstance(identity, str) or not isinstance(digest, str):
            continue
        result[(identity, digest)] = source
    return result


def _contexts(group):
    for context in group.get("same_request_contexts", []):
        endpoints = context.get("client_http_endpoints", [])
        actions = context.get("access_check_actions", [])
        count = context.get("distinct_request_count")
        if (isinstance(count, int) and not isinstance(count, bool)
                and len(endpoints) == 1 and len(actions) == 1):
            yield endpoints[0], actions[0], count


def build_evidence_matrix(request_chains, action_api, error_operations):
    """Align catalogs only where source name/hash and exact endpoint/action agree.

    Counts remain local to each source capture. Error observation counts are
    retained as reported per group and must not be summed across layers.
    """
    chains_by_source = _source_index(request_chains, "locator")
    api_by_source = _source_index(action_api, "source")
    errors_by_source = _source_index(error_operations, "locator")
    sources = []
    for key in sorted(set(chains_by_source) | set(api_by_source) | set(errors_by_source)):
        chain_source = chains_by_source.get(key)
        api_source = api_by_source.get(key)
        error_source = errors_by_source.get(key)
        pair_map = {}
        if api_source:
            for pair in api_source.get("pairs", []):
                endpoint, action = pair.get("client_http_endpoint"), pair.get("access_check_action")
                if isinstance(endpoint, str) and isinstance(action, str):
                    pair_map[(endpoint, action)] = pair

        chain_counts = {}
        if chain_source:
            for chain in chain_source.get("chains", []):
                endpoint = chain.get("client_http_endpoint")
                actions = {item.get("value") for item in chain.get("observed_access_check_actions", [])
                           if isinstance(item.get("value"), str)}
                if endpoint and len(actions) == 1 and chain.get("client_http_completion_state") == "observed":
                    pair = (endpoint, next(iter(actions)))
                    chain_counts[pair] = chain_counts.get(pair, 0) + 1

        error_map = {}
        ambiguous_error_contexts = 0
        unpaired_error_observations = []
        if error_source:
            for group in error_source.get("groups", []):
                contexts = group.get("same_request_contexts", [])
                if not contexts or all(not context.get("client_http_endpoints")
                                        or not context.get("access_check_actions") for context in contexts):
                    unpaired_error_observations.append({
                        "operation_role": group.get("operation_role", "unknown"),
                        "operation_callpath": group.get("operation_callpath"),
                        "code": group.get("code"),
                        "evidence_layer": group.get("evidence_layer", "unknown"),
                        "recorded_outcome": group.get("recorded_outcome", "unknown"),
                        "recorded_symbol": group.get("recorded_symbol"),
                        "observed_event_count": group.get("observed_event_count", 0),
                        "distinct_request_count": group.get("distinct_request_count", 0),
                        "codebook_candidate_state": group.get("codebook_candidate_state", "unknown"),
                        "codebook_candidates": group.get("codebook_candidates", []),
                        "semantic_authority": group.get("semantic_authority", "unverified_candidate"),
                        "operation_binding_proven": group.get("operation_binding_proven", "no"),
                        "link_state": "no_client_endpoint_action_context_observed",
                    })
                ambiguous_error_contexts += sum(
                    1 for context in contexts
                    if (context.get("client_http_endpoints") or context.get("access_check_actions"))
                    and (len(context.get("client_http_endpoints", [])) != 1
                         or len(context.get("access_check_actions", [])) != 1)
                )
                for endpoint, action, context_count in _contexts(group):
                    pair = (endpoint, action)
                    row = {
                        "operation_role": group.get("operation_role", "unknown"),
                        "operation_callpath": group.get("operation_callpath"),
                        "code": group.get("code"),
                        "evidence_layer": group.get("evidence_layer", "unknown"),
                        "recorded_outcome": group.get("recorded_outcome", "unknown"),
                        "recorded_symbol": group.get("recorded_symbol"),
                        "observed_event_count": group.get("observed_event_count", 0),
                        "group_distinct_request_count": group.get("distinct_request_count", 0),
                        "context_distinct_request_count": context_count,
                        "codebook_candidate_state": group.get("codebook_candidate_state", "unknown"),
                        "codebook_candidates": group.get("codebook_candidates", []),
                        "semantic_authority": group.get("semantic_authority", "unverified_candidate"),
                        "operation_binding_proven": group.get("operation_binding_proven", "no"),
                        "link_basis": "same_request_co_observation_candidate",
                    }
                    error_map.setdefault(pair, []).append(row)

        all_pairs = sorted(set(pair_map) | set(error_map) | set(chain_counts))
        rows = []
        for endpoint, action in all_pairs:
            api_pair = pair_map.get((endpoint, action))
            postman = api_pair.get("postman_candidates", []) if api_pair else []
            postman_states = sorted({row.get("postman_candidate_state", "unknown") for row in postman})
            # Exact route strings and versions remain as supplied; name similarity
            # is retained as a candidate and never upgraded to an exact mapping.
            rows.append({
                "client_http_endpoint": endpoint,
                "access_check_action": action,
                "observed_chain_request_count": chain_counts.get((endpoint, action), 0),
                "crosswalk_request_count": api_pair.get("distinct_client_http_requests") if api_pair else None,
                "chain_crosswalk_count_relation": (
                    "equal_in_this_capture" if api_pair and chain_counts.get((endpoint, action), 0) ==
                    api_pair.get("distinct_client_http_requests") else
                    "different_or_unavailable" if api_pair else "not_crosswalked"
                ),
                "endpoint_action_relation": api_pair.get("endpoint_action_relation") if api_pair else "not_crosswalked",
                "api_candidate_state": api_pair.get("postman_candidate_state") if api_pair else "not_compared",
                "api_route_candidates": postman,
                "api_candidate_states": postman_states,
                "outcome_observations": sorted(error_map.get((endpoint, action), []), key=lambda row: (
                    row["operation_role"], row["operation_callpath"] or "", row["evidence_layer"],
                    row["code"] or "", row["recorded_outcome"])),
                "semantic_classification": "unresolved",
                "execution_or_causality_proven": False,
            })
        sources.append({
            "source": key[0],
            "source_sha256": key[1],
            "request_chain_catalog_present": chain_source is not None,
            "api_reconciliation_catalog_present": api_source is not None,
            "error_operation_catalog_present": error_source is not None,
            "request_projection_count": chain_source.get("request_projection_count") if chain_source else None,
            "capture_coverage": chain_source.get("coverage") if chain_source else None,
            "capture_finality": chain_source.get("capture_finality") if chain_source else "not_available",
            "ambiguous_outcome_context_count": ambiguous_error_contexts,
            "unpaired_outcome_observations": sorted(unpaired_error_observations, key=lambda row: (
                row["operation_role"], row["operation_callpath"] or "", row["evidence_layer"], row["code"] or "")),
            "route_outcome_pairs": rows,
            "pair_count": len(rows),
            "cross_source_counts_must_not_be_summed": True,
        })
    return {
        "version": EVIDENCE_MATRIX_VERSION,
        "status": "unpublished_source_scoped_evidence_candidates",
        "interpretation": "exact-source-and-context alignment of independently derived candidates",
        "source_join_basis": "same_locator_and_source_sha256",
        "context_join_basis": "exact_client_endpoint_and_exact_access_action",
        "counts_across_layers_must_not_be_summed": True,
        "business_service_ownership_authoritative": False,
        "response_semantics_authoritative": False,
        "causality_execution_or_workflow_finality_proven": False,
        "sources": sources,
    }
