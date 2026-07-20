"""
ShadowSensor Phase 5 — Process-window feature aggregator.

Merges per-event 30-feature vectors for a single process window into one
30-feature output vector.
"""
from __future__ import annotations

from ml.features.feature_spec import FEATURE_REGISTRY, default_feature_vector


_SUM_FEATURES = (
    "image_load_count",
    "create_remote_thread_count",
    "open_process_count",
    "network_event_count",
)

_OR_FEATURES = (
    "has_encoded_command",
    "has_download_keyword",
    "unsigned_image_loaded",
    "open_process_lsass_target",
    "open_process_suspicious_access",
    "is_known_suspicious_chain",
    "is_lolbin",
    "is_suspicious_parent",
    "parent_is_same_image",
)

_FIRST_EVENT_FEATURES = (
    "cmd_length",
    "cmd_entropy",
    "is_signed",
    "hour_of_day",
    "is_off_hours",
    "parent_cmd_length",
    "dest_port",
    "is_suspicious_port",
    "is_external_ip",
    "dns_query_length",
)

_FIRST_EVENT_SOURCE_EIDS = {
    feature.name: feature.source_eids
    for feature in FEATURE_REGISTRY
    if feature.name in _FIRST_EVENT_FEATURES
}


class ProcessWindowAggregator:
    """Aggregate event vectors and rule hits for one process window."""

    def aggregate(
        self,
        event_vectors: list[tuple[int, dict]],
        rule_hits: list[dict],
    ) -> dict:
        output = default_feature_vector()

        for feature in _SUM_FEATURES:
            output[feature] = sum(
                int(vector.get(feature, 0))
                for _, vector in event_vectors
            )

        for feature in _OR_FEATURES:
            output[feature] = 1 if any(
                int(vector.get(feature, 0)) == 1
                for _, vector in event_vectors
            ) else 0

        for feature in _FIRST_EVENT_FEATURES:
            source_eids = _FIRST_EVENT_SOURCE_EIDS[feature]
            for event_type_id, vector in event_vectors:
                if event_type_id in source_eids:
                    output[feature] = vector.get(feature, output[feature])
                    break

        output["rule_hit_count"] = len(rule_hits)
        output["unique_rules_fired"] = len(
            {
                rh.get("rule_id")
                for rh in rule_hits
                if rh.get("rule_id")
            }
        )
        output["has_powershell_rule_hit"] = 1 if any(
            (rh.get("rule_id") or "").startswith("PS_")
            for rh in rule_hits
        ) else 0
        output["has_lolbin_rule_hit"] = 1 if any(
            (rh.get("rule_id") or "").startswith("LOLBIN_")
            for rh in rule_hits
        ) else 0
        output["has_network_rule_hit"] = 1 if any(
            (rh.get("rule_id") or "").startswith("NET_")
            for rh in rule_hits
        ) else 0
        output["has_api_rule_hit"] = 1 if any(
            (rh.get("rule_id") or "").startswith("API_")
            for rh in rule_hits
        ) else 0
        output["has_chain_rule_hit"] = 1 if any(
            (rh.get("rule_id") or "").startswith("CHAIN_")
            for rh in rule_hits
        ) else 0

        return output
