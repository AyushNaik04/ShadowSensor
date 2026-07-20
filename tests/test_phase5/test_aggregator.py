"""Tests for Phase 5 process-window feature aggregator."""

from __future__ import annotations

from ml.features.aggregator import ProcessWindowAggregator
from ml.features.feature_spec import FEATURE_NAMES, default_feature_vector


def _vec(**updates) -> dict:
    vector = default_feature_vector()
    vector.update(updates)
    return vector


def _rh(rule_id: str | None, rule_name: str = "rule") -> dict:
    return {"rule_id": rule_id, "rule_name": rule_name}


def test_empty_event_vectors_returns_defaults():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [])
    assert result == default_feature_vector()


def test_sum_merge_image_load_count():
    agg = ProcessWindowAggregator()
    events = [
        (7, _vec(image_load_count=1)),
        (7, _vec(image_load_count=1)),
        (7, _vec(image_load_count=1)),
    ]
    result = agg.aggregate(events, [])
    assert result["image_load_count"] == 3


def test_sum_merge_network_event_count():
    agg = ProcessWindowAggregator()
    events = [
        (3, _vec(network_event_count=1)),
        (3, _vec(network_event_count=1)),
        (22, _vec(network_event_count=1)),
    ]
    result = agg.aggregate(events, [])
    assert result["network_event_count"] == 3


def test_or_merge_unsigned_image():
    agg = ProcessWindowAggregator()
    events = [
        (7, _vec(unsigned_image_loaded=0)),
        (7, _vec(unsigned_image_loaded=1)),
    ]
    result = agg.aggregate(events, [])
    assert result["unsigned_image_loaded"] == 1


def test_or_merge_all_zero():
    agg = ProcessWindowAggregator()
    events = [(1, _vec()), (7, _vec()), (10, _vec())]
    result = agg.aggregate(events, [])
    assert result["has_encoded_command"] == 0
    assert result["has_download_keyword"] == 0
    assert result["unsigned_image_loaded"] == 0
    assert result["open_process_lsass_target"] == 0
    assert result["open_process_suspicious_access"] == 0
    assert result["is_known_suspicious_chain"] == 0
    assert result["is_lolbin"] == 0
    assert result["is_suspicious_parent"] == 0
    assert result["parent_is_same_image"] == 0


def test_or_merge_is_lolbin():
    agg = ProcessWindowAggregator()
    events = [(1, _vec(is_lolbin=0)), (1, _vec(is_lolbin=1))]
    result = agg.aggregate(events, [])
    assert result["is_lolbin"] == 1


def test_first_event_cmd_length():
    agg = ProcessWindowAggregator()
    events = [
        (1, _vec(cmd_length=12)),
        (1, _vec(cmd_length=99)),
    ]
    result = agg.aggregate(events, [])
    assert result["cmd_length"] == 12


def test_first_event_hour_of_day():
    agg = ProcessWindowAggregator()
    events = [
        (1, _vec(hour_of_day=9)),
        (1, _vec(hour_of_day=21)),
    ]
    result = agg.aggregate(events, [])
    assert result["hour_of_day"] == 9


def test_rule_hit_count():
    agg = ProcessWindowAggregator()
    hits = [_rh(f"PS_RULE_{i:03d}") for i in range(5)]
    result = agg.aggregate([], hits)
    assert result["rule_hit_count"] == 5


def test_unique_rules_fired():
    agg = ProcessWindowAggregator()
    hits = [
        _rh("PS_ENCODED_CMD_001"),
        _rh("PS_ENCODED_CMD_001"),
        _rh("LOLBIN_MSHTA_001"),
    ]
    result = agg.aggregate([], hits)
    assert result["unique_rules_fired"] == 2


def test_has_powershell_rule_hit_true():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [_rh("PS_ENCODED_CMD_001")])
    assert result["has_powershell_rule_hit"] == 1


def test_has_lolbin_rule_hit_true():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [_rh("LOLBIN_MSHTA_001")])
    assert result["has_lolbin_rule_hit"] == 1


def test_has_network_rule_hit_true():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [_rh("NET_DNS_LONG_QUERY_001")])
    assert result["has_network_rule_hit"] == 1


def test_has_api_rule_hit_true():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [_rh("API_AV_PROCESS_ACCESS_001")])
    assert result["has_api_rule_hit"] == 1


def test_has_chain_rule_hit_true():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [_rh("CHAIN_SCHEDULED_TASK_SVCHOST_001")])
    assert result["has_chain_rule_hit"] == 1


def test_empty_rule_hits_gives_zero_rule_features():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [])
    assert result["rule_hit_count"] == 0
    assert result["unique_rules_fired"] == 0
    assert result["has_powershell_rule_hit"] == 0
    assert result["has_lolbin_rule_hit"] == 0
    assert result["has_network_rule_hit"] == 0
    assert result["has_api_rule_hit"] == 0
    assert result["has_chain_rule_hit"] == 0


def test_result_has_exactly_30_keys():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [])
    assert len(result) == 30


def test_result_keys_match_feature_names():
    agg = ProcessWindowAggregator()
    result = agg.aggregate([], [])
    assert set(result.keys()) == set(FEATURE_NAMES)


def test_mixed_eid_window():
    agg = ProcessWindowAggregator()
    events = [
        (1, _vec(cmd_length=15, is_lolbin=1, has_encoded_command=1)),
        (3, _vec(network_event_count=1, dest_port=4444, is_suspicious_port=1)),
        (7, _vec(image_load_count=1, unsigned_image_loaded=1)),
    ]
    hits = [_rh("PS_ENCODED_CMD_001"), _rh("LOLBIN_MSHTA_001")]
    result = agg.aggregate(events, hits)
    assert len(result) == 30
    assert result["image_load_count"] == 1
    assert result["network_event_count"] == 1
    assert result["is_lolbin"] == 1
    assert result["has_encoded_command"] == 1
    assert result["unsigned_image_loaded"] == 1
    assert result["rule_hit_count"] == 2
    assert result["has_powershell_rule_hit"] == 1
    assert result["has_lolbin_rule_hit"] == 1


def test_is_known_suspicious_chain_or_merge():
    agg = ProcessWindowAggregator()
    events = [
        (1, _vec(is_known_suspicious_chain=0)),
        (1, _vec(is_known_suspicious_chain=1)),
    ]
    result = agg.aggregate(events, [])
    assert result["is_known_suspicious_chain"] == 1


def test_prefix_check_uses_rule_id_not_rule_name():
    agg = ProcessWindowAggregator()
    hits = [
        _rh("CUSTOM_999", "PS test rule"),
        _rh(None, "LOLBIN misleading name"),
    ]
    result = agg.aggregate([], hits)
    assert result["has_powershell_rule_hit"] == 0
    assert result["has_lolbin_rule_hit"] == 0
    assert result["has_network_rule_hit"] == 0
    assert result["has_api_rule_hit"] == 0
    assert result["has_chain_rule_hit"] == 0


def test_first_event_scoped_by_eid_not_by_nondefault_value():
    agg = ProcessWindowAggregator()
    events = [
        (1, _vec(is_off_hours=0)),
        (1, _vec(is_off_hours=1)),
    ]
    result = agg.aggregate(events, [])
    assert result["is_off_hours"] == 0
