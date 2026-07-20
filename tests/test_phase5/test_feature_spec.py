"""Tests for Phase 5 feature specification registry and constants."""

from ml.features.feature_spec import (
    FEATURE_NAMES,
    FEATURE_REGISTRY,
    LOLBIN_NAMES,
    SUSPICIOUS_CHAINS,
    SUSPICIOUS_PARENT_IMAGES,
    SUSPICIOUS_PORTS,
    default_feature_vector,
)


def test_registry_has_30_features():
    assert len(FEATURE_REGISTRY) == 30


def test_feature_names_are_unique():
    names = [f.name for f in FEATURE_REGISTRY]
    assert len(names) == len(set(names))


def test_feature_names_match_feature_names_list():
    assert FEATURE_NAMES == [f.name for f in FEATURE_REGISTRY]


def test_default_vector_has_all_30_keys():
    vector = default_feature_vector()
    assert len(vector) == 30
    assert set(vector.keys()) == set(FEATURE_NAMES)


def test_default_vector_dtypes():
    vector = default_feature_vector()
    by_name = {f.name: f for f in FEATURE_REGISTRY}
    for name, value in vector.items():
        assert isinstance(value, by_name[name].dtype)


def test_lolbin_names_nonempty():
    assert len(LOLBIN_NAMES) > 0


def test_suspicious_parent_images_nonempty():
    assert len(SUSPICIOUS_PARENT_IMAGES) > 0


def test_suspicious_chains_nonempty():
    assert len(SUSPICIOUS_CHAINS) > 0


def test_suspicious_ports_nonempty():
    assert len(SUSPICIOUS_PORTS) > 0


def test_all_chain_members_are_lowercase():
    for parent, child in SUSPICIOUS_CHAINS:
        assert parent == parent.lower()
        assert child == child.lower()


def test_lolbin_names_are_lowercase():
    for name in LOLBIN_NAMES:
        assert name == name.lower()


def test_suspicious_parent_images_are_lowercase():
    for name in SUSPICIOUS_PARENT_IMAGES:
        assert name == name.lower()
