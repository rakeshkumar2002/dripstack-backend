from dripstack.shared.jsonpath import get_by_path, path_exists

sample = {
    "technician": {"email": "tech@example.com", "name": "Alex"},
    "error": {"status": 409, "code": "OBJECT_OVERRIDDEN", "tags": ["write", "priority"]},
    "weird key": {"nested": True},
}


def test_resolves_dot_paths_with_and_without_leading_dollar():
    assert get_by_path(sample, "$.technician.email") == "tech@example.com"
    assert get_by_path(sample, "error.status") == 409


def test_resolves_array_indices_and_bracket_keys():
    assert get_by_path(sample, "$.error.tags[0]") == "write"
    assert get_by_path(sample, '$["weird key"].nested') is True


def test_returns_none_for_missing_paths():
    assert get_by_path(sample, "$.error.missing") is None
    assert get_by_path(sample, "$.a.b.c.d") is None


def test_path_exists_distinguishes_present_vs_absent():
    assert path_exists(sample, "$.error.code") is True
    assert path_exists(sample, "$.error.nope") is False
