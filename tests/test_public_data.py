import pytest

from agents.public_data import analyze, run


def test_join_preserves_all_types_and_reports_unmatched():
    notifications = [
        {"id": "42", "name": "Example", "databreachcause": "Cyberattack"},
        {"id": "43", "name": "Other"},
    ]
    details = [
        {"id": "42", "informationtype": "Name"},
        {"id": "42", "informationtype": "Financial"},
        {"id": "42", "informationtype": "Name"},
        {"id": "99", "informationtype": "Other"},
    ]
    result = analyze(notifications, details, requested=2)
    assert result["records"][0]["information_types"] == ["Financial", "Name"]
    assert result["information_type_counts"] == {"Financial": 1, "Name": 1}
    assert result["notifications_with_details"] == 1
    assert result["notifications_without_details"] == 1
    assert result["unmatched_detail_rows"] == 1
    assert result["sample_limited"] is True
    assert result["mode"] == "historical_read_only"


def test_rejects_duplicate_and_invalid_ids():
    with pytest.raises(ValueError):
        analyze([{"id": "1"}, {"id": "1"}], [], requested=2)
    with pytest.raises(ValueError):
        analyze([{"id": "1') OR true"}], [], requested=1)


def test_limit_bounds():
    with pytest.raises(ValueError):
        run(101)
