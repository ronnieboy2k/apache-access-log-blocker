from datetime import datetime
from apache_access_log_blocker.log_grouper import group_logs_by_contiguous_seconds


def test_group_logs_by_contiguous_seconds_filters_request_method():
    logs = [
        {
            "request_method": "GET",
            "request_dt": datetime(2026, 8, 31, 22, 0, 0),
        },
        {
            "request_method": "POST",
            "request_dt": datetime(2026, 8, 31, 22, 0, 1),
        },
        {
            "request_method": "GET",
            "request_dt": datetime(2026, 8, 31, 22, 0, 1),
        },
    ]

    result = group_logs_by_contiguous_seconds(logs)

    assert len(result) == 1
    assert len(result[0]) == 2


def test_group_logs_by_contiguous_seconds_with_post_method():
    logs = [
        {
            "request_method": "POST",
            "request_dt": datetime(2026, 8, 31, 22, 0, 0),
        },
        {
            "request_method": "POST",
            "request_dt": datetime(2026, 8, 31, 22, 0, 1),
        },
        {
            "request_method": "GET",
            "request_dt": datetime(2026, 8, 31, 22, 0, 2),
        },
    ]

    result = group_logs_by_contiguous_seconds(logs, request_method="post")

    assert len(result) == 1
    assert len(result[0]) == 2
