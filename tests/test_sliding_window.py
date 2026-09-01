from datetime import datetime
from apache_access_log_blocker.sliding_window import (
    create_sliding_detection_windows,
)


def test_create_sliding_detection_windows():
    logs = [
        [
            {
                "request_dt_str": "31/Aug/2026:22:00:00 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 0),
                "remote_addr": "127.0.0.1",
            },
            {
                "request_dt_str": "31/Aug/2026:22:00:01 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 1),
                "remote_addr": "127.0.0.1",
            },
            {
                "request_dt_str": "31/Aug/2026:22:00:02 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 2),
                "remote_addr": "127.0.0.1",
            },
        ]
    ]

    result = create_sliding_detection_windows(
        logs,
        request_threshold=2,
        detection_window=2,
    )

    assert len(result) == 3

    assert (
        "31/Aug/2026:22:00:00 +0800",
        "31/Aug/2026:22:00:01 +0800",
    ) in result

    assert (
        "31/Aug/2026:22:00:01 +0800",
        "31/Aug/2026:22:00:02 +0800",
    ) in result

    assert (
        "31/Aug/2026:22:00:02 +0800",
        "31/Aug/2026:22:00:02 +0800",
    ) in result


def test_create_sliding_detection_windows_counts_seconds():
    logs = [
        [
            {
                "request_dt_str": "31/Aug/2026:22:00:00 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 0),
                "remote_addr": "127.0.0.1",
            },
            {
                "request_dt_str": "31/Aug/2026:22:00:00 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 0),
                "remote_addr": "127.0.0.1",
            },
            {
                "request_dt_str": "31/Aug/2026:22:00:01 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 1),
                "remote_addr": "127.0.0.1",
            },
            {
                "request_dt_str": "31/Aug/2026:22:00:02 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 2),
                "remote_addr": "127.0.0.1",
            },
        ]
    ]

    result = create_sliding_detection_windows(
        logs,
        request_threshold=2,
        detection_window=2,
    )

    window = result[
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:01 +0800",
        )
    ]

    assert len(window) == 3


def test_create_sliding_detection_windows_ignores_short_logs():
    logs = [
        [
            {
                "request_dt_str": "31/Aug/2026:22:00:00 +0800",
                "request_dt": datetime(2026, 8, 31, 22, 0, 0),
            },
        ]
    ]

    result = create_sliding_detection_windows(
        logs,
        request_threshold=2,
        detection_window=2,
    )

    assert result == {}
