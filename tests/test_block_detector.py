from datetime import datetime
from apache_access_log_blocker.block_detector import (
    find_get_remote_addrs_to_block,
    find_post_remote_addrs_to_block,
)


def test_find_post_remote_addrs_to_block():
    detection_windows = {
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:02 +0800",
        ): [
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
        ]
    }

    result = find_post_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert result == (
        ["127.0.0.1"],
        [
            (
                "31/Aug/2026:22:00:00 +0800",
                "31/Aug/2026:22:00:02 +0800",
            )
        ],
    )


def test_find_get_remote_addrs_to_block():
    detection_windows = {
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:02 +0800",
        ): [
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/about",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/contact",
            },
        ]
    }

    result = find_get_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert result == (
        ["127.0.0.1"],
        [
            (
                "31/Aug/2026:22:00:00 +0800",
                "31/Aug/2026:22:00:02 +0800",
            )
        ],
    )


def test_find_get_remote_addrs_to_block_below_threshold():
    detection_windows = {
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:02 +0800",
        ): [
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/about",
            },
        ]
    }

    result = find_get_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert result == ([], [])


def test_find_get_remote_addrs_to_block_ignores_post():
    detection_windows = {
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:02 +0800",
        ): [
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "POST",
                "request_url": "/login",
            },
        ]
    }

    result = find_get_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert result == ([], [])


def test_find_get_remote_addrs_to_block_multiple_ips():
    detection_windows = {
        (
            "31/Aug/2026:22:00:00 +0800",
            "31/Aug/2026:22:00:02 +0800",
        ): [
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/about",
            },
            {
                "remote_addr": "127.0.0.1",
                "request_method": "GET",
                "request_url": "/contact",
            },
            {
                "remote_addr": "127.0.0.2",
                "request_method": "GET",
                "request_url": "/",
            },
            {
                "remote_addr": "127.0.0.2",
                "request_method": "GET",
                "request_url": "/about",
            },
            {
                "remote_addr": "127.0.0.2",
                "request_method": "GET",
                "request_url": "/contact",
            },
        ]
    }

    result = find_get_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert set(result[0]) == {"127.0.0.1", "127.0.0.2"}
    assert len(result[1]) == 2
