from apache_access_log_blocker.block_manager import (
    find_new_remote_addrs_to_block,
    ensure_auto_block_section,
    create_block_entries,
)


def test_find_new_remote_addrs_to_block():
    content = """
<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    Require not ip 127.0.0.1

    # Apache Access Log Auto Blocker - END
</RequireAll>
"""

    result = find_new_remote_addrs_to_block(
        content,
        "# Apache Access Log Auto Blocker - BEGIN",
        "# Apache Access Log Auto Blocker - END",
        ["127.0.0.1", "127.0.0.2"],
    )

    assert result == ["127.0.0.2"]


def test_find_new_remote_addrs_to_block_without_block_section():
    content = """
<RequireAll>
    Require all granted
</RequireAll>
"""

    result = find_new_remote_addrs_to_block(
        content,
        "# Apache Access Log Auto Blocker - BEGIN",
        "# Apache Access Log Auto Blocker - END",
        ["127.0.0.1", "127.0.0.2"],
    )

    assert result == ["127.0.0.1", "127.0.0.2"]


def test_ensure_auto_block_section_without_require_all():
    content = "DirectoryIndex index.php"

    auto_block_section = """    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
"""

    htaccess_require_all = """<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
</RequireAll>
"""

    result, changed = ensure_auto_block_section(
        content,
        auto_block_section,
        htaccess_require_all,
        "# Apache Access Log Auto Blocker - BEGIN",
    )

    assert changed is True
    assert result == f"{content}\n\n{htaccess_require_all}"


def test_ensure_auto_block_section_with_require_all_without_marker():
    content = """<RequireAll>
    Require all granted
</RequireAll>
"""

    auto_block_section = """    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
"""

    htaccess_require_all = """<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
</RequireAll>
"""

    result, changed = ensure_auto_block_section(
        content,
        auto_block_section,
        htaccess_require_all,
        "# Apache Access Log Auto Blocker - BEGIN",
    )

    assert changed is True
    assert "# Apache Access Log Auto Blocker - BEGIN" in result
    assert "# Apache Access Log Auto Blocker - END" in result


def test_ensure_auto_block_section_already_exists():
    content = """<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
</RequireAll>
"""

    auto_block_section = """    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
"""

    htaccess_require_all = """<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    # Apache Access Log Auto Blocker - END
</RequireAll>
"""

    result, changed = ensure_auto_block_section(
        content,
        auto_block_section,
        htaccess_require_all,
        "# Apache Access Log Auto Blocker - BEGIN",
    )

    assert result == content
    assert changed is False


def test_create_block_entries_post():
    new_remote_addrs_to_block = ["127.0.0.1"]

    post_remote_addrs_to_block = (
        ["127.0.0.1"],
        [
            (
                "31/Aug/2026:22:00:00 +0800",
                "31/Aug/2026:22:00:02 +0800",
            )
        ],
    )

    get_remote_addrs_to_block = ([], [])

    result = create_block_entries(
        new_remote_addrs_to_block,
        post_remote_addrs_to_block,
        get_remote_addrs_to_block,
        "31/Aug/2026:22:00:00 +0800",
        "31/Aug/2026:22:00:02 +0800",
        "%d/%b/%Y:%H:%M:%S %z",
    )

    assert "# METHOD: POST" in result
    assert (
        "# DETECTION WINDOW: 31/Aug/2026:22:00:00 +0800 -> 31/Aug/2026:22:00:02 +0800"
        in result
    )
    assert "Require not ip 127.0.0.1" in result


def test_create_block_entries_get():
    new_remote_addrs_to_block = ["127.0.0.2"]

    post_remote_addrs_to_block = ([], [])

    get_remote_addrs_to_block = (
        ["127.0.0.2"],
        [
            (
                "31/Aug/2026:22:00:01 +0800",
                "31/Aug/2026:22:00:03 +0800",
            )
        ],
    )

    result = create_block_entries(
        new_remote_addrs_to_block,
        post_remote_addrs_to_block,
        get_remote_addrs_to_block,
        "31/Aug/2026:22:00:00 +0800",
        "31/Aug/2026:22:00:05 +0800",
        "%d/%b/%Y:%H:%M:%S %z",
    )

    assert "# METHOD: GET" in result
    assert (
        "# DETECTION WINDOW: 31/Aug/2026:22:00:01 +0800 -> 31/Aug/2026:22:00:03 +0800"
        in result
    )
    assert "Require not ip 127.0.0.2" in result


def test_create_block_entries_get():
    new_remote_addrs_to_block = ["127.0.0.2"]

    post_remote_addrs_to_block = ([], [])

    get_remote_addrs_to_block = (
        ["127.0.0.2"],
        [
            (
                "31/Aug/2026:22:00:01 +0800",
                "31/Aug/2026:22:00:03 +0800",
            )
        ],
    )

    result = create_block_entries(
        new_remote_addrs_to_block,
        post_remote_addrs_to_block,
        get_remote_addrs_to_block,
        "31/Aug/2026:22:00:00 +0800",
        "31/Aug/2026:22:00:05 +0800",
        "%d/%b/%Y:%H:%M:%S %z",
    )

    assert "# METHOD: GET" in result
    assert (
        "# DETECTION WINDOW: 31/Aug/2026:22:00:01 +0800 -> 31/Aug/2026:22:00:03 +0800"
        in result
    )
    assert "Require not ip 127.0.0.2" in result
