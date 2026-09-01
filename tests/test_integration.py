from datetime import datetime, timedelta

from apache_access_log_blocker.access_log import read_access_log_window
from apache_access_log_blocker.log_grouper import group_logs_by_contiguous_seconds
from apache_access_log_blocker.sliding_window import (
    create_sliding_detection_windows,
)
from apache_access_log_blocker.block_detector import (
    find_get_remote_addrs_to_block,
    find_post_remote_addrs_to_block,
)
from apache_access_log_blocker.block_manager import (
    find_new_remote_addrs_to_block,
    ensure_auto_block_section,
    create_block_entries,
)


def test_end_to_end_blocks_malicious_ip(tmp_path):
    log_dt_format = "%d/%b/%Y:%H:%M:%S %z"

    access_log = tmp_path / "access.log"
    htaccess = tmp_path / ".htaccess"

    now = datetime.now().astimezone().replace(microsecond=0)

    # 3 POST requests from the same IP within 2 seconds.
    request_1 = now - timedelta(seconds=5)
    request_2 = now - timedelta(seconds=5)
    request_3 = now - timedelta(seconds=4)

    access_log.write_text(
        f"127.0.0.1 - - [{request_1.strftime(log_dt_format)}] "
        f'"POST /login HTTP/1.1" 200 123\n'
        f"127.0.0.1 - - [{request_2.strftime(log_dt_format)}] "
        f'"POST /login HTTP/1.1" 200 123\n'
        f"127.0.0.1 - - [{request_3.strftime(log_dt_format)}] "
        f'"POST /login HTTP/1.1" 200 123\n',
        encoding="utf-8",
    )

    htaccess.write_text(
        """<RequireAll>
    Require all granted
</RequireAll>
""",
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # Read access log
    # ---------------------------------------------------------

    access_log_window, read_start, read_end = read_access_log_window(
        access_log=access_log,
        read_window=10,
        remote_addr_index=0,
        request_dt_index=3,
        request_method_n_url_index=4,
        log_dt_format=log_dt_format,
    )

    assert len(access_log_window) == 3

    # ---------------------------------------------------------
    # Group logs
    # ---------------------------------------------------------

    logs = group_logs_by_contiguous_seconds(
        access_log_window,
        request_method="POST",
    )

    assert len(logs) == 1
    assert len(logs[0]) == 3

    # ---------------------------------------------------------
    # Create detection windows
    # ---------------------------------------------------------

    detection_windows = create_sliding_detection_windows(
        logs,
        request_threshold=3,
        detection_window=2,
    )

    assert detection_windows

    # ---------------------------------------------------------
    # Detect IPs
    # ---------------------------------------------------------

    post_remote_addrs_to_block = find_post_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    get_remote_addrs_to_block = find_get_remote_addrs_to_block(
        detection_windows,
        request_threshold=3,
    )

    assert post_remote_addrs_to_block[0] == ["127.0.0.1"]
    assert get_remote_addrs_to_block == ([], [])

    remote_addrs_to_block = set(
        post_remote_addrs_to_block[0] + get_remote_addrs_to_block[0]
    )

    # ---------------------------------------------------------
    # Find new IPs
    # ---------------------------------------------------------

    begin_marker = "# Apache Access Log Auto Blocker - BEGIN"
    end_marker = "# Apache Access Log Auto Blocker - END"

    content = htaccess.read_text(encoding="utf-8")

    new_remote_addrs_to_block = find_new_remote_addrs_to_block(
        content,
        begin_marker,
        end_marker,
        remote_addrs_to_block,
    )

    assert new_remote_addrs_to_block == {"127.0.0.1"}

    # ---------------------------------------------------------
    # Ensure block section exists
    # ---------------------------------------------------------

    auto_block_section = f"""    {begin_marker}

    {end_marker}
"""

    htaccess_require_all = f"""<RequireAll>
    Require all granted

{auto_block_section}</RequireAll>
"""

    content, changed = ensure_auto_block_section(
        content,
        auto_block_section,
        htaccess_require_all,
        begin_marker,
    )

    assert changed is True

    # ---------------------------------------------------------
    # Create block entry
    # ---------------------------------------------------------

    require_not = create_block_entries(
        new_remote_addrs_to_block,
        post_remote_addrs_to_block,
        get_remote_addrs_to_block,
        read_start,
        read_end,
        log_dt_format,
    )

    assert "Require not ip 127.0.0.1" in require_not

    # ---------------------------------------------------------
    # Write block entry
    # ---------------------------------------------------------

    position = content.rfind(end_marker)

    assert position != -1

    content = content[:position] + require_not + "    " + content[position:]

    htaccess.write_text(content, encoding="utf-8")

    # ---------------------------------------------------------
    # Verify final .htaccess
    # ---------------------------------------------------------

    final_content = htaccess.read_text(encoding="utf-8")

    assert begin_marker in final_content
    assert end_marker in final_content
    assert "Require all granted" in final_content
    assert "Require not ip 127.0.0.1" in final_content
