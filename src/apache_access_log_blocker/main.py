import config
from access_log import read_access_log_window
from log_grouper import group_logs_by_contiguous_seconds
from sliding_window import create_sliding_detection_windows
from block_detector import (
    find_get_remote_addrs_to_block,
    find_post_remote_addrs_to_block,
)
from pprint import pprint
from pathlib import Path
from block_manager import (
    find_new_remote_addrs_to_block,
    ensure_auto_block_section,
    create_block_entries,
)

access_log = config.access_log_file_path
htaccess = config.htaccess_file_path
read_window = config.access_log_read_window
access_log_remote_addr_index = config.access_log_remote_addr_index
access_log_request_dt_index = config.access_log_request_dt_index
access_log_request_method_n_url_index = config.access_log_request_method_n_url_index
log_dt_format = config.access_log_dt_format

request_method = "GET"
request_threshold = getattr(config, f"{request_method.lower()}_request_threshold")
detection_window = getattr(config, f"{request_method.lower()}_detection_window")


access_log_window, access_log_dt_read_start, access_log_dt_read_end = (
    read_access_log_window(
        access_log,
        read_window,
        access_log_remote_addr_index,
        access_log_request_dt_index,
        access_log_request_method_n_url_index,
        log_dt_format,
    )
)
logs = group_logs_by_contiguous_seconds(access_log_window)

detection_windows = create_sliding_detection_windows(
    logs, request_threshold, detection_window
)

post_remote_addrs_to_block = find_post_remote_addrs_to_block(
    detection_windows, request_threshold
)
# post_remote_addrs_to_block = ([], [])
get_remote_addrs_to_block = find_get_remote_addrs_to_block(
    detection_windows, request_threshold
)
# get_remote_addrs_to_block = ([], [])


begin_marker = config.auto_block_begin_marker
end_marker = config.auto_block_end_marker
auto_block_section = config.auto_block_section_template
htaccess_require_all = config.htaccess_require_all_template

remote_addrs_to_block = set(
    post_remote_addrs_to_block[0] + get_remote_addrs_to_block[0]
)

if remote_addrs_to_block:
    htaccess = Path(htaccess)

    with htaccess.open("r+", encoding="utf-8") as file:
        content = file.read()

        # Find remote addresses / IPs that are not yet in the block section.
        new_remote_addrs_to_block = find_new_remote_addrs_to_block(
            content,
            begin_marker,
            end_marker,
            remote_addrs_to_block,
        )
        # End: Find new remote addresses / IPs.

        if new_remote_addrs_to_block:

            # Ensure the block section exists.
            content, changed = ensure_auto_block_section(
                content,
                auto_block_section,
                htaccess_require_all,
                begin_marker,
            )

            if changed:
                file.seek(0)
                file.write(content)
                file.truncate()
            # End: Ensure the block section exists.

            if begin_marker in content:

                # Create and add remote addresses / IPs to block section.
                require_not = create_block_entries(
                    new_remote_addrs_to_block,
                    post_remote_addrs_to_block,
                    get_remote_addrs_to_block,
                    access_log_dt_read_start,
                    access_log_dt_read_end,
                    log_dt_format,
                )

                if require_not:

                    position = content.rfind(end_marker)

                    if position != -1:
                        content = (
                            content[:position]
                            + require_not
                            + "    "
                            + content[position:]
                        )

                        file.seek(0)
                        file.write(content)
                        file.truncate()
                # End: Create and add remote addresses / IPs to block section.


pprint(remote_addrs_to_block)


# block_entry = f"""    # METHOD: {request_method.upper()}
#     # WINDOW: {dt_start} -> {dt_end}
#     # ADDED: {dt_now}
#     Require not ip {remote_addr}

# """
