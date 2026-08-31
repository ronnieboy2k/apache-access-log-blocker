import re
from datetime import datetime


def find_new_remote_addrs_to_block(
    content,
    begin_marker,
    end_marker,
    remote_addrs_to_block,
):

    result = []

    if begin_marker in content:
        begin_position = content.find(begin_marker)
        end_position = content.find(end_marker, begin_position)
        end_position += len(end_marker)

        for remote_addr_to_block in remote_addrs_to_block:
            if not re.search(
                rf"Require\s+not\s+ip\s+{re.escape(remote_addr_to_block)}",
                content[begin_position:end_position],
                re.IGNORECASE,
            ):
                result.append(remote_addr_to_block)
    else:
        result = remote_addrs_to_block

    return result


def ensure_auto_block_section(
    content,
    auto_block_section,
    htaccess_require_all,
    begin_marker,
):
    original_content = content

    if "<RequireAll>" not in content:
        content += f"\n\n{htaccess_require_all}"

    elif begin_marker not in content:

        position = content.rfind("</RequireAll>")

        if position != -1:
            content = (
                content[:position] + "\n" + auto_block_section + content[position:]
            )

    return content, content != original_content


def create_block_entries(
    new_remote_addrs_to_block,
    post_remote_addrs_to_block,
    get_remote_addrs_to_block,
    access_log_dt_read_start,
    access_log_dt_read_end,
    log_dt_format,
):
    result = ""
    dt_now = datetime.now().astimezone().strftime(log_dt_format)
    window = ""
    for remote_addr in new_remote_addrs_to_block:

        if (
            remote_addr in post_remote_addrs_to_block[0]
            and remote_addr in get_remote_addrs_to_block[0]
        ):
            method = "GET / POST"
            window = f"    # READ WINDOW: {access_log_dt_read_start} -> {access_log_dt_read_end}\n"
        elif remote_addr in post_remote_addrs_to_block[0]:
            method = "POST"
            for index, detected_remote_addr in enumerate(post_remote_addrs_to_block[0]):
                if remote_addr == detected_remote_addr:
                    dt_start = post_remote_addrs_to_block[1][index][0]
                    dt_end = post_remote_addrs_to_block[1][index][1]

                    window = f"    # DETECTION WINDOW: {dt_start} -> {dt_end}\n"
                    break
        else:
            method = "GET"
            for index, detected_remote_addr in enumerate(get_remote_addrs_to_block[0]):
                if remote_addr == detected_remote_addr:
                    dt_start = get_remote_addrs_to_block[1][index][0]
                    dt_end = get_remote_addrs_to_block[1][index][1]

                    window = f"    # DETECTION WINDOW: {dt_start} -> {dt_end}\n"
                    break

        result += f"""# METHOD: {method}
    {window}    # ADDED: {dt_now}
        Require not ip {remote_addr}\n\n"""

    return result
