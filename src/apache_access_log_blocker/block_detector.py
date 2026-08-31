def find_get_remote_addrs_to_block(detection_windows, request_threshold):

    remote_addrs_to_block = []
    request_window_dt_start_n_end = []

    for window_key, window_logs in detection_windows.items():
        remote_addrs = []
        if len(window_logs) < request_threshold:
            continue

        for log in window_logs:
            if (
                log["request_method"].lower() != "get"
                or log["remote_addr"] in remote_addrs_to_block
            ):
                continue
            remote_addrs.append(
                (
                    log["remote_addr"],
                    window_key[0],
                    window_key[1],
                )
            )

        unique_remote_addrs = set(remote_addrs)
        for unique_remote_addr in unique_remote_addrs:
            if (
                remote_addrs.count(unique_remote_addr) >= request_threshold
                and unique_remote_addr[0] not in remote_addrs_to_block
            ):
                remote_addrs_to_block.append(unique_remote_addr[0])
                request_window_dt_start_n_end.append(
                    (unique_remote_addr[1], unique_remote_addr[2])
                )

    return remote_addrs_to_block, request_window_dt_start_n_end


def find_post_remote_addrs_to_block(detection_windows, request_threshold):

    remote_addrs_to_block = []
    request_window_dt_start_n_end = []

    for window_key, window_logs in detection_windows.items():
        request_pairs = []
        if len(window_logs) < request_threshold:
            continue

        for log in window_logs:
            if (
                log["request_method"].lower() != "post"
                or log["remote_addr"] in remote_addrs_to_block
            ):
                continue
            request_pairs.append(
                (
                    log["remote_addr"],
                    log["request_url"],
                    window_key[0],
                    window_key[1],
                )
            )

        unique_request_pairs = set(request_pairs)
        for request_pair in unique_request_pairs:
            if (
                request_pairs.count(request_pair) >= request_threshold
                and request_pair[0] not in remote_addrs_to_block
            ):
                remote_addrs_to_block.append(request_pair[0])
                request_window_dt_start_n_end.append((request_pair[2], request_pair[3]))

    return remote_addrs_to_block, request_window_dt_start_n_end
