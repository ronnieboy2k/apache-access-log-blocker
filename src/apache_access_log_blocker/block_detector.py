def find_get_remote_addrs_to_block(detection_windows, request_threshold):

    result = []

    for _, window_logs in detection_windows.items():
        remote_addrs = []
        if len(window_logs) < request_threshold:
            continue

        for log in window_logs:
            if log["request_method"].lower() != "get":
                continue
            remote_addrs.append(log["remote_addr"])

        unique_remote_addrs = set(remote_addrs)
        for unique_remote_addr in unique_remote_addrs:
            if (
                remote_addrs.count(unique_remote_addr) >= request_threshold
                and unique_remote_addr not in result
            ):
                result.append(unique_remote_addr)

    return result


def find_post_remote_addrs_to_block(detection_windows, request_threshold):

    result = []

    for _, window_logs in detection_windows.items():
        request_pairs = []
        if len(window_logs) < request_threshold:
            continue

        for log in window_logs:
            if log["request_method"].lower() != "post":
                continue
            request_pairs.append((log["remote_addr"], log["request_url"]))

        unique_request_pairs = set(request_pairs)
        for request_pair in unique_request_pairs:
            if (
                request_pairs.count(request_pair) >= request_threshold
                and request_pair[0] not in result
            ):
                result.append(request_pair[0])

    return result
