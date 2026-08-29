from datetime import timedelta


def group_logs_by_contiguous_seconds(logs, request_method="get"):

    result = []

    get_logs = [
        log for log in logs if log["request_method"].lower() == request_method.lower()
    ]

    seconds_counter = 0
    old_dt = None
    for log in get_logs:

        access_log_dt2 = log["request_dt"] - timedelta(seconds=1)

        if old_dt:
            if old_dt == access_log_dt2:
                seconds_counter += 1
                result[len(result) - 1].append(log)
            elif old_dt == log["request_dt"]:
                result[len(result) - 1].append(log)
            else:
                seconds_counter = 1
                result.append([log])
        else:
            seconds_counter += 1
            result.append([log])

        old_dt = log["request_dt"]

    return result
