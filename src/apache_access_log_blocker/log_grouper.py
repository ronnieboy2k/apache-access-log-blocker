import re
from datetime import datetime, timedelta


def group_logs_by_contiguous_seconds(logs, request_method="get"):

    result = []

    get_logs = [
        log for log in logs if log["request_method"].lower() == request_method.lower()
    ]

    timestamp_pattern = re.compile(
        r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-][0-9]{4})\]"
    )

    seconds_counter = 0
    old_dt = None
    for log in get_logs:

        match = timestamp_pattern.search(log["request_dt"])

        if match:
            access_log_dt = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
            access_log_dt2 = access_log_dt - timedelta(seconds=1)

            if old_dt:
                if old_dt == access_log_dt2:
                    seconds_counter += 1
                    result[len(result) - 1].append(log)
                elif old_dt == access_log_dt:
                    result[len(result) - 1].append(log)
                else:
                    seconds_counter = 1
                    result.append([log])
            else:
                seconds_counter += 1
                result.append([log])

            old_dt = access_log_dt

    return result
