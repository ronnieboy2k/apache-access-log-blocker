def create_sliding_detection_windows(logs, request_threshold, detection_window):

    result = {}

    for log in logs:

        if len(log) < request_threshold:
            continue

        for index in range(len(log)):

            requests = []
            start = None
            end = None
            second_counter = 0
            previous_dt = None

            for value in log[index:]:

                if previous_dt != value["request_dt"]:
                    second_counter += 1

                    if second_counter > detection_window:
                        break

                if start is None:
                    start = value["request_dt_str"]

                requests.append(value)
                end = value["request_dt_str"]

                previous_dt = value["request_dt"]

            window_key = (start, end)

            if window_key not in result or len(requests) > len(result[window_key]):
                result[window_key] = requests

    return result
