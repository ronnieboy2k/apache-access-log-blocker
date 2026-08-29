def create_sliding_detection_windows(logs, request_threshold, detection_window):

    result = {}

    for log in logs:

        if len(log) < request_threshold:
            continue

        for index, value in enumerate(log):

            requests = []

            start = None
            end = None
            second_counter = 0
            for index2, value2 in enumerate(log):

                if index2 >= index:

                    requests.append(value2)

                    if not second_counter:
                        second_counter += 1
                        start = value2["request_dt"]

                    elif log[index2]["request_dt"] != log[index2 - 1]["request_dt"]:
                        second_counter += 1

                    if second_counter == detection_window:
                        end = value2["request_dt"]
                        break

            else:
                end = value2["request_dt"]

            result[(start, end)] = requests

    return result
