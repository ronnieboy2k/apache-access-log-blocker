from pathlib import Path
import re
from datetime import datetime, timedelta


def read_access_log_window(
    access_log,
    read_window,
    remote_addr_index,
    request_dt_index,
    request_method_n_url_index,
):

    result = []

    access_log = Path(access_log)

    access_log_dt_read_end = datetime.now().astimezone().replace(microsecond=0)
    access_log_dt_read_start = access_log_dt_read_end - timedelta(seconds=read_window)

    with access_log.open("r", encoding="utf-8") as file:
        for line in file:

            parts = re.findall(r'\[[^\]]*\]|"[^"]*"|\S+', line)
            request_data = {}
            for index, value in enumerate(parts):
                if index == remote_addr_index:
                    request_data["remote_addr"] = value
                if index == request_dt_index:
                    request_data["request_dt"] = datetime.strptime(
                        value.strip("[]"), "%d/%b/%Y:%H:%M:%S %z"
                    )
                if index == request_method_n_url_index:
                    method_n_url = value.split(" ")
                    request_data["request_method"] = method_n_url[0].removeprefix('"')
                    request_data["request_url"] = method_n_url[1]

            if request_data:
                if (
                    access_log_dt_read_start
                    <= request_data["request_dt"]
                    <= access_log_dt_read_end
                ):
                    result.append(request_data)

    return result
