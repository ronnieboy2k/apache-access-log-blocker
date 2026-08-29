import config
from access_log import read_access_log_window
from log_grouper import group_logs_by_contiguous_seconds
from sliding_window import create_sliding_detection_windows
from pprint import pprint

access_log = config.access_log_file_path
read_window = config.access_log_read_window
access_log_remote_addr_index = config.access_log_remote_addr_index
access_log_request_dt_index = config.access_log_request_dt_index
access_log_request_method_n_url_index = config.access_log_request_method_n_url_index

request_method = "GET"
request_threshold = getattr(config, f"{request_method.lower()}_request_threshold")
detection_window = getattr(config, f"{request_method.lower()}_detection_window")


logs = read_access_log_window(
    access_log,
    read_window,
    access_log_remote_addr_index,
    access_log_request_dt_index,
    access_log_request_method_n_url_index,
)
logs = group_logs_by_contiguous_seconds(logs)

detection_windows = create_sliding_detection_windows(
    logs, request_threshold, detection_window
)

pprint(detection_windows)
