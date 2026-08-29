access_log_directory_path = "./"
access_log_filename = "access.log"
access_log_file_path = access_log_directory_path + access_log_filename

# in seconds
# access_log_read_window = 6
access_log_read_window = 172800

access_log_remote_addr_index = 0
access_log_request_dt_index = 3
access_log_request_method_n_url_index = 4

post_request_threshold = 5
post_detection_window = 2

get_request_threshold = 15
get_detection_window = 3
