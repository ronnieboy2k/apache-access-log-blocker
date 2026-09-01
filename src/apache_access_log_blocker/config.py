access_log_dt_format = "%d/%b/%Y:%H:%M:%S %z"

access_log_directory_path = "./"
access_log_filename = "access.log"
access_log_file_path = access_log_directory_path + access_log_filename

# in seconds
access_log_read_window = 6
# access_log_read_window = 172800

access_log_remote_addr_index = 0
access_log_request_dt_index = 3
access_log_request_method_n_url_index = 4

post_request_threshold = 5
post_detection_window = 2

get_request_threshold = 15
# get_request_threshold = 3
get_detection_window = 3

htaccess_directory_path = "./"
htaccess_filename = "htaccess.txt"
htaccess_file_path = htaccess_directory_path + htaccess_filename

# .htaccess markers
auto_block_begin_marker = "# Apache Access Log Auto Blocker - BEGIN"
auto_block_end_marker = "# Apache Access Log Auto Blocker - END"

# .htaccess templates
auto_block_section_template = f"""    {auto_block_begin_marker}

    {auto_block_end_marker}
"""

htaccess_require_all_template = f"""<RequireAll>
    Require all granted

{auto_block_section_template}</RequireAll>
"""
