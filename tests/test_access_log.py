from datetime import datetime, timedelta
from apache_access_log_blocker.access_log import read_access_log_window


def test_read_access_log_window(tmp_path):

    log_dt_format = "%d/%b/%Y:%H:%M:%S %z"

    now = datetime.now().astimezone().replace(microsecond=0)

    inside_window = now - timedelta(seconds=5)
    outside_window = now - timedelta(seconds=30)

    access_log = tmp_path / "access.log"

    access_log.write_text(
        f"127.0.0.1 - - [{inside_window.strftime(log_dt_format)}] "
        f'"GET /inside HTTP/1.1" 200 123\n'
        f"127.0.0.2 - - [{outside_window.strftime(log_dt_format)}] "
        f'"GET /outside HTTP/1.1" 200 123\n',
        encoding="utf-8",
    )

    result, read_start, read_end = read_access_log_window(
        access_log=access_log,
        read_window=10,
        remote_addr_index=0,
        request_dt_index=3,
        request_method_n_url_index=4,
        log_dt_format=log_dt_format,
    )

    assert len(result) == 1

    request = result[0]

    assert request["remote_addr"] == "127.0.0.1"

    assert request["request_dt"] == inside_window

    assert request["request_dt_str"] == inside_window.strftime(log_dt_format)

    assert request["request_method"] == "GET"

    assert request["request_url"] == "/inside"

    assert read_start <= request["request_dt"] <= read_end
