# Apache Access Log Blocker

Automated Apache access log monitoring and IP blocking based on configurable request rates, detection windows, HTTP methods, and URL patterns.

## Project Background

This project is a modern Python reimplementation of an Apache access log auto-blocking tool I originally developed in **C++ approximately 19 years ago**.

The original C++ version was created to monitor Apache access logs, detect suspicious request patterns, and automatically block potentially malicious IP addresses.

For this version, I rebuilt the application in Python and significantly enhanced both its architecture and functionality.

The Python version now includes:

* Configurable request thresholds
* Configurable detection windows
* Configurable access log read windows
* Contiguous-second log grouping
* Sliding detection windows
* Dedicated GET and POST detection rules
* URL-based POST request detection
* Automated `.htaccess` management
* Duplicate IP blocking prevention
* Separation of detection and block-management responsibilities
* Unit testing
* End-to-end integration testing
* Configuration-driven behavior

The project demonstrates how an older solution can be revisited, modernized, and improved using current programming practices and software architecture.

---

## How It Works

The application follows a multi-stage detection and blocking process.

```text
Apache Access Log
        │
        ▼
Read Access Log Window
        │
        ▼
Group Logs by Contiguous Seconds
        │
        ▼
Create Sliding Detection Windows
        │
        ▼
Apply Request Threshold
        │
        ├───────────────┐
        ▼               ▼
   GET Detection    POST Detection
        │               │
        └───────┬───────┘
                ▼
      IPs to Block
                │
                ▼
     Check Existing Blocks
                │
                ▼
      Update .htaccess
```

### 1. Access Log Read Window

The application reads only a configurable time period from the Apache access log.

For example:

```text
READ WINDOW: 10 seconds
```

If the current time is:

```text
14:30:10
```

the application reads requests between:

```text
14:30:00 → 14:30:10
```

This prevents the application from processing the entire access log on every execution.

---

### 2. Contiguous Detection

After reading the access log, requests are grouped into sequences of **contiguous timestamp-seconds**.

For example:

```text
22:00:00
22:00:00
22:00:01
22:00:01
22:00:02
```

belongs to one contiguous sequence because each timestamp-second follows the previous second.

The purpose of this stage is to establish the request sequence used by the detection-window algorithm.

---

### 3. Detection Threshold

The **request threshold** determines how many requests are required before an IP can be considered suspicious.

For example:

```text
POST request threshold = 3
```

means an IP must generate at least **3 matching POST requests** within the configured detection window before it can be blocked.

The threshold is configurable and can be adjusted according to the desired sensitivity.

---

### 4. Sliding Detection Window

The application uses a sliding detection window to detect bursts of requests.

For example, with:

```text
Request threshold: 3
Detection window: 2 seconds
```

the application evaluates requests across consecutive two-second periods.

Example:

```text
22:00:00  ── Request
22:00:00  ── Request
22:00:01  ── Request
```

This produces:

```text
Detection Window:
22:00:00 → 22:00:01
```

with:

```text
3 requests
```

If the threshold is:

```text
3
```

the IP qualifies for blocking.

The sliding-window approach allows the application to detect bursts even when the requests do not align with fixed clock intervals.

---

## Detection Rules

GET and POST requests are evaluated separately.

### GET Detection

GET detection identifies an IP generating requests to **different URLs** at a suspicious rate.

Example:

```text
127.0.0.1 → GET /
127.0.0.1 → GET /about
127.0.0.1 → GET /contact
```

If the configured GET threshold is reached within the detection window, the IP is considered for blocking.

This can help identify automated scanning or crawling behavior.

---

### POST Detection

POST detection identifies repeated requests from the same IP to the **same URL**.

Example:

```text
127.0.0.1 → POST /login
127.0.0.1 → POST /login
127.0.0.1 → POST /login
```

If the configured POST threshold is reached within the detection window, the IP is considered for blocking.

This can help detect repeated automated POST attempts against endpoints such as login or form-processing URLs.

---

## Duplicate Block Prevention

Before adding an IP to `.htaccess`, the application checks whether the IP is already present in the Apache Access Log Auto Blocker section.

This prevents duplicate entries such as:

```apache
Require not ip 127.0.0.1
Require not ip 127.0.0.1
Require not ip 127.0.0.1
```

Only newly detected IP addresses are added.

---

## `.htaccess` Management

The application can automatically create the required `<RequireAll>` section when it does not already exist.

Example:

```apache
<RequireAll>
    Require all granted

    # Apache Access Log Auto Blocker - BEGIN

    # METHOD: POST
    # DETECTION WINDOW: 31/Aug/2026:22:00:00 +0800 -> 31/Aug/2026:22:00:01 +0800
    # ADDED: 31/Aug/2026:22:00:05 +0800
    Require not ip 127.0.0.1

    # Apache Access Log Auto Blocker - END
</RequireAll>
```

The automatically managed section is identified by:

```text
# Apache Access Log Auto Blocker - BEGIN
# Apache Access Log Auto Blocker - END
```

This makes it possible to distinguish automatically generated rules from manually configured `.htaccess` rules.

---

## Configuration

Detection behavior is configurable through `config.py`.

Configuration includes values such as:

```python
access_log_read_window
get_request_threshold
get_detection_window
post_request_threshold
post_detection_window
access_log_dt_format
```

This allows detection behavior to be changed without modifying the detection algorithms.

For example:

```python
GET_REQUEST_THRESHOLD = 15
GET_DETECTION_WINDOW = 3

POST_REQUEST_THRESHOLD = 5
POST_DETECTION_WINDOW = 2
```

The actual configuration variable names and values can be adjusted according to the deployment environment.

---

## Project Structure

```text
apache-access-log-blocker/
│
├── .github/
│   └── workflows/
│       ├── deploy.yml
│       └── tests.yml
│
├── src/
│   └── apache_access_log_blocker/
│       ├── access_log.py
│       ├── log_grouper.py
│       ├── sliding_window.py
│       ├── block_detector.py
│       ├── block_manager.py
│       └── ...
│
├── tests/
│   ├── test_access_log.py
│   ├── test_log_grouper.py
│   ├── test_sliding_window.py
│   ├── test_block_detector.py
│   ├── test_block_manager.py
│   └── test_integration.py
│
├── config.py
├── main.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

The application is separated into components so that log reading, grouping, detection, and block management can be tested independently.

---

## Testing

The project includes unit tests for the individual components as well as an end-to-end integration test.

Run all tests with:

```bash
pytest -v
```

The test suite covers areas including:

* Access log parsing
* Access log time-window filtering
* Contiguous-second grouping
* Sliding detection windows
* GET detection
* POST detection
* Duplicate IP detection
* `.htaccess` block-section management
* Block-entry generation
* End-to-end malicious IP detection and blocking

The integration test verifies that the individual components work together as a complete detection and blocking pipeline.

---

## Running the Application

The application can be executed using:

```bash
python main.py
```

The application reads the configured Apache access log, evaluates the configured detection rules, and updates the configured `.htaccess` file when a suspicious IP is detected.

---

## Running with Cron

The application is designed to be executed periodically using a cron job.

For example, to run the application every **5 seconds**, a cron scheduler can execute:

```bash
python /path/to/apache-access-log-blocker/main.py
```

However, standard cron implementations commonly provide **one-minute granularity**. For sub-minute execution, a wrapper loop, systemd timer, or another scheduler capable of sub-minute intervals should be used.

### Example: Cron Every Minute

To run the application once per minute:

```cron
* * * * * /usr/bin/python3 /path/to/apache-access-log-blocker/main.py
```

### Example: Multiple Runs Per Minute

If a five-second monitoring interval is required, one approach is to use a shell loop:

```bash
while true; do
    /usr/bin/python3 /path/to/apache-access-log-blocker/main.py
    sleep 5
done
```

For production environments, a dedicated process supervisor or systemd service/timer may be preferable to a continuously running shell loop.

---

## Production Considerations

Before deploying the application in production:

1. Verify the Apache log format matches the configured parser indexes.
2. Verify the configured `.htaccess` path.
3. Test the generated `.htaccess` rules.
4. Start with conservative request thresholds.
5. Monitor blocked IP addresses for false positives.
6. Run the application under an account with the required permissions.
7. Test the application against a copy of the production `.htaccess` before enabling automatic blocking.
8. Ensure the Apache configuration supports the generated `Require not ip` directives.

---

## Development History

### Original Version

The original implementation was written in **C++ approximately 19 years ago**.

Its primary purpose was to monitor Apache access logs and automatically block IP addresses exhibiting suspicious request patterns.

### Python Reimplementation

The current version was rebuilt from the ground up in Python with a focus on:

* Cleaner modular architecture
* Testability
* Configurable detection rules
* Sliding-window detection
* Separate GET and POST detection
* Automated `.htaccess` management
* Duplicate-block prevention
* Unit and integration testing
* Easier future maintenance and extension

This is not simply a language conversion of the original implementation. The Python version is an **enhanced and modernized implementation** based on the same original concept.

---

## License

See [LICENSE](LICENSE) for licensing information.
