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

The project demonstrates how an older solution can be revisited, modernized, and improved using current programming practices, modular architecture, and automated testing.

---

## How It Works

The application follows a multi-stage detection and blocking pipeline:

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

Each stage has a specific responsibility, allowing the individual components to be developed and tested independently.

---

## 1. Access Log Read Window

The application reads only a configurable time period from the Apache access log.

For example:

```text
READ WINDOW: 10 seconds
```

If the current time is:

```text
14:30:10
```

the application processes requests between:

```text
14:30:00 → 14:30:10
```

This avoids processing the entire Apache access log every time the application runs.

The read window is configurable and can be adjusted according to the monitoring frequency and server environment.

---

## 2. Contiguous-Second Log Grouping

After reading the access log, requests are grouped into sequences of **contiguous timestamp-seconds**.

For example:

```text
22:00:00
22:00:00
22:00:01
22:00:01
22:00:02
```

belongs to one contiguous sequence because the timestamp seconds progress continuously:

```text
22:00:00 → 22:00:01 → 22:00:02
```

Multiple requests occurring during the same second remain part of that same sequence.

The purpose of this stage is to organize requests into usable sequences before applying the detection-window algorithm.

---

## 3. Request Threshold

The **request threshold** determines how many matching requests are required before an IP is considered suspicious.

For example:

```text
POST request threshold = 3
```

means an IP must generate at least:

```text
3 matching POST requests
```

within the configured detection window before it qualifies for blocking.

The threshold is configurable so that the sensitivity of the detection system can be adjusted without changing the detection algorithms.

---

## 4. Sliding Detection Window

The application uses a **sliding detection window** to detect bursts of requests across consecutive timestamp-seconds.

For example:

```text
Request threshold: 3
Detection window: 2 seconds
```

Consider these requests:

```text
22:00:00  ── Request
22:00:00  ── Request
22:00:01  ── Request
22:00:02  ── Request
```

The first sliding detection window is:

```text
22:00:00 → 22:00:01
```

containing:

```text
3 requests
```

Since the request threshold is:

```text
3
```

the IP qualifies for blocking under the applicable detection rule.

The window then slides forward and evaluates subsequent requests.

This approach allows the application to detect bursts without relying exclusively on fixed clock boundaries.

---

## 5. GET Detection

GET requests are evaluated separately from POST requests.

The GET detection rule identifies an IP generating requests to **different URLs** at a suspicious rate.

Example:

```text
127.0.0.1 → GET /
127.0.0.1 → GET /about
127.0.0.1 → GET /contact
```

If the configured GET request threshold is reached within the detection window, the IP is considered for blocking.

This type of behavior can help identify automated scanning, crawling, or other abnormal request activity.

The GET threshold and detection window are configurable.

Example:

```python
GET_REQUEST_THRESHOLD = 15
GET_DETECTION_WINDOW = 3
```

---

## 6. POST Detection

POST requests are evaluated separately from GET requests.

The POST detection rule identifies repeated requests from the same IP to the **same URL**.

Example:

```text
127.0.0.1 → POST /login
127.0.0.1 → POST /login
127.0.0.1 → POST /login
```

If the configured POST request threshold is reached within the detection window, the IP is considered for blocking.

This can help detect repeated automated POST attempts against endpoints such as:

* Login forms
* Authentication endpoints
* Form-processing endpoints
* Other POST-based application endpoints

Example configuration:

```python
POST_REQUEST_THRESHOLD = 5
POST_DETECTION_WINDOW = 2
```

---

## 7. Detection and Blocking Separation

The application separates the responsibility of **detecting suspicious activity** from the responsibility of **managing Apache block rules**.

The main components are organized around these responsibilities:

```text
access_log.py
    │
    └── Read and parse Apache access logs

log_grouper.py
    │
    └── Group requests into contiguous timestamp sequences

sliding_window.py
    │
    └── Create sliding detection windows

block_detector.py
    │
    └── Identify IPs that meet GET/POST detection rules

block_manager.py
    │
    ├── Identify new IPs
    ├── Maintain the automatic block section
    └── Generate .htaccess block entries
```

This separation makes the code easier to test, maintain, and extend.

---

## Duplicate Block Prevention

Before adding an IP address to `.htaccess`, the application checks whether that IP already exists inside the Apache Access Log Auto Blocker section.

This prevents duplicate entries such as:

```apache
Require not ip 127.0.0.1
Require not ip 127.0.0.1
Require not ip 127.0.0.1
```

Only newly detected IP addresses are added.

This is particularly important when the application is executed repeatedly by a scheduler.

---

## `.htaccess` Management

The application can automatically create the required Apache `<RequireAll>` structure when necessary.

The automatically managed section is identified using markers:

```text
# Apache Access Log Auto Blocker - BEGIN
# Apache Access Log Auto Blocker - END
```

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

This allows automatically generated rules to remain separated from manually configured Apache rules.

---

## Configuration

Detection behavior is controlled through `config.py`.

Configuration includes values such as:

```python
access_log_read_window

get_request_threshold

get_detection_window

post_request_threshold

post_detection_window

access_log_dt_format
```

This allows detection behavior to be modified without changing the detection algorithms.

Example:

```python
GET_REQUEST_THRESHOLD = 15
GET_DETECTION_WINDOW = 3

POST_REQUEST_THRESHOLD = 5
POST_DETECTION_WINDOW = 2
```

The actual values can be adjusted according to the deployment environment and desired detection sensitivity.

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

The project follows a modular structure so that log processing, detection logic, and Apache block management are separated into dedicated modules.

---

## Testing

The project includes both unit tests and an end-to-end integration test.

Run the complete test suite with:

```bash
pytest -v
```

The test suite covers areas including:

* Apache access log parsing
* Access log time-window filtering
* Contiguous-second grouping
* Sliding detection windows
* GET detection
* POST detection
* Request threshold handling
* Duplicate IP detection
* `.htaccess` block-section management
* Block-entry generation
* End-to-end malicious IP detection and blocking

The integration test verifies that the individual processing components work together as a complete detection and blocking pipeline.

---

## Development Environment

The project was developed and tested using:

```text
Python 3.14.6
pytest 9.1.1
```

A Python virtual environment is recommended for local development.

Example:

```powershell
python -m venv .venv
```

Activate the virtual environment on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install the project:

```powershell
python -m pip install -e .
```

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Run the tests:

```powershell
pytest -v
```

The `.venv` directory should not be committed to the repository. It should be excluded using `.gitignore`.

---

## Continuous Integration

The project includes a GitHub Actions workflow for automated testing.

The test workflow runs the test suite when changes are pushed to `main` or when a pull request targets `main`.

The workflow:

1. Checks out the repository
2. Sets up Python
3. Installs project dependencies
4. Installs development dependencies
5. Runs the complete pytest suite

Example command used by the workflow:

```bash
python -m pytest -v
```

This provides automated verification that changes do not break the existing test suite.

---

## Running the Application

The application can be executed using:

```bash
python main.py
```

The application:

1. Reads the configured Apache access log
2. Filters requests within the configured read window
3. Groups requests into contiguous timestamp sequences
4. Creates sliding detection windows
5. Applies GET and POST detection rules
6. Identifies IP addresses that meet the configured thresholds
7. Checks whether the IPs are already blocked
8. Creates new Apache block entries
9. Updates the configured `.htaccess` file

---

## Running with Cron

The application is designed to be executed periodically by a scheduler.

A monitoring interval should be chosen based on the configured access-log read window and detection requirements.

For example, if the application is intended to check the log every minute:

```cron
* * * * * /usr/bin/python3 /path/to/apache-access-log-blocker/main.py
```

This executes the application once every minute.

### Sub-Minute Monitoring

Standard cron implementations commonly provide **one-minute granularity**.

Therefore, cron alone is generally not appropriate when the application needs to run every few seconds.

For example, a five-second monitoring interval could be implemented using a process loop:

```bash
while true; do
    /usr/bin/python3 /path/to/apache-access-log-blocker/main.py
    sleep 5
done
```

For production environments, a dedicated process supervisor or `systemd` service/timer is preferable to a manually maintained shell loop.

### Choosing the Schedule

The scheduler interval should work together with the application's read and detection windows.

For example:

```text
Read window:       10 seconds
Detection window:   2 seconds
Scheduler interval: 5 seconds
```

Conceptually:

```text
Every 5 seconds
       │
       ▼
Read previous 10 seconds of logs
       │
       ▼
Evaluate detection windows
       │
       ▼
Block qualifying IPs
```

This overlapping approach helps avoid missing suspicious request bursts between executions.

---

## Production Considerations

Before deploying the application in production:

1. Verify that the Apache log format matches the configured parser indexes.
2. Verify the configured Apache `.htaccess` path.
3. Test generated `.htaccess` rules before enabling automatic blocking.
4. Start with conservative request thresholds.
5. Monitor blocked IP addresses for potential false positives.
6. Run the application using an account with the required file permissions.
7. Test against a copy of the production `.htaccess` before enabling automatic modification.
8. Ensure the Apache configuration supports the generated `Require not ip` directives.
9. Keep a backup of the production `.htaccess` before enabling automatic updates.
10. Consider logging block decisions separately for operational monitoring and auditing.

Automatic IP blocking should be deployed carefully because legitimate clients can sometimes generate unexpected request patterns.

---

## Development History

### Original C++ Version

Approximately **19 years ago**, I developed the original version of this concept using C++.

The original application monitored Apache access logs, identified suspicious request patterns, and automatically blocked IP addresses.

At the time, the project was designed around the tools, architecture, and development practices available to me.

### Python Reimplementation

The current implementation was rebuilt from the ground up in Python.

The goal was not simply to translate the original C++ code into Python.

Instead, the original concept was used as the foundation for a more structured implementation featuring:

* Modular architecture
* Separation of responsibilities
* Configurable detection rules
* Contiguous-second grouping
* Sliding-window detection
* Dedicated GET and POST detection
* URL-based POST detection
* Automated `.htaccess` management
* Duplicate-block prevention
* Unit testing
* Integration testing
* Automated CI testing
* Configuration-driven behavior

This makes the current implementation an **enhanced and modernized version** of the original tool rather than a direct language conversion.

---

## AI-Assisted Development

AI tools were used as a development aid during this project, primarily for:

* Brainstorming and design discussion
* Code review
* Debugging assistance
* Test-case suggestions
* Identifying edge cases
* Documentation refinement

AI assistance was used as a supporting development tool rather than as a replacement for development work.

All architectural decisions, implementation choices, testing, debugging, integration work, and final code validation were performed and reviewed by the author.

The resulting implementation was tested locally using the project's automated test suite, including unit tests and end-to-end integration testing.

---

## Project Goals

The project was developed with several goals:

* Revisit and modernize an older real-world development project
* Demonstrate practical Python backend development
* Apply modular software architecture
* Separate processing and business responsibilities
* Make detection behavior configurable
* Improve testability
* Introduce automated testing
* Demonstrate CI-based test execution
* Provide a practical Apache server automation example

The project represents the evolution of an older C++ solution into a modern Python implementation with improved architecture, testing, and maintainability.

---

## License

See [LICENSE](LICENSE) for licensing information.
