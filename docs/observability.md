# Logging and observability

XrefGen runs inside IDA Pro and has no always-on server or external telemetry service. The presentation logger in `modules/presentation/logger.py` is the shared boundary; application and analysis code should emit through its `trace`, `debug`, `info`, `warn`, `error`, or `critical` functions.

Events are one JSON object per line with an ISO-8601 UTC timestamp, normalized level, service (`xrefgen`), component, and message. Control characters are flattened, and common credential assignments plus bearer credentials are redacted. Do not put binary contents, full request/file contents, secrets, or unnecessary personal data in messages. Exceptions should be summarized without sensitive values.

`general.log_level` accepts `trace`, `debug`, `info`, `warn`, `error`, `fatal`, or `critical`. The default is `info`. `general.log_file` optionally enables a UTF-8 rotating file sink (5 MB per file, three backups); stdout remains available to IDA's console. No network destination, external service, or telemetry dependency is required. Python's logging handlers serialize concurrent writes; avoid configuring the logger from worker code.

Use INFO for lifecycle transitions and counts, WARN for recoverable degradation (such as invalid configuration or cache fallback), ERROR for failed operations, and CRITICAL/FATAL only when the plugin cannot continue. DEBUG and TRACE are for opt-in diagnosis. Avoid duplicate exception reports across layers.

The plugin currently has no distributed requests, queues, or background service requiring W3C trace context or OpenTelemetry. Correlation identifiers and metrics are therefore not generated. For new analysis flows, include a stable operation name and relevant module/count/duration fields in the message, never invented trace identifiers. Run `pytest -q tests/test_presentation_logger.py` for the logger's structured output, filtering, injection, rotation, and configuration checks.
