# lockrail-proxy

Local HTTPS intercepting proxy for Lockrail. Scans outbound AI API requests and
inbound responses for secrets, replacing them with safe handles before the model
ever sees them.

Used by `lockrail proxy start`.
