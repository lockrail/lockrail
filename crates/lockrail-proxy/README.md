# lockrail-proxy

Local HTTPS intercepting proxy for Lockrail. Scans supported outbound AI API
requests and inbound responses for secrets, replacing them with safe handles
before the model sees them.

The proxy rewrites only uncompressed textual/JSON bodies where updating HTTP
headers is safe. Streaming, compressed, unknown binary, and unsupported-host
traffic is passed through unchanged instead of being corrupted.

Used by `lockrail proxy start`.
