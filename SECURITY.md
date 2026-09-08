# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on the
repository. The report is visible only to the maintainers. Include:

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Affected versions (if known)
- Any suggested fix or mitigation

We will acknowledge your report within **48 hours** and provide a fix timeline within **7 business days**. We follow coordinated disclosure -- we ask that you give us a reasonable window to ship a fix before publishing details.

If you do not receive an acknowledgment within 48 hours, open a plain issue that says only that a report is waiting, without details.

## Supported Versions

Only the latest release receives security updates. We do not backport fixes to older versions.

| Version | Supported |
| ------- | --------- |
| Latest  | Yes       |
| < Latest | No       |

## Security Model

Portus has three trust domains with different threat exposure:

**Controller (trusted).** Runs inside the Kubernetes cluster with RBAC-scoped access to Gateway API CRDs. It watches Gateways, HTTPRoutes, GRPCRoutes, TLSRoutes, TCPRoutes and UDPRoutes, reconciles them into a compiled configuration, and pushes that config to the dataplane over a gRPC stream. The controller is trusted infrastructure -- compromise of the controller means compromise of the routing configuration.

**gRPC config stream (must be secured).** The config stream between controller and dataplane carries the full compiled routing configuration, including backend addresses, TLS certificate references, and authentication credentials. It runs over mTLS by default: the Helm chart generates a CA and a controller certificate on first install (`grpcTls.secretName` swaps in your own), the controller presents the certificate and requires client certificates signed by the CA, and it copies the Secret into each Gateway's namespace for the dataplane pods it provisions. `grpcTls.enabled=false` sends the stream in plaintext, which is only acceptable for local development.

**Dataplane (untrusted input).** The Pingora-based proxy handles external traffic from the internet. It is the primary attack surface. All request parsing, path matching, header inspection, and upstream routing happens here. The dataplane trusts only the compiled config it receives from the controller -- it does not access the Kubernetes API directly.

**Cross-namespace isolation** relies on Gateway API ReferenceGrants. Routes in one namespace cannot reference Services or Secrets in another namespace unless a ReferenceGrant in the target namespace explicitly allows it.


## Deployment Hardening Checklist

- **Keep gRPC mTLS on.** `grpcTls.enabled` defaults to `true`; leave it. To use your own CA, set `grpcTls.secretName` to a Secret with `ca.crt`, `tls.crt`, `tls.key` whose certificate names the controller Service.
- **Never set `GRPC_TLS_INSECURE=true` in production.** This flag disables TLS certificate verification on the gRPC stream. It exists for local development only.
- **Never run with `RUST_LOG=trace` in production.** Pingora's HTTP layer logs full request headers at trace level, which can include `Authorization` headers and other credentials.
- **Restrict access to controller port 50051.** Use a Kubernetes NetworkPolicy to ensure only dataplane pods can reach the controller's gRPC port.
- **Use ReferenceGrants for cross-namespace references.** Do not rely on namespace boundaries alone -- create explicit ReferenceGrant resources to control which routes can reference which backends and secrets.
- **Monitor `proxy_tls_cert_expiry_seconds`.** This metric tracks time until TLS certificate expiration on each listener. Alert before certificates expire.
- **Monitor `proxy_circuit_breaker_state`.** This metric surfaces upstream service health. A persistent open state indicates a backend is failing and traffic is being shed.

## Security Features

Portus's dataplane includes the following security controls:

**TLS.** TLS 1.2+ only, implemented with rustls backed by aws-lc-rs (FIPS-capable). No OpenSSL dependency. Certificate selection is SNI-based, with per-listener TLS configuration compiled from Kubernetes Secret references.

**Authentication.** Password verification uses bcrypt with timing-safe comparison via the `subtle` crate, preventing timing side-channel attacks. Credential material is zeroized on drop to limit exposure in memory.

**Header injection prevention.** CRLF sequences in header values are rejected to prevent HTTP response splitting and header injection attacks.

**IP spoofing prevention.** `X-Forwarded-For` handling uses the rightmost-untrusted-hop strategy, which is resistant to spoofing by upstream clients that prepend fake entries to the XFF chain.

**Rate limiting and circuit breakers.** Per-route rate limiting and per-backend circuit breakers are configurable through Gateway API policy resources.

**Request body size limits.** Configurable maximum request body size prevents resource exhaustion from oversized payloads.

**Regex safety.** All regex patterns used in route matching are pre-compiled at config load time and bounded in size to prevent ReDoS attacks.
