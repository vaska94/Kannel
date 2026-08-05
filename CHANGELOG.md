# Changelog

All notable changes to Kamex (formerly Kannel) will be documented in this file.

## [Unreleased]

### Added
- **SNI on outbound TLS connections.** The hostname was passed into
  `conn_open_ssl()` and then discarded, so no `server_name` extension was sent.
  Any server that selects a certificate by name — anything behind Cloudflare or
  sharing an address between virtual hosts — either failed the handshake or
  served the wrong certificate. SNI is now sent for host names and, per RFC 6066,
  omitted for literal addresses.
- **`ssl-verify-host` (core and sqlbox groups, default `false`).** When enabled,
  a server Kamex connects to must present a certificate issued by a trusted CA
  *and* issued for the host that was configured. Literal addresses are matched
  against the certificate's IP SANs. Enabling it implies peer verification,
  falling back to the system CA store when `ssl-trusted-ca-file` is unset.

  Without it, outbound TLS remains unauthenticated: peer verification is off
  unless a CA bundle is configured, and even then **any** valid certificate from
  **any** host was accepted, because nothing compared the certificate to the host
  requested. That affects SMPP over TLS, `dlr-url` callbacks and `sms-service`
  fetches. It defaults to `false` only because turning it on can stop a gateway
  from reaching an SMSC using a self-signed or name-mismatched certificate;
  operators are encouraged to enable it. See `doc/configuration.md`.
- `test/test_http` gained `-N` to require certificate/host matching, so the
  behaviour above can be exercised directly.

## [1.8.5] - 2026-08-05

Fixes mined from the upstream Kannel mailing list archives and Debian's patch
queue. Upstream trunk has been frozen at r5336 (2024-05-14) since before Kamex
forked, so none of these would ever have been fixed there.

### Fixed
- **SMPP delivery receipts with padded fields were parsed wrong, and reported a
  fabricated error code.** The receipt parser required `stat:` and `err:` values
  to follow the label with no space, so a real-world receipt of the form
  `... stat:UNDELIV err: 042 ...` failed the strict parse and fell back to the
  lenient path. That path never assigned the network error code, so **every**
  fallback-parsed receipt reported error `0` regardless of what the SMSC sent.
  Both are fixed: the parser now tolerates whitespace after the label, and the
  fallback path parses the error code it extracted.
- **SMPP receipt status matching is now case-insensitive.** A receipt carrying
  `stat:delivrd` parsed correctly and was then silently reclassified as a
  failure.
- **`reply-couldnotrepresent` was read from the wrong configuration key.** It was
  loaded from `reply-couldnotfetch`, so setting it had no effect while
  `reply-couldnotfetch` silently overrode both messages. Because the correct name
  is declared in the config schema, `-t` validation accepted it and gave no hint.
  Inherited from Kannel; never reported upstream.
- **OpenSMPPBox reported expired messages as accepted.** A missing `break` made
  `DLR_EXPIRED` fall through to `DLR_BUFFERED`, so every expired receipt went out
  as `stat:ACCEPTD` (state 6) instead of `stat:EXPIRED` (state 3). Upstream Kannel
  has the same defect.
- **Build failure on 32-bit time64 targets.** `send_enquire_link()` took a
  `long *` while its caller passed a `time_t *`. Harmless on 64-bit, but an error
  under GCC 14+ on platforms such as Debian i386/armhf, where it would also have
  truncated the enquire-link timer.

### Changed
- `make check` now exits non-zero when a check fails and prints `check.log` to
  stdout. Previously it announced the failure and exited 0, so failing tests
  could pass unnoticed in CI.
- Removed the unused `<openssl/engine.h>` include and `CRYPTO_CALLBACK_PTR`
  typedef; the ENGINE header is gone in OpenSSL 4.0.
- `dbpool_sqlite3` reports the runtime library version via `sqlite3_libversion()`
  instead of the `sqlite3_version` symbol.
- `checks/check.log.new` is no longer tracked; the check runner deleted it on
  every run, leaving the working tree permanently dirty.

## [1.8.4] - 2026-08-05

### Fixed
- **SMPP binds failed with passwords longer than 8 characters** - the SMPP 3.4
  spec caps the bind `password` field at 9 octets, but many commercial operators
  use credentials up to 16 characters. Outbound binds silently truncated the
  configured password to 8 characters (the operator then rejected the bind), and
  inbound binds to OpenSMPPBox with a long password failed with misparsed PDU
  fields. The field limit in the bind PDUs (`bind_transmitter`, `bind_receiver`,
  `bind_transceiver`, `outbind`) is now 17 octets, allowing 16-character
  passwords in both directions. Operators using spec-compliant passwords are
  unaffected. (#1)
- **PostgreSQL DLR storage silently stopped working on PostgreSQL 12+** - the
  driver located single rows with `WHERE oid = (SELECT oid ...)`, but user tables
  have not carried an `oid` system column since PostgreSQL 12 removed
  `default_with_oids`. Both statements failed with
  `column "oid" does not exist`, so:
  - consumed DLRs were never deleted, and the table grew by one row per message
    for the lifetime of the deployment
  - intermediate DLR status updates were never applied
  Delivery receipts still reached the application, which is why this went
  unnoticed. Both statements now use `ctid`, which every server version provides
  and which gives the same "exactly one matching row" guarantee within a single
  statement.

## [1.8.1] - 2026-01-18

### Added
- **Prometheus /metrics endpoint** - Native Prometheus monitoring support
  - Counters: `kamex_sms_sent_total`, `kamex_sms_received_total`, `kamex_dlr_*_total`
  - Gauges: `kamex_uptime_seconds`, `kamex_smsc_online`, `kamex_sms_queue_*`
  - Rates: `kamex_sms_sent_rate`, `kamex_sms_received_rate` (per second)
  - Log queue metrics: `kamex_log_queue_depth`, `kamex_log_dropped_total`
  - No authentication required (standard for metrics endpoints)
- **OpenAPI specification** - Complete API documentation in `doc/openapi.yaml`
  - Admin API endpoints (monitoring, control, SMSC management)
  - SMS API endpoints (sendsms with all parameters)
  - Compatible with Swagger UI and code generators
- **Reproducible builds** - Enterprise-grade build verification and compliance
  - Supports `SOURCE_DATE_EPOCH` for deterministic timestamps
  - `--enable-reproducible` configure flag (auto-enabled with SOURCE_DATE_EPOCH)
  - Strips absolute paths from binaries with `-ffile-prefix-map`
  - Identical SHA256 hashes for same source + environment
  - Docker images: pinned base image digest and EPEL version
  - GitHub Actions CI sets `SOURCE_DATE_EPOCH` automatically
  - Addons (SQLBox, OpenSMPPBox) support reproducible builds
- **Config validation** - Validate configuration files without starting services (nginx-style)
  - `bearerbox -t /etc/kamex/kamex.conf` - test bearerbox config
  - `smsbox -t /etc/kamex/kamex.conf` - test smsbox config
  - Clean output: `bearerbox: configuration file ... test is successful`
  - Returns exit code 0 on success, 1 on failure
  - Useful for CI/CD pipelines and deployment automation
- **Command-line help** - `bearerbox --help` and `smsbox --help` now work
  - Full usage information with all options
  - Examples for common operations
  - See `doc/cli.md` for complete documentation
- **Structured JSON logging** - Machine-readable log format for log aggregation
  - Enable with `log-format = json` in core or smsbox groups
  - Output: `{"ts":"...","level":"info","pid":123,"tid":0,"msg":"..."}`
  - Compatible with ELK, Loki, Splunk, Fluentd, and other log systems
  - See `doc/logging.md` for examples with jq
- **Environment variable expansion** - Reference env vars in config with `${VAR}` syntax
  - `admin-password = ${ADMIN_PASSWORD}` expands from environment
  - Mixed content supported: `host = smsc.${ENV}.example.com`
  - Enables Docker/K8s secrets injection without config changes
  - See `doc/configuration.md` for usage examples
- **SBOM** - CycloneDX 1.7 Software Bill of Materials (`sbom.json`)
  - Runtime dependencies with exact versions from UBI 10
  - Package URLs (PURLs) for vulnerability scanning
  - For security compliance and supply chain verification

## [1.8.0] - 2026-01-12

### Added
- **Async logging** - Log messages are now queued and written by a dedicated writer thread
  - Bounded queue (128K entries, ~512MB max) prevents unbounded growth
  - Calling threads no longer block on I/O - ~10x throughput improvement
  - PANIC level remains synchronous (crash context must hit disk immediately)
  - Per-SMSC exclusive logging preserved via `exclusive_idx` routing
  - 4KB buffer per entry handles 9-segment SMS in hex logs
- **Logging observability** - New monitoring endpoints for log queue health
  - `/health` returns `warn` status when queue >= 80% or messages dropped
  - `/status.json` includes `logging` section with queue depth, dropped count, writer status
- **Architecture documentation** - `doc/logging.md` explains async logging design
- **RPM logrotate** - Logrotate config now included in RPM package

### Fixed
- **Async logging security** - Fixed multiple issues found during security audit:
  - Race condition: capture `log_queue` to local variable before use
  - Memory leak: use `gw_native_free` destructor in `gwlist_destroy`
  - Out-of-bounds: validate `exclusive_idx < num_logfiles` before array access
  - Shutdown race: set `log_queue = NULL` before destroying queue
- **fakesmsc installation** - Now installs real binary instead of libtool wrapper
- **test_headers.c** - Removed WAP/WSP dependencies, now tests HTTP headers only
- **check_sendsms.sh** - Fixed incorrect path and cumulative auth failure count
- **check_headers.sh** - Updated for simplified test_headers
- **run-checks** - Now checks exit codes instead of treating any stderr as failure

### Changed
- Log writer thread uses `gwthread_create()` for proper gwlib integration
- `LogQueueStatus` struct added to `gwlib/log.h` for queue monitoring
- Queue size reduced from 512K to 128K entries (still handles sustained bursts)

## [1.7.8] - 2026-01-12

### Added
- **OpenSMPPBox packaging** - RPM package for kamex-opensmppbox addon
- **OpenSMPPBox systemd service** - `kamex-opensmppbox.service` with security hardening

### Changed
- Modernized OpenSMPPBox configure.ac, removed DocBook build system
- GitHub workflow now builds all 3 packages: kamex, kamex-sqlbox, kamex-opensmppbox

## [1.7.7] - 2026-01-12

### Removed
- **SQLite2 support** - Removed obsolete SQLite 2.x database backend (use SQLite3)
- **libsdb support** - Removed dead libsdb database abstraction library
- Removed ~500 lines of dead code from gwlib, gw, and sqlbox

### Changed
- Cleaned up database pool enum and initialization code
- Updated test_dbpool.c to remove SQLite2 tests

## [1.7.6] - 2026-01-12

### Added
- **SQLBox packaging** - RPM package for kamex-sqlbox addon
- **SQLBox systemd service** - `kamex-sqlbox.service` with security hardening

### Changed
- **Systemd services** - Use `RuntimeDirectory`, `StateDirectory`, `LogsDirectory` for better compatibility
- **Systemd paths** - Service files now use `@SBINDIR@` template for correct paths in both `make install` and RPM

### Fixed
- **Namespace errors** - Fixed `status=226/NAMESPACE` errors in containers/VMs
- **SQLBox build** - Modernized configure.ac, removed DocBook build system

## [1.7.5] - 2026-01-10

### Rebrand
- **Renamed from Kannel to Kamex** due to licensing restrictions
- New MIT license for Kamex code, original Kannel code remains under Kannel Software License 1.0
- Configuration files remain compatible with Kannel
- Systemd service files renamed to `kamex-bearerbox`, `kamex-smsbox`
- Paths changed to `/etc/kamex`, `/var/log/kamex`, etc.

### Added
- **Web Admin Panel** - Built-in dashboard at `/` and `/admin` with real-time monitoring
  - Dashboard with SMS/DLR traffic stats and SMSC status
  - Queue viewer showing pending messages from store-status
  - Send SMS form for testing
  - Gateway controls (suspend/resume/shutdown/restart SMSCs)
  - Auto-refresh toggle (5s/15s/30s/Off)
  - Admin mode vs view-only mode detection
- **JSON API** - Modern REST-like endpoints
  - `/api/sendsms` - POST-only JSON endpoint for sending SMS
  - `/status.json` - JSON status output with rates and SMSC details
  - Token authentication via `X-API-Key` header and `api-token` config
- **Health Check** - `/health` endpoint for load balancers and Kubernetes
- CORS headers for smsbox sendsms endpoint

### Removed
- **libxml2 dependency** - No longer required
- **WAP/WML support** - Removed all WAP-related code and files
- **RADIUS support** - Removed RADIUS authentication
- Legacy platform support (Solaris, Interix3, FreeBSD c_r)
- SVN/CVS artifacts and dead code

### Changed
- Admin panel HTML embedded in binary (no external file needed)
- OpenSSL 1.1+ thread safety test skipped (always thread-safe)
- Modernized autoconf configuration

### Fixed
- JSON SMSC status comma handling for multiple SMSCs
- OpenSSL auto-detection for modern distros
- iconv library detection for Linux systems

## [1.6.5] - 2025-12-01

### Added
- Unix socket support for Redis connections
- Systemd service files with security hardening
- Logrotate configuration
- Performance benchmarks
- GitHub-friendly README.md and markdown documentation

### Changed
- Updated build dependencies for Fedora/EL10
- Replaced bootstrap.sh with standard autoreconf

### Fixed
- OpenSSL detection for modern distros
- gettext m4 macros
- Benchmark scripts

## [1.6.4] and earlier

See the original Kannel changelog for historical changes.
