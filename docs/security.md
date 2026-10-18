# Security

[← FlowTrack](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

- Passwords are stored as scrypt hashes with per-user salt; only SHA-256 digests of session tokens are
  stored. Sessions use an `HttpOnly`, `SameSite=Strict` cookie and expire after 7 days of inactivity.
- Five failed logins from one address within five minutes block further attempts for a while.
- Roles are enforced by the API, not only hidden in the UI.
- The web interface is HTTPS-only (TLS 1.2+). Plain `http://` on the same port is redirected to
  `https://`, and the session cookie is marked `Secure`. The installer creates a self-signed certificate
  (ECDSA P-256, valid 825 days, all host addresses in SAN) and renews it on upgrade when it expires
  within 30 days. Browsers warn about self-signed certificates once — compare the SHA-256 fingerprint
  the installer prints. To use your own certificate, place it at `/etc/flowtrack/tls/cert.pem` and
  `key.pem` (readable by group `flowtrack`) and restart `flowtrack-web`; the installer keeps it.
  `FT_TLS=no` at install time keeps plain HTTP (e.g. behind a TLS reverse proxy — then set
  `X-Forwarded-Proto: https` there).
- The Telegram bot token and the SMTP password are kept in `/var/lib/flowtrack/notify.json` (readable by the service
  only), never sent to the browser and never written to the log.
- ClickHouse listens on `127.0.0.1` only; user filters reach it as bound query parameters.
- Services run as the unprivileged `flowtrack` user with a read-only system (`ProtectSystem=strict`);
  users, sessions and devices added from the UI are stored in `/var/lib/flowtrack`.

## API tokens and webhooks (1.11.0)

- API tokens (`ftapi_…`, 256 random bits) are stored only as SHA-256 in `/var/lib/flowtrack/api_tokens.json` (0600)
  and shown once. They never manage users, tokens or the license, nor delete backups; a *Read only* token changes
  nothing. Wrong tokens share the failed-login limit of the address (5 in 5 minutes). Revoke a leaked one in
  *Settings → API*: it stops working at once.
- Webhook secrets and extra headers stay in `notify.json` (0600), are never sent to the browser or the log; with a
  secret each request is signed (HMAC-SHA256 over the timestamp and the body).

