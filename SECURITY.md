# Security Policy

## Supported version

This plugin targets **Jellyfin 10.10.7** (ABI 10.10.0.0). Only the latest
released version of the plugin, running on a 10.10.x server, is supported for
security fixes.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue and do
not include exploit details in a public bug report.

Use GitHub's private reporting: open the repository's **Security → Report a
vulnerability** ("Report a vulnerability" / private advisory) at
<https://github.com/NeptuneHub/jellyfin-plugin-mfa/security/advisories/new>.

Please include the plugin version, your Jellyfin server version, and the steps
to reproduce. You'll get an acknowledgement and a fix timeline once the report
is triaged. Coordinated disclosure is appreciated: give a reasonable window for
a fix before any public write-up.

## Security model (summary)

This plugin's goal is to **increase** account security without weakening any
existing Jellyfin protection.

- **TOTP secrets** are stored AES-256-GCM encrypted, with the user id bound in as
  AAD, so a file-system attacker cannot swap secret blobs between users.
- **Recovery codes** are stored PBKDF2-SHA256 (salted, 100k iterations) and
  verified in constant time. Each code is single-use and consumed atomically.
- **Enforcement** happens in two layers: native login endpoints are refused
  *before* a token is minted for any user who must satisfy 2FA, and a
  `SessionStarted` failsafe revokes any unverified session that slips past
  (e.g. Quick Connect, third-party auth plugins).
- **Replay protection**: a used TOTP time-step is rejected in-memory and via a
  persisted floor that survives restarts.
- **Audit log** is an HMAC-SHA256 hash-chain keyed with a file separate from the
  TOTP encryption key.

## Operational requirements (read this)

### 1. Behind a reverse proxy? Configure Jellyfin's forwarded headers.

The plugin's per-IP rate limiting and the IP recorded in the audit log come from
the **direct TCP peer address**. The plugin deliberately does **not** trust
`X-Forwarded-For` on its own (a client can forge it).

If Jellyfin sits behind nginx / SWAG / Caddy / Traefik / Cloudflare and you have
**not** told Jellyfin about the proxy, every request appears to come from the
proxy's IP. Then all clients share one rate-limit bucket (one abusive client can
rate-limit everyone, and per-attacker throttling becomes ineffective) and
audit-log IPs are wrong.

**Fix:** in **Dashboard → Networking**, set **Known proxies** so the request's
remote address reflects the real client. The per-account lockout and per-challenge
attempt caps still bound brute force without this, but per-IP defenses depend on
it.

### 2. Account lockout is intentional — and can be used to deny service.

After repeated **wrong second-factor codes**, an account is locked out for
`LockoutDurationMinutes` (default 15).

- A wrong **password** does **not** count toward this 2FA lockout (Jellyfin has
  its own password-attempt throttling). This prevents an unauthenticated attacker
  who merely knows a username from locking the account out at will.
- Wrong **codes** require the correct password to reach, so only someone who
  already holds the password can trip the 2FA lockout. Admins can clear a lockout
  from the plugin's admin page (Unlock).

### 3. Key files must stay readable only by the Jellyfin service account.

The plugin writes `secret.key` and `audit.key` under the plugin data directory and
re-locks their permissions on every load (chmod 0600 on Unix; a restrictive DACL on
Windows). On a shared host, ensure the plugin data directory itself is not
world-readable. Back these keys up securely — losing `secret.key` makes every
enrolled TOTP secret undecryptable (users must re-enroll).

### 4. Trusted-session window is a bearer-token trade-off.

A device that has completed 2FA stays trusted for `TrustedSessionDays` (default 30,
sliding) so a restart doesn't force every TV/phone to re-authenticate. Trust is a
hash of the access token bound to the device id. A token *and* its device id stolen
together would be honored for the rest of that window; lower `TrustedSessionDays`
if your threat model requires it. Trust is wiped on 2FA disable/reset, which also
logs out the user's live sessions.

### 5. Quick Connect pass-through is off by default.

`AllowQuickConnectForEnrolledUsers` (default **off**) lets an already-2FA-verified
user complete a Quick Connect login without re-entering a code. Leave it off unless
you accept that it relaxes the second-factor requirement for Quick Connect.

### 6. Keep pre-mint blocking enabled.

`BlockNativeLoginForEnforcedUsers` (default **on**) refuses native login endpoints
before a token is minted for enforced users. Disabling it falls back to
block-after-mint, which has a brief window where a freshly minted token is live
before the failsafe revokes it. Leave it on.
