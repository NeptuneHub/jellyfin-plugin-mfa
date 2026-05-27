# Multi-Factor Authentication (MFA) for Jellyfin

Per-user TOTP authentication with single-use recovery codes, enforced at sign-in so a password
alone never grants a session. It also support quickconnect for third party device.

## Supported version

Targets **Jellyfin 10.10.7 only**, built against the 10.10 server ABI (`TargetAbi` 10.10.0.0) on
.NET 8. Other Jellyfin releases are not supported.

## What it does

- **Per-user TOTP enrollment** — scan a QR code (or enter the secret) in any RFC 6238 authenticator
  app and confirm a 6-digit code.
- **Single-use recovery codes** — ten salted, hashed backup codes, regenerable, each usable once.
- **Enforcement at sign-in** — an enrolled user must provide the second factor every time.
- **Modified web login page** — the standard Jellyfin sign-in page gains a code field, so username,
  password and code are entered together. Users without 2FA leave it blank and sign in as usual.
- **Per-user menu link** — a *Two-Factor Auth* entry is added to the user menu for enrolling and
  managing 2FA (or visit `/Mfa/Setup`).
- **Quick Connect** — for enrolled users it is allowed only when enabled in the admin settings;
  otherwise those sign-ins are blocked until 2FA is completed. Users without 2FA are unaffected.
- **Admin configuration** (Dashboard → Plugins → Multi-Factor Authentication) — set the enforcement
  scope (Optional / Admins only / Everyone), toggle pre-mint blocking of the native login, toggle
  Quick Connect for enrolled users, review the audit log, and reset or disable a locked-out user
  (which also signs out their active sessions).

Third-party clients (mobile, TV, scripts) use the API directly and are unaffected: a user with no
2FA signs in normally; an enrolled user completes 2FA on the web sign-in page.

## Security

- TOTP secrets are stored **AES-256-GCM encrypted**, with the ciphertext cryptographically bound to
  the owning user id so a secret cannot be moved between accounts.
- Recovery codes are stored as **PBKDF2-SHA256 salted hashes**, never in clear text.
- The encryption key file is locked down on every load — `0600` on Unix and a restrictive ACL on
  Windows (current account, SYSTEM, Administrators only).
- TOTP codes are single-use, with a replay floor that survives restarts.
- Secret comparisons are constant-time; verification is protected by per-IP and per-user rate limits
  with account lockout.
- Disabling or resetting a user's 2FA revokes that user's live sessions.

The plugin does not trust `X-Forwarded-For` on its own. If Jellyfin runs behind a reverse proxy,
configure Jellyfin's known-proxies / forwarded-headers settings so rate limiting sees the real
client address.

## Build locally

Requires the .NET SDK 8.0.

```bash
git clone https://github.com/NeptuneHub/jellyfin-plugin-mfa.git
cd jellyfin-plugin-mfa
.\build.ps1     # Windows
./build.sh      # Linux / macOS
```

You get a ready-to-install package in `dist/Jellyfin.Plugin.Mfa/` (`Jellyfin.Plugin.Mfa.dll`,
`Otp.NET.dll`, `QRCoder.dll`, `meta.json`).

## Install from a local build

Copy `dist/Jellyfin.Plugin.Mfa/` into Jellyfin's `plugins` folder, then restart Jellyfin.

- **Linux:** `/var/lib/jellyfin/plugins/`
- **Docker:** `/config/plugins/`
- **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\`

## Install from the manifest

1. In Jellyfin, go to **Dashboard → Plugins → Catalog** and open the repository settings (gear icon).
2. Add a repository pointing at:
   ```
   https://raw.githubusercontent.com/NeptuneHub/jellyfin-plugin-mfa/main/manifest.json
   ```
3. Install **Multi-Factor Authentication (MFA)** from the catalog, then restart Jellyfin.
