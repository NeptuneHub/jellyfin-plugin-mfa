# 🔐 Two-Factor Authentication for Jellyfin

Per-user two-factor authentication for Jellyfin: **TOTP authenticator enrollment** with
**single-use recovery codes**, enforced at sign-in for every enrolled user. Nothing else —
no email OTP, no passkeys, no SSO, no IP controls. One focused, security-first plugin.

<p align="center">
  <img src="https://img.shields.io/badge/Jellyfin-10.10.7-00a4dc?style=for-the-badge" />
  <img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tests-51%20passing-00a4dc?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-2b2b2b?style=for-the-badge" />
</p>

---

## What it does

- **Per-user TOTP enrollment.** Users scan a QR code (or enter a key) with any RFC 6238
  authenticator app (Google Authenticator, Authy, 1Password, …) and confirm a 6-digit code.
- **Single-use recovery codes.** Ten PBKDF2-hashed backup codes so a user who loses their
  authenticator can still get in.
- **Enforced at sign-in.** Once enrolled, a user's password alone never yields a usable
  session — they must pass TOTP (or a recovery code) every time.
- **Minimal admin page.** See who is enrolled, and reset/disable 2FA for a locked-out user
  (which also signs out their live sessions).
- **Optional policy.** Require 2FA for everyone, for admins only, or leave it opt-in.

## Compatibility

- **Jellyfin 10.10.x** (built against `Jellyfin.Controller`/`Jellyfin.Model` 10.10.6,
  `TargetAbi` 10.10.0.0). Verified to load on **10.10.7**.
- **.NET 8.**

> Upgrading from the old 2.x "Jellyfin Security" suite is a breaking change — the data model
> was trimmed and legacy secret formats are no longer accepted. **Users must re-enroll.**

## How enforcement works

Two coherent mechanisms guarantee that a password alone is never enough for an enrolled user:

1. **`POST /TwoFactorAuth/Authenticate`** (the path the injected login page uses) validates the
   TOTP/recovery code **before** a session token is ever minted — race-free by construction.
2. A **`SessionStarted` failsafe** covers native clients or anyone hitting Jellyfin's stock
   `/Users/AuthenticateByName` directly: any session a password-only login creates for an
   enrolled (or enforcement-required) user is blocked, and every request on that token is
   rejected with `403` until 2FA is completed.

A small `inject.js` is added to the web UI to route enrolled users through the 2FA login page
and to redirect a blocked session to complete the challenge.

## Security notes (confidentiality & integrity)

- TOTP secrets are stored **AES-256-GCM encrypted**, with the ciphertext **AAD-bound to the
  user id** so a secret can't be swapped between user records. Legacy non-AAD ciphertexts are
  rejected.
- Recovery codes are stored **PBKDF2-SHA256 salted hashes**; unsalted legacy hashes are rejected.
- The persistent encryption key file is locked down on every load — `chmod 0600` on Unix and an
  explicit restrictive DACL on Windows (current account + SYSTEM + Administrators only).
- TOTP codes are single-use with a persisted replay floor that survives restarts.
- Constant-time comparison for all secret checks; per-IP and per-user rate limits plus account
  lockout on the verify/authenticate paths.
- Disabling or resetting 2FA revokes the user's live sessions.

> **Reverse proxies:** this plugin does **not** trust `X-Forwarded-For` itself. If Jellyfin is
> behind a proxy, configure Jellyfin's own forwarded-headers / known-proxies settings so the
> real client IP is what rate-limiting sees.

## Usage

- **Enroll:** open **Two-Factor Auth** from the user menu (or visit `/TwoFactorAuth/Setup`),
  scan the QR code, confirm a code, then generate recovery codes.
- **Sign in:** enrolled users sign in via the 2FA login page (username + password + code).
- **Admin reset:** Dashboard → Plugins → Two-Factor Authentication → **Users** → *Reset 2FA*
  for a user who has lost their authenticator and recovery codes.

## Build

```bash
dotnet build src/Jellyfin.Plugin.TwoFactorAuth -c Release
dotnet test  tests/Jellyfin.Plugin.TwoFactorAuth.Tests
```

Copy the built `Jellyfin.Plugin.TwoFactorAuth.dll` (plus `Otp.NET.dll` and `QRCoder.dll`) into a
`plugins/TwoFactorAuth/` folder in your Jellyfin data directory and restart the server.

## License

MIT
