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

## Crypto Information

Every cryptographic primitive used by the plugin, mapped to the relevant NIST standard. All random
values come from the OS CSPRNG (`RandomNumberGenerator`); no insecure `System.Random` is used
anywhere, and there is no MD5, SHA-1 outside the RFC-mandated TOTP, DES/3DES/RC4, ECB mode, or
static IV/nonce.

| Where used | Algorithm | NIST standard | Quantum-safe? | Status |
|---|---|---|---|---|
| TOTP secret at rest | AES-256-GCM (256-bit key, 96-bit random nonce, 128-bit tag), AAD-bound to user id | FIPS 197 + SP 800-38D | Yes (AES-256) | Maximum — no stronger option |
| TOTP code generation | HMAC-SHA1, 6 digits, 30 s (RFC 6238 default) | SP 800-63B (TOTP); HMAC-SHA1 allowed by SP 800-107 | Yes (symmetric) | Kept for authenticator-app compatibility; HMAC-SHA1 is not broken (SHA-1 collisions don't affect HMAC) |
| Recovery codes at rest | PBKDF2-HMAC-SHA256, 100k iterations, 128-bit salt | SP 800-132 | Yes | Sufficient — codes are high-entropy (~49 bits) and verification loops all codes, so higher iteration counts add latency/DoS, not security |
| Audit-log hash chain | HMAC-SHA256, separate keyed file | FIPS 198-1 + 180-4 | Yes | Strong — tamper-evident |
| Access-token verification (trusted sessions) | SHA-256 + constant-time compare (`FixedTimeEquals`), device-bound | FIPS 180-4 | Yes (256-bit) | Correct for a high-entropy token; only the hash is stored, never the token |
| Keys, salts, nonces, challenge tokens | 256-bit random via OS CSPRNG | SP 800-90A | n/a | Maximum-practical |
| Key establishment / digital signatures (asymmetric) | none used | ML-KEM / ML-DSA (FIPS 203 / 204) | — | Not applicable — no asymmetric crypto to migrate |

**Post-quantum note.** NIST's PQC standards — **ML-KEM** (FIPS 203), **ML-DSA** (FIPS 204) and
**SLH-DSA** (FIPS 205) — replace *asymmetric* algorithms (RSA, ECDSA, ECDH), the only ones broken by
Shor's algorithm. This plugin uses **no asymmetric cryptography**, so there is nothing to migrate.
Its symmetric ciphers and hashes are only marginally affected by Grover's algorithm, and at
256-bit (AES-256, SHA-256/HMAC-SHA256) are already considered quantum-resistant per NISTIR 8105.
Post-quantum key exchange, where it eventually matters, lives in the **TLS transport** handled by
Jellyfin / your reverse proxy — outside this plugin.

This is a source-level mapping to published standards, not a formal FIPS validation or third-party
cryptographic audit.

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
