![GitHub license](https://img.shields.io/github/license/neptunehub/jellyfin-plugin-mfa.svg)
![Latest Tag](https://img.shields.io/github/v/tag/neptunehub/jellyfin-plugin-mfa?label=latest-tag)
![Media Server Support: Jellyfin 10.10.7 & 10.11.x](https://img.shields.io/badge/Media%20Server-Jellyfin%2010.10.7%20%26%2010.11.x-blue?style=flat-square&logo=server&logoColor=white)

# Multi-Factor Authentication (MFA) for Jellyfin

<p align="center">
  <img src="https://github.com/NeptuneHub/jellyfin-plugin-mfa/blob/main/mfa.png?raw=true" alt="MFA Logo" width="480">
</p>

Per-user TOTP authentication with single-use recovery codes, enforced at sign-in so a password
alone never grants a session. It also supports Quick Connect for third-party devices.

## Supported versions

Supports **Jellyfin 10.10.7** (ABI 10.10.0.0, .NET 8) **and the latest Jellyfin 10.11.\*** (ABI
10.11.0.0, .NET 9). The plugin catalog serves the right build to each server automatically. The
10.10 build lives on the `main` branch; the 10.11 build on the `10.11` branch.

## What it does

- **Per-user TOTP enrollment.** Scan a QR code (or enter the secret) in any RFC 6238 authenticator
  app and confirm a 6-digit code.
- **Single-use recovery codes.** Ten salted, hashed backup codes, regenerable, each usable once.
- **Enforcement at sign-in.** An enrolled user must provide the second factor every time.
- **Modified web login page.** The standard Jellyfin sign-in page gains a code field, so username,
  password and code are entered together. Users without 2FA leave it blank and sign in as usual.
- **Per-user menu link.** A *Two-Factor Auth* entry is added to the user menu for enrolling and
  managing 2FA (or visit `/Mfa/Setup`).
- **Quick Connect.** For enrolled users it is allowed only when enabled in the admin settings;
  otherwise those sign-ins are blocked until 2FA is completed. Users without 2FA are unaffected.
- **Admin configuration** (Dashboard > Plugins > Multi-Factor Authentication). Set the enforcement
  scope (Optional, Admins only, or Everyone), toggle pre-mint blocking of the native login, toggle
  Quick Connect for enrolled users, review the audit log, and reset or disable a locked-out user
  (which also signs out their active sessions).

Third-party clients (mobile, TV, scripts) use the API directly and are unaffected. A user with no
2FA signs in normally; an enrolled user completes 2FA on the web sign-in page.

The plugin does not trust `X-Forwarded-For` on its own. If Jellyfin runs behind a reverse proxy,
configure Jellyfin's known-proxies / forwarded-headers settings so rate limiting sees the real
client address.

## Crypto Information

All random values use the operating system's secure RNG. There is no MD5, DES, RC4, or ECB mode, and
no SHA-1 except inside TOTP, where RFC 6238 requires it.

| Use | Algorithm | NIST reference |
|---|---|---|
| TOTP secret storage | AES-256-GCM, bound to the user id | FIPS 197, SP 800-38D |
| TOTP codes | HMAC-SHA1, 6 digits, 30s | RFC 6238, SP 800-63B |
| Recovery codes | PBKDF2-HMAC-SHA256, 100k iterations, salted | SP 800-132 |
| Audit log | HMAC-SHA256 with a separate key | FIPS 198-1 |
| Trusted-session tokens | SHA-256, constant-time compare, device-bound | FIPS 180-4 |
| Keys, salts, nonces, tokens | 256-bit from the OS secure RNG | SP 800-90A |

A few notes:

- HMAC-SHA1 in TOTP is safe. The known SHA-1 weakness is about collisions, which do not affect HMAC.
  SHA-1 is kept because it is the only variant every authenticator app supports.
- PBKDF2 stays at 100k iterations on purpose. Recovery codes are random and high-entropy, and each
  attempt checks every stored code, so raising the count adds delay without adding real security.
- Trusted-session tokens are stored only as a hash, never the token itself.

NIST's post-quantum standards (ML-KEM, ML-DSA) replace asymmetric algorithms like RSA and ECC. This
plugin uses none of those, so there is nothing to migrate. Its symmetric ciphers and hashes are
256-bit and already regarded as quantum-safe. Quantum-safe key exchange belongs to the TLS layer,
which Jellyfin or your reverse proxy handles.

## Build locally

Requires the .NET SDK 8.0 (10.10 build) or 9.0 (10.11 build).

```bash
git clone https://github.com/NeptuneHub/jellyfin-plugin-mfa.git
cd jellyfin-plugin-mfa
git checkout 10.11      # only for the Jellyfin 10.11 build (.NET 9); skip for 10.10
.\build.ps1     # Windows
./build.sh      # Linux / macOS
```

You get a ready-to-install package in `dist/Jellyfin.Plugin.Mfa/` (`Jellyfin.Plugin.Mfa.dll`,
`Otp.NET.dll`, `QRCoder.dll`, `meta.json`).

## Release (maintainers)

Maintainers do not need to build or tag releases by hand. In the repository's **Actions** tab, run
the **Build Plugin** workflow and enter the new version (for example `v1.0.1`). It then bumps the
version in the csproj, `meta.json`, and `manifest.json`, builds and zips the plugin with md5 and
sha256 checksums, generates a changelog from the commits since the last release, commits the bump,
and publishes the GitHub Release with the assets attached.

For the **Jellyfin 10.11** build, run the same workflow with **Use workflow from: `10.11`** and the
same version (e.g. `v1.0.4`). It publishes the 10.11 variant (version `X.Y.Z.1`, ABI 10.11.0.0) and
adds it to the shared `manifest.json` on `main` alongside the 10.10 entry.

## Install from a local build

Copy `dist/Jellyfin.Plugin.Mfa/` into Jellyfin's `plugins` folder, then restart Jellyfin.

- **Linux:** `/var/lib/jellyfin/plugins/`
- **Docker:** `/config/plugins/`
- **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\`

## Install from the manifest

1. In Jellyfin, go to **Dashboard > Plugins > Catalog** and open the repository settings (gear icon).
2. Add a repository pointing at:
   ```
   https://raw.githubusercontent.com/NeptuneHub/jellyfin-plugin-mfa/main/manifest.json
   ```
3. Install **Multi-Factor Authentication (MFA)** from the catalog, then restart Jellyfin.
