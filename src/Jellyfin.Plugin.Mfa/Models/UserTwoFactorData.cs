using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.Mfa.Models;

/// <summary>
/// Per-user 2FA state. Persisted as users/{userId}.json. Only TOTP + single-use
/// recovery codes are supported; the secret is stored AES-GCM encrypted (AAD-bound
/// to the user id) and recovery codes are stored PBKDF2-hashed. No plaintext
/// secret ever touches disk.
/// </summary>
public class UserTwoFactorData
{
    public Guid UserId { get; set; }

    /// <summary>True once the user has a confirmed TOTP secret. Always read
    /// together with <see cref="TotpVerified"/> — never on its own — so a
    /// half-enrolled account (secret stashed but never confirmed) is treated
    /// as having no second factor rather than being locked out.</summary>
    public bool TotpEnabled { get; set; }

    public bool TotpVerified { get; set; }

    /// <summary>AES-256-GCM encrypted TOTP secret, "v2:" + base64(nonce|ct|tag),
    /// AAD-bound to <see cref="UserId"/>. Null when 2FA is not enrolled.</summary>
    public string? EncryptedTotpSecret { get; set; }

    public int FailedAttemptCount { get; set; }

    public DateTime? LockoutEnd { get; set; }

    public List<RecoveryCode> RecoveryCodes { get; set; } = new();

    public DateTime? RecoveryCodesGeneratedAt { get; set; }

    /// <summary>Highest TOTP time-step ever accepted for this user. Persisted
    /// across restarts so a code captured before a restart can't be replayed
    /// once the in-memory replay cache is empty. Monotonically increases.</summary>
    public long LastUsedTotpStep { get; set; }

    /// <summary>Sessions that have completed 2FA, persisted so a server restart
    /// doesn't force every device (TV, phone, …) to re-authenticate. Stores only a
    /// hash of the access token — never the token itself — bound to the device id,
    /// with a sliding expiry. Cleared on 2FA disable/reset.</summary>
    public List<VerifiedSession> VerifiedSessions { get; set; } = new();
}

/// <summary>A persisted record that a specific access token already cleared 2FA.
/// The token is stored only as a SHA-256 hash (base64); pairing it with the
/// device id means a stolen token replayed from a different device still
/// re-prompts. <see cref="ExpiresAt"/> slides forward on each use.</summary>
public class VerifiedSession
{
    /// <summary>Base64 SHA-256 of the Jellyfin access token. Never the token.</summary>
    public string TokenHash { get; set; } = string.Empty;

    public string? DeviceId { get; set; }

    public string? DeviceName { get; set; }

    public DateTime VerifiedAt { get; set; }

    public DateTime ExpiresAt { get; set; }
}

public class RecoveryCode
{
    /// <summary>PBKDF2-SHA256 hash, format "v2$iter$saltB64$hashB64".</summary>
    public string Hash { get; set; } = string.Empty;

    public bool Used { get; set; }

    public DateTime? UsedAt { get; set; }
}
