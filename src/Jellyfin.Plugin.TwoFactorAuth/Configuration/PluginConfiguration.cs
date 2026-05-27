using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.TwoFactorAuth.Configuration;

/// <summary>Scope of 2FA enforcement.</summary>
public enum EnforcementScope
{
    /// <summary>Default. Each user opts in to 2FA from the Setup page. Users
    /// without 2FA enabled sign in normally.</summary>
    Optional = 0,

    /// <summary>2FA is required for Jellyfin administrators. Regular users
    /// remain Optional.</summary>
    Admins = 1,

    /// <summary>2FA is required for every user.</summary>
    All = 2,
}

public class PluginConfiguration : BasePluginConfiguration
{
    public bool Enabled { get; set; } = true;

    /// <summary>Granular 2FA enforcement scope: Optional (per-user opt-in),
    /// Admins (only admins must have 2FA), or All (everyone).</summary>
    public EnforcementScope EnforcementScope { get; set; } = EnforcementScope.Optional;

    /// <summary>Returns true iff this user must have 2FA enabled given the
    /// current policy.</summary>
    public bool ShouldEnforceFor(bool isAdmin)
    {
        return EnforcementScope switch
        {
            EnforcementScope.All => true,
            EnforcementScope.Admins => isAdmin,
            _ => false,
        };
    }

    /// <summary>Lifetime of a challenge token (seconds the user has to enter a
    /// code after their password is accepted). Range enforced at use.</summary>
    public int ChallengeTokenTtlSeconds { get; set; } = 300;

    /// <summary>How long a successful 2FA verification pre-authorizes follow-up
    /// session opens for the same (user, device). Default 120s — covers the
    /// flurry of WebSocket + HTTP sessions Jellyfin spawns right after sign-in.
    /// Clamped to 30-900.</summary>
    public int PreVerifyWindowSeconds { get; set; } = 120;

    public int MaxFailedAttempts { get; set; } = 5;

    public int LockoutDurationMinutes { get; set; } = 15;

    public int AuditLogMaxEntries { get; set; } = 1000;

    /// <summary>What appears in authenticator apps (issuer field of the
    /// otpauth:// URI). Defaults to "Jellyfin".</summary>
    public string TotpIssuerName { get; set; } = "Jellyfin";
}
