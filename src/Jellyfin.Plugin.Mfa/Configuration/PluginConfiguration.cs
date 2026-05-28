using System.Collections.Generic;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.Mfa.Configuration;

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

    /// <summary>When true (default), the native Jellyfin login endpoints
    /// (<c>/Users/AuthenticateByName</c> and <c>/Users/{id}/Authenticate</c>)
    /// are refused with 403 BEFORE a session token is minted, for any user who
    /// must satisfy 2FA (already enrolled, or required by <see cref="EnforcementScope"/>).
    /// This closes the brief window in which a password-only token is usable
    /// before the SessionStarted failsafe blocks it — enrolled users get the
    /// stronger pre-mint guarantee. Users with no 2FA obligation are unaffected
    /// and log in normally on every client (web, TV, mobile). Set false to fall
    /// back to block-after-mint behaviour only.</summary>
    public bool BlockNativeLoginForEnforcedUsers { get; set; } = true;

    /// <summary>When true, an enrolled user may complete a Quick Connect login
    /// without entering a TOTP/recovery code. Authorizing a Quick Connect request
    /// already requires an existing signed-in session, and under 2FA enforcement
    /// that session was itself 2FA-verified — so the second factor was effectively
    /// provided at approval time. Default false: Quick Connect sessions for
    /// enrolled users are revoked by the SessionStarted failsafe like any other
    /// login that hasn't completed 2FA. Users with no 2FA obligation can always
    /// use Quick Connect, regardless of this setting. Note this relaxation applies
    /// only to already-<em>enrolled</em> users; a user who is merely required to
    /// have 2FA (by <see cref="EnforcementScope"/>) but hasn't enrolled is still
    /// forced through enrollment.</summary>
    public bool AllowQuickConnectForEnrolledUsers { get; set; }

    /// <summary>How long (days) a device that has completed 2FA stays trusted, so a
    /// Jellyfin restart doesn't force every device to re-authenticate. The window
    /// SLIDES: it's refreshed each time the device is used, so a regularly-used
    /// device never re-prompts, while one left idle past this window re-does 2FA
    /// once. Trust is stored as a hash of the access token bound to the device,
    /// and is wiped on 2FA disable/reset. Clamped to 1–365; default 30.</summary>
    public int TrustedSessionDays { get; set; } = 30;

    /// <summary>CIDR ranges (one per entry) of reverse proxies allowed to set
    /// <c>X-Forwarded-For</c>. When a request arrives from an IP inside any of
    /// these ranges, the real client IP is taken from the rightmost untrusted
    /// hop in the XFF header — used for rate-limit keying and audit logging.
    /// When this list is empty (default), XFF is ignored and the TCP peer IP
    /// is used directly: that's correct for direct-to-internet deployments,
    /// but behind a proxy it causes every request to share one bucket so one
    /// brute-forcer can 429 every other user.
    /// <para>Examples: <c>127.0.0.1/32</c>, <c>10.0.0.0/8</c>, <c>172.16.0.0/12</c>,
    /// <c>192.168.0.0/16</c>, <c>::1/128</c>. For Cloudflare add the published
    /// edge prefixes (e.g. <c>173.245.48.0/20</c>, <c>103.21.244.0/22</c>, …).</para>
    /// <para>SECURITY: only add ranges you control end-to-end. A trusted proxy is
    /// taken at its word; if an attacker can forge XFF from inside a trusted
    /// CIDR they can spoof their per-IP rate-limit bucket and audit IP.
    /// Direct-to-internet servers should leave this empty.</para>
    /// </summary>
    public List<string> TrustedProxyCidrs { get; set; } = new();
}
