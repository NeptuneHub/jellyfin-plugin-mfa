using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.Mfa.Models;

public class TwoFactorRequiredResponse
{
    public bool TwoFactorRequired { get; set; } = true;

    public string ChallengeToken { get; set; } = string.Empty;

    public List<string> Methods { get; set; } = new();

    public bool EnrollmentRequired { get; set; }

    public string ChallengePageUrl { get; set; } = string.Empty;

    public string EnrollmentPageUrl { get; set; } = string.Empty;
}

public class VerifyResponse
{
    public string AccessToken { get; set; } = string.Empty;
}

public class TotpSetupResponse
{
    public string SecretKey { get; set; } = string.Empty;

    public string QrCodeBase64 { get; set; } = string.Empty;

    public string ManualEntryKey { get; set; } = string.Empty;
}

public class ChallengeInfoResponse
{
    public string Username { get; set; } = string.Empty;

    public List<string> Methods { get; set; } = new();

    public bool EnrollmentRequired { get; set; }

    public DateTime ExpiresAt { get; set; }
}

public class UserTwoFactorStatus
{
    public Guid UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public bool TotpEnabled { get; set; }

    public int RecoveryCodesRemaining { get; set; }

    public bool IsLockedOut { get; set; }
}
