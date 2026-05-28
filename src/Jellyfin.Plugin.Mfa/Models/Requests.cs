namespace Jellyfin.Plugin.Mfa.Models;

public class VerifyRequest
{
    public string ChallengeToken { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;

    public string Method { get; set; } = "totp";
}

public class ConfirmTotpRequest
{
    public string Code { get; set; } = string.Empty;
}

/// <summary>Self-service 2FA disable requires re-proving possession of the
/// current second factor (TOTP code or recovery code), so a stolen session
/// token alone can't strip an account's 2FA.</summary>
public class DisableTotpRequest
{
    public string Code { get; set; } = string.Empty;
}

/// <summary>Regenerating recovery codes invalidates the old set and reveals a
/// fresh one, so it requires re-proving possession of the current second factor
/// (TOTP code or recovery code) — a stolen session alone must not be able to
/// rotate and harvest recovery codes.</summary>
public class GenerateRecoveryCodesRequest
{
    public string Code { get; set; } = string.Empty;
}

public class ChallengeTokenRequest
{
    public string ChallengeToken { get; set; } = string.Empty;
}

public class ForcedEnrollmentConfirmRequest
{
    public string ChallengeToken { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;
}

public class ToggleUserRequest
{
    public bool Enabled { get; set; }
}

public class LoginWithCodeRequest
{
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;
}
