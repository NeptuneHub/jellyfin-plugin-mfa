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
