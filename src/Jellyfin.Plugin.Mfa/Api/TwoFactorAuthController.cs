using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Data.Enums;
using Jellyfin.Plugin.Mfa.Models;
using Jellyfin.Plugin.Mfa.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Mfa.Api;

/// <summary>
/// Endpoints for per-user TOTP + recovery-code 2FA: enrollment (self-service and
/// policy-forced), the sign-in challenge/verify flow, and a minimal admin surface
/// (status list, reset/disable, audit log). Everything else the plugin used to
/// expose (email OTP, passkeys, device pairing, app passwords, OIDC, IP controls)
/// has been removed.
/// </summary>
[ApiController]
[Route("Mfa")]
[Produces(MediaTypeNames.Application.Json)]
public class TwoFactorAuthController : ControllerBase
{
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly TotpService _totpService;
    private readonly RecoveryCodeService _recoveryCodes;
    private readonly RateLimiter _rateLimiter;
    private readonly SessionTerminationService _sessionTerm;
    private readonly ISessionManager _sessionManager;
    private readonly IUserManager _userManager;
    private readonly ILogger<TwoFactorAuthController> _logger;

    public TwoFactorAuthController(
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        TotpService totpService,
        RecoveryCodeService recoveryCodes,
        RateLimiter rateLimiter,
        SessionTerminationService sessionTerm,
        ISessionManager sessionManager,
        IUserManager userManager,
        ILogger<TwoFactorAuthController> logger)
    {
        _store = store;
        _challengeStore = challengeStore;
        _totpService = totpService;
        _recoveryCodes = recoveryCodes;
        _rateLimiter = rateLimiter;
        _sessionTerm = sessionTerm;
        _sessionManager = sessionManager;
        _userManager = userManager;
        _logger = logger;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Guid GetCurrentUserId()
    {
        var claim = User.FindFirst("Jellyfin-UserId");
        if (claim != null && Guid.TryParse(claim.Value, out var userId))
        {
            return userId;
        }

        throw new UnauthorizedAccessException();
    }

    private string ClientIp() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    // SEC S4: a submitted code is at most 6 chars (TOTP) or ~14 (recovery), and a
    // challenge token is ~43 chars (base64url of 32 bytes). Reject anything wildly
    // longer before it reaches PBKDF2 (recovery verify hashes the input once per
    // stored code) so an oversized body can't amplify into CPU.
    private const int MaxCodeLength = 64;
    private const int MaxTokenLength = 128;

    private static bool FieldTooLong(string? code, string? token = null)
        => (code is not null && code.Length > MaxCodeLength)
            || (token is not null && token.Length > MaxTokenLength);

    private bool IsAdmin(Guid userId)
    {
        try
        {
            return _userManager.GetUserById(userId)?.HasPermission(PermissionKind.IsAdministrator) ?? false;
        }
        catch
        {
            return false;
        }
    }

    private static int FindRecoveryCodeIndex(UserTwoFactorData userData, string submitted)
    {
        var normalized = RecoveryCodeService.NormalizeForCompare(submitted);
        // Iterate in constant time relative to the user's code count — don't
        // early-return on match so timing can't reveal which index matched.
        int found = -1;
        for (int i = 0; i < userData.RecoveryCodes.Count; i++)
        {
            var stored = userData.RecoveryCodes[i];
            if (stored.Used) continue;
            if (RecoveryCodeService.Verify(normalized, stored.Hash) && found < 0)
            {
                found = i;
            }
        }
        return found;
    }

    private IActionResult ServeEmbeddedPage(string filename)
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.{filename}";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return NotFound();
        }

        using var reader = new System.IO.StreamReader(stream);
        var html = reader.ReadToEnd();

        // Anti-clickjacking: /Setup reveals the QR secret + recovery codes on
        // screen and /Challenge is a credential-entry surface. frame-ancestors
        // 'none' is the modern X-Frame-Options: DENY; send both.
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["Content-Security-Policy"] = "frame-ancestors 'none'";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content(html, "text/html; charset=utf-8");
    }

    private void UnblockAccessTokenFromPendingAuthResponse(string pendingAuthResponse, string username)
    {
        if (string.IsNullOrEmpty(pendingAuthResponse))
        {
            return;
        }

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(pendingAuthResponse);
            if (doc.RootElement.TryGetProperty("AccessToken", out var tokenElement)
                && tokenElement.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var token = tokenElement.GetString();
                if (!string.IsNullOrEmpty(token))
                {
                    _challengeStore.UnblockToken(token);
                    _challengeStore.MarkTokenVerified(token);
                    _logger.LogInformation("[2FA] Unblocked access token for {User} after successful 2FA", username);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Could not parse stashed auth response to unblock token");
        }
    }

    // -------------------------------------------------------------------------
    // Static pages / asset
    // -------------------------------------------------------------------------

    [HttpGet("Challenge")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetChallengePage() => ServeEmbeddedPage("challenge.html");

    [HttpGet("Setup")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetSetupPage() => ServeEmbeddedPage("setup.html");

    [HttpGet("Login")]
    [AllowAnonymous]
    [Produces("text/html")]
    public IActionResult GetLoginPage() => ServeEmbeddedPage("login.html");

    [HttpGet("inject.js")]
    [AllowAnonymous]
    public IActionResult GetInjectScript()
    {
        var assembly = typeof(Plugin).Assembly;
        var resourceName = $"{typeof(Plugin).Namespace}.Pages.inject.js";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            return NotFound();
        }

        using var reader = new System.IO.StreamReader(stream);
        var js = reader.ReadToEnd();
        Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        Response.Headers.Pragma = "no-cache";
        Response.Headers.Expires = "0";
        return Content(js, "application/javascript; charset=utf-8");
    }

    // -------------------------------------------------------------------------
    // Challenge info
    // -------------------------------------------------------------------------

    [HttpGet("Challenge/Info")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(ChallengeInfoResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ActionResult<ChallengeInfoResponse> GetChallengeInfo([FromQuery] string token)
    {
        var challenge = _challengeStore.GetChallenge(token);
        if (challenge is null)
        {
            return BadRequest(new { message = "Invalid or expired challenge." });
        }

        return Ok(new ChallengeInfoResponse
        {
            Username = challenge.Username,
            Methods = challenge.AvailableMethods,
            EnrollmentRequired = challenge.EnrollmentRequired,
            ExpiresAt = challenge.ExpiresAt,
        });
    }

    // -------------------------------------------------------------------------
    // Forced enrollment (EnforcementScope = Admins/All): user has no 2FA yet
    // and must enroll before their session is released.
    // -------------------------------------------------------------------------

    [HttpPost("Enroll/Totp/Begin")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(TotpSetupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TotpSetupResponse>> BeginForcedTotpEnrollment([FromBody, Required] ChallengeTokenRequest request)
    {
        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null || !challenge.EnrollmentRequired)
        {
            return BadRequest(new { message = "Invalid or expired enrollment challenge." });
        }

        var rl = _rateLimiter.CheckAndRecord("enroll_begin:" + request.ChallengeToken, 5, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many setup attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        if (userData.TotpVerified)
        {
            return BadRequest(new { message = "This account already has a second factor." });
        }

        var (secret, qrCodeBase64, manualEntryKey) = _totpService.GenerateSecret(challenge.Username);
        // Stash the secret only. TotpEnabled/Verified flip on Confirm so a user
        // who abandons setup isn't left half-enrolled (which would gate them out).
        userData.TotpVerified = false;
        userData.EncryptedTotpSecret = _totpService.EncryptSecret(secret, challenge.UserId);
        userData.LastUsedTotpStep = 0;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        _totpService.ResetReplayCache(challenge.UserId.ToString());

        return Ok(new TotpSetupResponse
        {
            SecretKey = secret,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = manualEntryKey,
        });
    }

    [HttpPost("Enroll/Totp/Confirm")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ConfirmForcedTotpEnrollment([FromBody, Required] ForcedEnrollmentConfirmRequest request)
    {
        if (FieldTooLong(request.Code, request.ChallengeToken))
        {
            return BadRequest(new { message = "Field too long." });
        }

        var clientIp = ClientIp();
        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null || !challenge.EnrollmentRequired)
        {
            return BadRequest(new { message = "Invalid or expired enrollment challenge." });
        }

        if (challenge.AttemptCount >= 5)
        {
            _challengeStore.ConsumeChallenge(request.ChallengeToken);
            return Unauthorized(new { message = "Too many failed attempts on this challenge. Restart sign-in." });
        }

        var rl = _rateLimiter.CheckAndRecord("enroll_confirm:" + clientIp, 10, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            return BadRequest(new { message = "TOTP setup has not been started." });
        }

        string secret;
        try
        {
            secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, challenge.UserId);
        }
        catch
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { message = "TOTP secret is corrupted. Restart setup." });
        }

        var valid = _totpService.ValidateCode(
            secret, request.Code, challenge.UserId.ToString(), persistedFloor: 0, out var acceptedStep);
        if (!valid)
        {
            challenge.IncrementAttempts();
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            return Unauthorized(new { message = "Invalid authenticator code." });
        }

        userData.TotpEnabled = true;
        userData.TotpVerified = true;
        userData.LastUsedTotpStep = acceptedStep;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
        _rateLimiter.Reset("enroll_confirm:" + clientIp);

        if (!string.IsNullOrEmpty(challenge.DeviceId))
        {
            _challengeStore.MarkDevicePreVerified(challenge.UserId, challenge.DeviceId);
            // Enrollment done — drop the block-only guard so the (user, device) is
            // governed normally again.
            _challengeStore.ClearEnrollmentInProgress(challenge.UserId, challenge.DeviceId);
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = challenge.UserId,
            Username = challenge.Username,
            RemoteIp = challenge.RemoteIp ?? clientIp,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = "forced_enroll_totp",
        }).ConfigureAwait(false);

        if (string.IsNullOrEmpty(challenge.PendingAuthResponse))
        {
            return Ok(new { message = "Two-factor setup complete. Sign in again to continue." });
        }

        UnblockAccessTokenFromPendingAuthResponse(challenge.PendingAuthResponse, challenge.Username);
        return Content(challenge.PendingAuthResponse, "application/json");
    }

    // -------------------------------------------------------------------------
    // POST /Authenticate — username + password + (optional) TOTP/recovery in one call.
    // This is the primary, race-free enforcement path: the code is verified
    // BEFORE a session is minted.
    // -------------------------------------------------------------------------

    [HttpPost("Authenticate")]
    [AllowAnonymous]
    public async Task<IActionResult> AuthenticateWithCode([FromBody] LoginWithCodeRequest req)
    {
        try
        {
            var clientIp = ClientIp();
            var rl = _rateLimiter.CheckAndRecord("auth:" + clientIp, 10, TimeSpan.FromMinutes(1));
            if (!rl.allowed)
            {
                Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
                    retryAfterSeconds = rl.retryAfterSeconds,
                });
            }

            if (req is null || string.IsNullOrEmpty(req.Username) || string.IsNullOrEmpty(req.Password))
            {
                return BadRequest(new { message = "Username and password are required." });
            }

            // Cap field lengths so an unbounded body can't burn server CPU in
            // Jellyfin's internal PBKDF2 password check.
            if (req.Password.Length > 1024
                || req.Username.Length > 256
                || (req.Code is not null && req.Code.Length > 64))
            {
                return BadRequest(new { message = "Field too long." });
            }

            _logger.LogInformation("[2FA] /Authenticate username={Name} codeProvided={Has}",
                req.Username, !string.IsNullOrEmpty(req.Code));

            var user = _userManager.GetUserByName(req.Username);
            if (user is null)
            {
                return Unauthorized(new { message = "Invalid username or password." });
            }

            var userData = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);

            if (await _store.IsLockedOutAsync(user.Id).ConfigureAwait(false))
            {
                var remaining = userData.LockoutEnd.HasValue
                    ? Math.Max(0, (int)(userData.LockoutEnd.Value - DateTime.UtcNow).TotalSeconds)
                    : 900;
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = "Account is locked out due to too many failed attempts.",
                    lockoutRemainingSeconds = remaining,
                });
            }

            var totpEnabled = userData.TotpEnabled && userData.TotpVerified;
            var config = Plugin.Instance?.Configuration;
            var requiresPostPasswordChallenge = !totpEnabled
                && config is not null
                && config.ShouldEnforceFor(IsAdmin(user.Id));

            var codeConsumedRecovery = false;

            // SEC S1: one identical response for every credential failure (wrong
            // password, missing code, wrong code) so neither the wording nor the
            // timing reveals whether an account has 2FA enabled.
            const string uniformFailMessage = "Invalid username, password, or verification code.";

            // --- Step 1: verify the PASSWORD first, WITHOUT minting a session.
            // AuthenticateUser runs Jellyfin's PBKDF2 for every existing user
            // regardless of 2FA state, closing the timing side-channel that
            // otherwise let an attacker distinguish 2FA from non-2FA accounts
            // (SEC S1). The session/token is only minted later, by
            // AuthenticateNewSession, after the code is verified — preserving the
            // "no usable token until 2FA passes" invariant. ---
            bool passwordValid;
            try
            {
                var authedUser = await _userManager
                    .AuthenticateUser(req.Username, req.Password, clientIp, isUserSession: true)
                    .ConfigureAwait(false);
                passwordValid = authedUser is not null;
            }
            catch (MediaBrowser.Controller.Authentication.AuthenticationException)
            {
                passwordValid = false;
            }

            if (!passwordValid)
            {
                await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                return Unauthorized(new { message = uniformFailMessage });
            }

            // --- Step 2: password is correct. If the user has 2FA, verify the
            // code now. The recovery code is consumed ONLY here, after the
            // password is proven, so an attacker holding a recovery code but not
            // the password can no longer burn the victim's codes (SEC S2). ---
            if (totpEnabled)
            {
                if (string.IsNullOrEmpty(req.Code))
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                    return Unauthorized(new { message = uniformFailMessage });
                }

                bool codeValid = false;

                var maybeRecovery = req.Code.Replace("-", string.Empty).Replace(" ", string.Empty);
                if (maybeRecovery.Length >= 8 && maybeRecovery.All(char.IsLetterOrDigit))
                {
                    var idx = FindRecoveryCodeIndex(userData, req.Code);
                    if (idx >= 0)
                    {
                        userData.RecoveryCodes[idx].Used = true;
                        userData.RecoveryCodes[idx].UsedAt = DateTime.UtcNow;
                        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                        codeValid = true;
                        codeConsumedRecovery = true;
                    }
                }

                if (!codeValid && req.Code.Length == 6 && req.Code.All(char.IsDigit))
                {
                    if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
                    {
                        return Unauthorized(new { message = "TOTP is enabled but no secret is configured. Please re-enroll." });
                    }

                    string secret;
                    try
                    {
                        secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, user.Id);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[2FA] Failed to decrypt TOTP secret for {Name}", req.Username);
                        return StatusCode(500, new { message = "Failed to decrypt TOTP secret. Please re-enroll 2FA." });
                    }

                    if (_totpService.ValidateCode(secret, req.Code, user.Id.ToString(),
                        userData.LastUsedTotpStep, out var acceptedStep))
                    {
                        codeValid = true;
                        userData.LastUsedTotpStep = acceptedStep;
                        // Persist the floor immediately so a concurrent verify with
                        // the same code/step is rejected.
                        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
                    }
                }

                if (!codeValid)
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                    await _store.AddAuditEntryAsync(new AuditEntry
                    {
                        Timestamp = DateTime.UtcNow,
                        UserId = user.Id,
                        Username = user.Username ?? string.Empty,
                        RemoteIp = clientIp,
                        Result = AuditResult.Failed,
                        Method = "totp",
                    }).ConfigureAwait(false);
                    return Unauthorized(new { message = uniformFailMessage });
                }
            }

            // --- Step 3: credentials fully verified — mint the Jellyfin session. ---
            var deviceId = HttpContext.Request.Headers["X-Emby-Device-Id"].FirstOrDefault()
                ?? Guid.NewGuid().ToString("N");
            var deviceName = HttpContext.Request.Headers["X-Emby-Device-Name"].FirstOrDefault()
                ?? "Browser";

            var authRequest = new AuthenticationRequest
            {
                Username = req.Username,
                Password = req.Password,
                App = "Jellyfin Web",
                AppVersion = "1.0.0",
                DeviceId = deviceId,
                DeviceName = deviceName,
                RemoteEndPoint = clientIp,
            };

            // Pre-verify (user, device) BEFORE AuthenticateNewSession, since the
            // SessionStarted failsafe fires during that call. Scoped to deviceId
            // so sibling devices can't piggy-back on the window.
            if (!requiresPostPasswordChallenge)
            {
                _challengeStore.MarkDevicePreVerified(user.Id, deviceId);
            }
            else
            {
                // SEC S3: about to mint a token we INTEND to keep (it's stashed and
                // handed back after enrollment). Mark this (user, device) so the
                // failsafe blocks it reversibly instead of revoking it. Set before
                // the mint so it's visible when SessionStarted fires (race-free).
                _challengeStore.MarkEnrollmentInProgress(user.Id, deviceId);
            }

            MediaBrowser.Controller.Authentication.AuthenticationResult result;
            var authSucceeded = false;
            try
            {
                try
                {
                    result = await _sessionManager.AuthenticateNewSession(authRequest).ConfigureAwait(false);
                    authSucceeded = true;
                }
                catch (MediaBrowser.Controller.Authentication.AuthenticationException)
                {
                    // Password was already verified in Step 1; reaching here is a
                    // rare race (e.g. user disabled between calls). Keep the
                    // uniform message so nothing is leaked.
                    return Unauthorized(new { message = uniformFailMessage });
                }
            }
            finally
            {
                if (!authSucceeded && !requiresPostPasswordChallenge)
                {
                    _challengeStore.ConsumeDevicePreVerified(user.Id, deviceId);
                }
            }

            // --- Step 2b: user must enroll (policy requires 2FA, none set up). ---
            if (requiresPostPasswordChallenge)
            {
                var methods = new List<string> { "enroll" };
                var challenge = _challengeStore.CreateChallenge(
                    user.Id,
                    user.Username ?? req.Username,
                    methods,
                    deviceId,
                    deviceName,
                    clientIp,
                    enrollmentRequired: true);
                challenge.PendingAuthResponse = System.Text.Json.JsonSerializer.Serialize(result);
                if (!string.IsNullOrEmpty(result.AccessToken))
                {
                    _challengeStore.BlockToken(result.AccessToken);
                }

                await _store.AddAuditEntryAsync(new AuditEntry
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = user.Id,
                    Username = user.Username ?? req.Username,
                    RemoteIp = clientIp,
                    DeviceId = deviceId,
                    DeviceName = deviceName,
                    Result = AuditResult.ChallengeIssued,
                    Method = "enroll",
                }).ConfigureAwait(false);

                return Unauthorized(new TwoFactorRequiredResponse
                {
                    TwoFactorRequired = true,
                    ChallengeToken = challenge.Token,
                    Methods = methods,
                    EnrollmentRequired = true,
                    ChallengePageUrl = $"/Mfa/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
                    EnrollmentPageUrl = $"/Mfa/Challenge?token={Uri.EscapeDataString(challenge.Token)}",
                });
            }

            // --- Step 3: success. ---
            if (!string.IsNullOrEmpty(result.AccessToken))
            {
                // Mark verified so the SessionStarted failsafe doesn't re-block
                // this token on later reconnects (issue #27).
                _challengeStore.MarkTokenVerified(result.AccessToken);
                _challengeStore.UnblockToken(result.AccessToken);
            }
            await _store.ResetFailedAttemptsAsync(user.Id).ConfigureAwait(false);
            _rateLimiter.Reset("auth:" + clientIp);

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = user.Id,
                Username = user.Username ?? string.Empty,
                RemoteIp = clientIp,
                DeviceId = deviceId,
                DeviceName = deviceName,
                Result = AuditResult.Success,
                Method = totpEnabled ? (codeConsumedRecovery ? "recovery" : "totp") : "password_only",
            }).ConfigureAwait(false);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] /Authenticate unhandled exception");
            return StatusCode(500, new { message = "Internal server error. Check Jellyfin logs for [2FA] entries." });
        }
    }

    // -------------------------------------------------------------------------
    // POST /Verify — complete a challenge issued by the SessionStarted failsafe
    // (a session was minted via the stock endpoint and blocked).
    // -------------------------------------------------------------------------

    [HttpPost("Verify")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(VerifyResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<VerifyResponse>> Verify([FromBody, Required] VerifyRequest request)
    {
        if (FieldTooLong(request.Code, request.ChallengeToken))
        {
            return BadRequest(new { message = "Field too long." });
        }

        var clientIp = ClientIp();
        var rl = _rateLimiter.CheckAndRecord("verify:" + clientIp, 10, TimeSpan.FromMinutes(1));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
                retryAfterSeconds = rl.retryAfterSeconds,
            });
        }

        var challenge = _challengeStore.GetChallenge(request.ChallengeToken);
        if (challenge is null)
        {
            return BadRequest(new { message = "Invalid or expired challenge." });
        }

        // Per-user limit: defense in depth against an IP rotator sidestepping
        // the per-IP bucket.
        var userRl = _rateLimiter.CheckAndRecord("verify_user:" + challenge.UserId.ToString("N"), 15, TimeSpan.FromMinutes(15));
        if (!userRl.allowed)
        {
            Response.Headers.Append("Retry-After", userRl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts for this account. Try again in {userRl.retryAfterSeconds} seconds.",
                retryAfterSeconds = userRl.retryAfterSeconds,
            });
        }

        if (challenge.AttemptCount >= 5)
        {
            _challengeStore.ConsumeChallenge(request.ChallengeToken);
            return Unauthorized(new { message = "Too many failed attempts on this challenge. Restart sign-in." });
        }

        if (await _store.IsLockedOutAsync(challenge.UserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out." });
        }

        var userData = await _store.GetUserDataAsync(challenge.UserId).ConfigureAwait(false);
        bool valid;
        var consumedRecovery = false;

        if (string.Equals(request.Method, "recovery", StringComparison.OrdinalIgnoreCase))
        {
            var idx = FindRecoveryCodeIndex(userData, request.Code);
            valid = idx >= 0;
            if (valid)
            {
                userData.RecoveryCodes[idx].Used = true;
                userData.RecoveryCodes[idx].UsedAt = DateTime.UtcNow;
                consumedRecovery = true;
            }
        }
        else
        {
            if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
            {
                challenge.IncrementAttempts();
                await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
                return Unauthorized(new { message = "No TOTP secret configured." });
            }

            string secret;
            try
            {
                secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, challenge.UserId);
            }
            catch
            {
                return StatusCode(500, new { message = "TOTP secret is corrupted. Re-enroll 2FA." });
            }

            valid = _totpService.ValidateCode(secret, request.Code, challenge.UserId.ToString(),
                userData.LastUsedTotpStep, out var acceptedTotpStep);
            if (valid)
            {
                userData.LastUsedTotpStep = acceptedTotpStep;
                await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
            }
        }

        if (valid && consumedRecovery)
        {
            await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        }

        if (!valid)
        {
            challenge.IncrementAttempts();
            await _store.RecordFailedAttemptAsync(challenge.UserId).ConfigureAwait(false);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = challenge.UserId,
                Username = challenge.Username,
                RemoteIp = challenge.RemoteIp ?? string.Empty,
                DeviceId = challenge.DeviceId ?? string.Empty,
                DeviceName = challenge.DeviceName ?? string.Empty,
                Result = AuditResult.Failed,
                Method = request.Method,
            }).ConfigureAwait(false);

            return Unauthorized(new { message = "Invalid 2FA code." });
        }

        _challengeStore.ConsumeChallenge(request.ChallengeToken);
        await _store.ResetFailedAttemptsAsync(challenge.UserId).ConfigureAwait(false);
        _rateLimiter.Reset("verify_user:" + challenge.UserId.ToString("N"));
        _rateLimiter.Reset("verify:" + clientIp);

        // Pre-verify this (user, device) so the follow-up WebSocket / HTTP
        // sessions Jellyfin fires aren't re-blocked.
        if (!string.IsNullOrEmpty(challenge.DeviceId))
        {
            _challengeStore.MarkDevicePreVerified(challenge.UserId, challenge.DeviceId);
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = challenge.UserId,
            Username = challenge.Username,
            RemoteIp = challenge.RemoteIp ?? string.Empty,
            DeviceId = challenge.DeviceId ?? string.Empty,
            DeviceName = challenge.DeviceName ?? string.Empty,
            Result = AuditResult.Success,
            Method = request.Method,
        }).ConfigureAwait(false);

        // Return the stashed Jellyfin auth response so the client ends up with a
        // working session identical to a non-2FA login.
        if (!string.IsNullOrEmpty(challenge.PendingAuthResponse))
        {
            UnblockAccessTokenFromPendingAuthResponse(challenge.PendingAuthResponse, challenge.Username);
            Response.ContentType = "application/json";
            return Content(challenge.PendingAuthResponse, "application/json");
        }

        return Ok(new VerifyResponse { AccessToken = string.Empty });
    }

    // -------------------------------------------------------------------------
    // Self-service enrollment
    // -------------------------------------------------------------------------

    [HttpPost("Setup/Totp")]
    [Authorize]
    [ProducesResponseType(typeof(TotpSetupResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<TotpSetupResponse>> SetupTotp()
    {
        var userId = GetCurrentUserId();
        var jellyfinUser = _userManager.GetUserById(userId);
        var username = jellyfinUser?.Username ?? userId.ToString();

        var (secret, qrCodeBase64, manualEntryKey) = _totpService.GenerateSecret(username);
        var encryptedSecret = _totpService.EncryptSecret(secret, userId);

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        // Stash only; TotpEnabled/Verified flip on Confirm to avoid leaving the
        // account half-enrolled if the user backs out.
        userData.TotpVerified = false;
        userData.EncryptedTotpSecret = encryptedSecret;
        userData.LastUsedTotpStep = 0;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);
        _totpService.ResetReplayCache(userId.ToString());

        return Ok(new TotpSetupResponse
        {
            SecretKey = secret,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = manualEntryKey,
        });
    }

    [HttpPost("Setup/Totp/Confirm")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ConfirmTotp([FromBody, Required] ConfirmTotpRequest request)
    {
        if (FieldTooLong(request.Code))
        {
            return BadRequest("Field too long.");
        }

        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            return BadRequest("TOTP setup has not been initiated");
        }

        string decryptedSecret;
        try
        {
            decryptedSecret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, userId);
        }
        catch
        {
            return StatusCode(500, new { message = "TOTP secret is corrupted. Restart setup." });
        }

        var valid = _totpService.ValidateCode(decryptedSecret, request.Code, userId.ToString(),
            persistedFloor: 0, out var acceptedStep);
        if (!valid)
        {
            return BadRequest("Invalid TOTP code");
        }

        userData.TotpEnabled = true;
        userData.TotpVerified = true;
        userData.LastUsedTotpStep = acceptedStep;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = ClientIp(),
            Result = AuditResult.ConfigChanged,
            Method = "enroll_totp",
        }).ConfigureAwait(false);

        return Ok();
    }

    /// <summary>Self-service disable. Requires a valid current second factor
    /// (TOTP or recovery code) so that a stolen session token alone cannot strip
    /// the account's 2FA — the caller must also prove possession of the factor.
    /// (Admins reset a locked-out user's 2FA via <see cref="ToggleUser"/>, which
    /// is gated by elevation and intentionally needs no code.)</summary>
    [HttpPost("Setup/Disable")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult> DisableTotp([FromBody, Required] DisableTotpRequest request)
    {
        var userId = GetCurrentUserId();
        var clientIp = ClientIp();

        if (FieldTooLong(request.Code))
        {
            return BadRequest(new { message = "Field too long." });
        }

        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        // Not enrolled → nothing to tear down; succeed idempotently without a code.
        if (!(userData.TotpEnabled && userData.TotpVerified))
        {
            return Ok();
        }

        if (await _store.IsLockedOutAsync(userId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Account is locked out. Try again later." });
        }

        // Per-user rate limit so a stolen token can't brute the code space here
        // any faster than on the sign-in path.
        var rl = _rateLimiter.CheckAndRecord("disable_user:" + userId.ToString("N"), 10, TimeSpan.FromMinutes(5));
        if (!rl.allowed)
        {
            Response.Headers.Append("Retry-After", rl.retryAfterSeconds.ToString(CultureInfo.InvariantCulture));
            return StatusCode(StatusCodes.Status429TooManyRequests, new
            {
                message = $"Too many attempts. Try again in {rl.retryAfterSeconds} seconds.",
            });
        }

        if (string.IsNullOrEmpty(request.Code))
        {
            return Unauthorized(new { message = "A current authenticator or recovery code is required to disable two-factor authentication." });
        }

        // Accept either a recovery code or a live TOTP code — same matching rules
        // as the sign-in path.
        var valid = false;
        var maybeRecovery = request.Code.Replace("-", string.Empty).Replace(" ", string.Empty);
        if (maybeRecovery.Length >= 8 && maybeRecovery.All(char.IsLetterOrDigit))
        {
            valid = FindRecoveryCodeIndex(userData, request.Code) >= 0;
        }

        if (!valid && request.Code.Length == 6 && request.Code.All(char.IsDigit)
            && !string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            string secret;
            try
            {
                secret = _totpService.DecryptSecret(userData.EncryptedTotpSecret, userId);
            }
            catch
            {
                return StatusCode(500, new { message = "TOTP secret is corrupted. Ask an administrator to reset your 2FA." });
            }

            valid = _totpService.ValidateCode(secret, request.Code, userId.ToString(),
                userData.LastUsedTotpStep, out _);
        }

        if (!valid)
        {
            await _store.RecordFailedAttemptAsync(userId).ConfigureAwait(false);
            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = userId,
                Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
                RemoteIp = clientIp,
                Result = AuditResult.Failed,
                Method = "self_disable",
            }).ConfigureAwait(false);
            return Unauthorized(new { message = "Invalid code." });
        }

        await _store.MutateAsync(userId, ud =>
        {
            ud.TotpEnabled = false;
            ud.TotpVerified = false;
            ud.EncryptedTotpSecret = null;
            ud.RecoveryCodes.Clear();
            ud.RecoveryCodesGeneratedAt = null;
            ud.LastUsedTotpStep = 0;
        }).ConfigureAwait(false);

        // Revoke the second factor AND any live session, then clear pre-verify.
        await _sessionTerm.LogoutAllForUserAsync(userId).ConfigureAwait(false);
        await _store.ResetFailedAttemptsAsync(userId).ConfigureAwait(false);
        _rateLimiter.Reset("disable_user:" + userId.ToString("N"));

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Username = _userManager.GetUserById(userId)?.Username ?? userId.ToString(),
            RemoteIp = clientIp,
            Result = AuditResult.ConfigChanged,
            Method = "self_disable",
        }).ConfigureAwait(false);

        return Ok();
    }

    // -------------------------------------------------------------------------
    // Recovery codes
    // -------------------------------------------------------------------------

    [HttpPost("RecoveryCodes/Generate")]
    [Authorize]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        if (!userData.TotpEnabled || !userData.TotpVerified)
        {
            return BadRequest(new { message = "Set up TOTP first before generating recovery codes." });
        }

        var (plaintext, records) = _recoveryCodes.GenerateCodes();
        userData.RecoveryCodes = records;
        userData.RecoveryCodesGeneratedAt = DateTime.UtcNow;
        await _store.SaveUserDataAsync(userData).ConfigureAwait(false);

        return Ok(new
        {
            codes = plaintext,
            generatedAt = userData.RecoveryCodesGeneratedAt,
            warning = "These codes are shown ONCE. Save them in a password manager. Each code works for one login.",
        });
    }

    [HttpGet("RecoveryCodes/Status")]
    [Authorize]
    public async Task<IActionResult> GetRecoveryCodesStatus()
    {
        var userId = GetCurrentUserId();
        var userData = await _store.GetUserDataAsync(userId).ConfigureAwait(false);

        return Ok(new
        {
            total = userData.RecoveryCodes.Count,
            remaining = userData.RecoveryCodes.Count(c => !c.Used),
            generatedAt = userData.RecoveryCodesGeneratedAt,
        });
    }

    [HttpGet("MyStatus")]
    [Authorize]
    public async Task<ActionResult<UserTwoFactorStatus>> GetMyStatus()
    {
        var userId = GetCurrentUserId();
        var data = await _store.GetUserDataAsync(userId).ConfigureAwait(false);
        var jellyfinUser = _userManager.GetUserById(userId);
        var isLockedOut = await _store.IsLockedOutAsync(userId).ConfigureAwait(false);
        return Ok(new UserTwoFactorStatus
        {
            UserId = userId,
            Username = jellyfinUser?.Username ?? userId.ToString(),
            TotpEnabled = data.TotpEnabled && data.TotpVerified,
            RecoveryCodesRemaining = data.RecoveryCodes.Count(c => !c.Used),
            IsLockedOut = isLockedOut,
        });
    }

    // -------------------------------------------------------------------------
    // Admin (RequiresElevation)
    // -------------------------------------------------------------------------

    [HttpGet("Users")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<UserTwoFactorStatus>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<UserTwoFactorStatus>>> GetUsers()
    {
        var allUserData = await _store.GetAllUsersAsync().ConfigureAwait(false);
        var result = new List<UserTwoFactorStatus>(allUserData.Count);

        foreach (var data in allUserData)
        {
            var jellyfinUser = _userManager.GetUserById(data.UserId);
            var isLockedOut = await _store.IsLockedOutAsync(data.UserId).ConfigureAwait(false);

            result.Add(new UserTwoFactorStatus
            {
                UserId = data.UserId,
                Username = jellyfinUser?.Username ?? data.UserId.ToString(),
                TotpEnabled = data.TotpEnabled && data.TotpVerified,
                RecoveryCodesRemaining = data.RecoveryCodes.Count(c => !c.Used),
                IsLockedOut = isLockedOut,
            });
        }

        return Ok(result);
    }

    /// <summary>Admin reset/disable. Enabled=true only clears lockout (a user must
    /// enroll their own authenticator). Enabled=false wipes all 2FA state and
    /// logs out the user's live sessions — the lockout-recovery path.</summary>
    [HttpPost("Users/{id}/Toggle")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> ToggleUser([FromRoute] Guid id, [FromBody, Required] ToggleUserRequest request)
    {
        var ju = _userManager.GetUserById(id);

        if (request.Enabled)
        {
            await _store.ResetFailedAttemptsAsync(id).ConfigureAwait(false);
        }
        else
        {
            await _store.MutateAsync(id, ud =>
            {
                ud.TotpEnabled = false;
                ud.TotpVerified = false;
                ud.EncryptedTotpSecret = null;
                ud.RecoveryCodes.Clear();
                ud.RecoveryCodesGeneratedAt = null;
                ud.LastUsedTotpStep = 0;
                ud.FailedAttemptCount = 0;
                ud.LockoutEnd = null;
            }).ConfigureAwait(false);
            await _sessionTerm.LogoutAllForUserAsync(id).ConfigureAwait(false);
        }

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = id,
            Username = ju?.Username ?? id.ToString(),
            RemoteIp = ClientIp(),
            Result = AuditResult.ConfigChanged,
            Method = "admin_toggle_" + (request.Enabled ? "on" : "off"),
        }).ConfigureAwait(false);

        return Ok();
    }

    [HttpGet("AuditLog")]
    [Authorize(Policy = "RequiresElevation")]
    [ProducesResponseType(typeof(IReadOnlyList<AuditEntry>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<AuditEntry>>> GetAuditLog([FromQuery] int? limit = null)
    {
        var entries = await _store.GetAuditLogAsync(limit).ConfigureAwait(false);
        return Ok(entries);
    }
}
