using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data.Enums;
using Jellyfin.Data.Queries;
using Jellyfin.Plugin.Mfa.Models;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// Server-side enforcement failsafe. Subscribes to <see cref="ISessionManager.SessionStarted"/>,
/// which fires for EVERY successful login regardless of client (web, Swiftfin,
/// Tizen) — including logins that hit Jellyfin's stock /Users/AuthenticateByName
/// directly instead of the plugin's /Authenticate endpoint. For an enrolled (or
/// enforcement-required) user whose session has not completed 2FA, it blocks the
/// minted access token and ends the session, so a password-only login yields no
/// usable token. The token block is set before any heavy async work so
/// RequestBlockerMiddleware 403s subsequent requests almost immediately.
/// </summary>
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix",
    Justification = "EventHandler suffix accurately describes a class that subscribes to ISessionManager events at startup.")]
public class AuthenticationEventHandler : IHostedService
{
    private readonly ISessionManager _sessionManager;
    private readonly UserTwoFactorStore _store;
    private readonly ChallengeStore _challengeStore;
    private readonly IDeviceManager _deviceManager;
    private readonly IUserManager _userManager;
    private readonly ILogger<AuthenticationEventHandler> _logger;

    public AuthenticationEventHandler(
        ISessionManager sessionManager,
        UserTwoFactorStore store,
        ChallengeStore challengeStore,
        IDeviceManager deviceManager,
        IUserManager userManager,
        ILogger<AuthenticationEventHandler> logger)
    {
        _sessionManager = sessionManager;
        _store = store;
        _challengeStore = challengeStore;
        _deviceManager = deviceManager;
        _userManager = userManager;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _sessionManager.SessionStarted += OnSessionStarted;
        _logger.LogDebug("[2FA] Subscribed to ISessionManager.SessionStarted");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _sessionManager.SessionStarted -= OnSessionStarted;
        return Task.CompletedTask;
    }

    private async void OnSessionStarted(object? sender, SessionEventArgs e)
    {
        try
        {
            if (e.SessionInfo is { } info)
            {
                await HandleSessionAsync(info).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[2FA] Error handling SessionStarted");
        }
    }

    private async Task HandleSessionAsync(SessionInfo info)
    {
        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled || info.UserId == Guid.Empty)
        {
            return;
        }

        // Resolve the access token Jellyfin minted for this session (synchronous).
        string? token = null;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = info.UserId });
            token = devices.Items.FirstOrDefault(d =>
                !string.IsNullOrEmpty(info.DeviceId)
                && string.Equals(d.DeviceId, info.DeviceId, StringComparison.Ordinal))?.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Couldn't look up access token for session");
        }

        var userData = await _store.GetUserDataAsync(info.UserId).ConfigureAwait(false);
        var isEnrolled = userData.TotpEnabled && userData.TotpVerified;

        var isAdmin = false;
        try
        {
            isAdmin = _userManager.GetUserById(info.UserId)?
                .HasPermission(PermissionKind.IsAdministrator) ?? false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Could not resolve admin status for {UserId}", info.UserId);
        }

        // Not enrolled and policy doesn't require it → genuinely no 2FA; allow.
        if (!isEnrolled && !config.ShouldEnforceFor(isAdmin))
        {
            return;
        }

        // Reconnect / follow-up session within the pre-verify window, or a token
        // that already completed 2FA this process lifetime → allow (issue #27).
        if (_challengeStore.IsDevicePreVerified(info.UserId, info.DeviceId)
            || (!string.IsNullOrEmpty(token) && _challengeStore.IsTokenVerified(token)))
        {
            return;
        }

        // Fresh, unverified login for a user who needs 2FA. Block the token
        // FIRST (in-memory, instant) so RequestBlockerMiddleware 403s every
        // request on it while the heavier revoke/teardown below runs.
        if (!string.IsNullOrEmpty(token))
        {
            _challengeStore.BlockToken(token);
        }

        // SEC S3: distinguish a genuinely-abandoned token (Quick Connect, or any
        // native login that slipped past the pre-mint block — the user will get a
        // fresh token via /Mfa/Authenticate) from the forced-enrollment token the
        // /Authenticate enrollment branch deliberately minted, blocked, and stashed
        // to hand back after the user enrolls. The former we REVOKE so it can't be
        // resurrected after a restart (the in-memory block is volatile); the latter
        // we leave block-only (reversible) so enrollment can complete.
        var enrollmentInProgress = _challengeStore.IsEnrollmentInProgress(info.UserId, info.DeviceId);

        _logger.LogInformation(
            "[2FA] {Action} unverified session for {Name} — 2FA required",
            enrollmentInProgress ? "Blocked (enrolling)" : "Revoked", info.UserName);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = info.UserId,
            Username = info.UserName ?? string.Empty,
            RemoteIp = info.RemoteEndPoint ?? string.Empty,
            DeviceId = info.DeviceId ?? string.Empty,
            DeviceName = info.DeviceName ?? string.Empty,
            Result = AuditResult.ChallengeIssued,
            Method = enrollmentInProgress ? "blocked" : "revoked",
        }).ConfigureAwait(false);

        try
        {
            if (!enrollmentInProgress && !string.IsNullOrEmpty(token))
            {
                // Revoke the access token in Jellyfin's persistent store — this
                // also ends the session, so no separate ReportSessionEnded needed.
                await _sessionManager.Logout(token).ConfigureAwait(false);
            }
            else
            {
                // Enrollment token (keep it alive, just end the unverified session)
                // or a session whose token couldn't be resolved (best effort).
                await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] Failed to tear down unverified session for {Name}", info.UserName);
        }
    }
}
