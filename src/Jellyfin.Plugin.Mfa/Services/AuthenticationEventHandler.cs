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

        // SEC S5: fail CLOSED if the admin lookup throws. Leaving the user looking
        // like a non-admin on a transient failure would let an admin slip through
        // under the Admins enforcement scope.
        bool mustEnforce;
        try
        {
            var isAdmin = _userManager.GetUserById(info.UserId)?
                .HasPermission(PermissionKind.IsAdministrator) ?? false;
            mustEnforce = config.ShouldEnforceFor(isAdmin);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Could not resolve admin status for {UserId} — failing closed", info.UserId);
            mustEnforce = config.EnforcementScope != Configuration.EnforcementScope.Optional;
        }

        // Not enrolled and policy doesn't require it → genuinely no 2FA; allow.
        if (!isEnrolled && !mustEnforce)
        {
            return;
        }

        // Persistent 2FA pass-through: a token that already cleared 2FA — this
        // process OR a previous one, via the on-disk record — is allowed without
        // re-prompting. This is what lets a TV/phone survive a Jellyfin restart.
        // Slide the expiry forward when it nears the window so an actively-used
        // device never lapses.
        if (!string.IsNullOrEmpty(token)
            && UserTwoFactorStore.IsSessionVerified(userData, token, info.DeviceId, DateTime.UtcNow, out var refreshSoon))
        {
            if (refreshSoon)
            {
                await _store.MarkSessionVerifiedAsync(info.UserId, token, info.DeviceId, info.DeviceName).ConfigureAwait(false);
            }

            return;
        }

        // Reconnect / follow-up session within the pre-verify window, or a token
        // that completed 2FA this process lifetime → allow (issue #27). Promote it
        // to the persistent record so the NEXT restart doesn't re-prompt this device.
        if (_challengeStore.IsDevicePreVerified(info.UserId, info.DeviceId)
            || (!string.IsNullOrEmpty(token) && _challengeStore.IsTokenVerified(token)))
        {
            if (!string.IsNullOrEmpty(token))
            {
                await _store.MarkSessionVerifiedAsync(info.UserId, token, info.DeviceId, info.DeviceName).ConfigureAwait(false);
            }

            return;
        }

        // Quick Connect pass-through (opt-in, enrolled users only). A user-scoped,
        // single-consume flag is set when this user authorized a Quick Connect code
        // from an already-2FA-verified device (see RequestBlockerMiddleware). The
        // incoming session has a DIFFERENT deviceId but the SAME userId, so we match
        // on user, not device. Gated on isEnrolled (NOT mere enforcement) so a
        // required-but-unenrolled user is still forced to enroll. Mark the token
        // verified + device pre-verified so the burst of follow-up WebSocket/HTTP
        // sessions on this login aren't re-blocked once the flag is consumed
        // (issue #27 logout loop).
        if (isEnrolled
            && config.AllowQuickConnectForEnrolledUsers
            && _challengeStore.ConsumeQuickConnectPending(info.UserId))
        {
            if (!string.IsNullOrEmpty(token))
            {
                _challengeStore.MarkTokenVerified(token);
                await _store.MarkSessionVerifiedAsync(info.UserId, token, info.DeviceId, info.DeviceName).ConfigureAwait(false);
            }

            _challengeStore.MarkDevicePreVerified(info.UserId, info.DeviceId);
            _logger.LogInformation(
                "[2FA] Allowed Quick Connect session for {Name} — QC pass-through enabled",
                info.UserName);
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

        if (!enrollmentInProgress && !string.IsNullOrEmpty(token))
        {
            // Revoke the access token in Jellyfin's persistent store — this also
            // ends the session, so no separate ReportSessionEnded needed.
            //
            // SEC S6: a failed revoke would leave a password-only token alive,
            // guarded only by the volatile in-memory block (which lapses after
            // ~10 min or a process restart). Retry once; if it still fails, escalate
            // to an Error log, re-affirm the in-memory block, and fall back to
            // ending the session so the gap is at least minimised and visible.
            var revoked = false;
            for (var attempt = 0; attempt < 2 && !revoked; attempt++)
            {
                try
                {
                    await _sessionManager.Logout(token).ConfigureAwait(false);
                    revoked = true;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[2FA] Logout attempt {Attempt} failed for {Name}", attempt + 1, info.UserName);
                }
            }

            if (!revoked)
            {
                _challengeStore.BlockToken(token);
                _logger.LogError(
                    "[2FA] Could not revoke unverified token for {Name} after retries — it remains blocked in-memory only; confirm the session ended",
                    info.UserName);
                try
                {
                    await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[2FA] Fallback ReportSessionEnded also failed for {Name}", info.UserName);
                }
            }
        }
        else if (enrollmentInProgress)
        {
            // Enrollment token: keep it alive (it'll be handed back after the user
            // completes /Mfa/Enroll/Totp/Confirm); just end the unverified session
            // so the password-only credentials can't keep it open server-side.
            try
            {
                await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Failed to end enrollment-in-progress session for {Name}", info.UserName);
            }
        }
        else
        {
            // SEC S3 unresolved-token corner: token couldn't be mapped to the
            // session (some Quick Connect clients, or a session whose DeviceId
            // doesn't match any device record). We CAN'T revoke it in Jellyfin's
            // persistent store — only end the session. The token therefore
            // remains valid in the DB until its natural expiry, guarded only by
            // the volatile in-memory BlockToken set above (which lapses on a
            // process restart). Warn + audit so the frequency is observable: if
            // this fires in your deployment, port the upstream response-rewrite
            // middleware to catch the token at mint time instead.
            _logger.LogWarning(
                "[2FA] S3 unresolved-token: no AccessToken resolvable for session of {Name} (DeviceId={DeviceId}) — ReportSessionEnded only; token remains valid in Jellyfin store until expiry",
                info.UserName, info.DeviceId);

            await _store.AddAuditEntryAsync(new AuditEntry
            {
                Timestamp = DateTime.UtcNow,
                UserId = info.UserId,
                Username = info.UserName ?? string.Empty,
                RemoteIp = info.RemoteEndPoint ?? string.Empty,
                DeviceId = info.DeviceId ?? string.Empty,
                DeviceName = info.DeviceName ?? string.Empty,
                Result = AuditResult.Failed,
                Method = "s3_unresolved_token",
                Details = "Session had no resolvable AccessToken; could not revoke, only ended.",
            }).ConfigureAwait(false);

            try
            {
                await _sessionManager.ReportSessionEnded(info.Id).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Failed to end unresolved-token session for {Name}", info.UserName);
            }
        }
    }
}
