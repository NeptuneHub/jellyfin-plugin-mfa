using System.Linq;
using Jellyfin.Data.Queries;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Kills every live session for a user and clears their in-memory pre-verify
/// state. Used when 2FA is disabled or reset (self-service or admin) so that
/// revoking the second factor also revokes any session that was already open.
/// </summary>
public class SessionTerminationService
{
    private readonly ISessionManager _sessionManager;
    private readonly IDeviceManager _deviceManager;
    private readonly ChallengeStore _challengeStore;
    private readonly ILogger<SessionTerminationService> _logger;

    public SessionTerminationService(
        ISessionManager sessionManager,
        IDeviceManager deviceManager,
        ChallengeStore challengeStore,
        ILogger<SessionTerminationService> logger)
    {
        _sessionManager = sessionManager;
        _deviceManager = deviceManager;
        _challengeStore = challengeStore;
        _logger = logger;
    }

    /// <summary>Logout every access token belonging to the user and wipe all
    /// in-memory pre-verify / blocked-device flags. Returns the number of
    /// sessions terminated. Does NOT modify the user's persisted 2FA data
    /// (paired devices, trusted devices) — caller decides what to wipe.</summary>
    public async Task<int> LogoutAllForUserAsync(Guid userId)
    {
        if (userId == Guid.Empty) return 0;
        int killed = 0;
        try
        {
            var devices = _deviceManager.GetDevices(new DeviceQuery { UserId = userId });
            foreach (var d in devices.Items.Where(d => !string.IsNullOrEmpty(d.AccessToken)))
            {
                try
                {
                    await _sessionManager.Logout(d.AccessToken).ConfigureAwait(false);
                    killed++;
                }
                catch (Exception inner)
                {
                    _logger.LogDebug(inner, "[2FA] Failed to logout token for device {Dev}", d.DeviceId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[2FA] LogoutAllForUserAsync failed enumerating devices for {UserId}", userId);
        }

        _challengeStore.WipeAllForUser(userId);
        return killed;
    }
}
