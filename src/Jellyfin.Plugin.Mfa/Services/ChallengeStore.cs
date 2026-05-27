using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jellyfin.Plugin.Mfa.Models;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// In-memory lifecycle store for the 2FA challenge flow. Holds:
///  - pending challenges (token → state) created when a password-valid login
///    still needs a second factor;
///  - per-(user,device) pre-verify marks, so the burst of WebSocket/HTTP
///    sessions Jellyfin spawns right after a successful sign-in isn't
///    re-challenged;
///  - blocked access tokens (the enforcement failsafe — RequestBlockerMiddleware
///    403s any request on a blocked token until 2FA completes);
///  - verified access tokens, so SessionStarted reconnects on an already-verified
///    token aren't re-blocked (issue #27 logout loop).
/// All state is process-local and rebuilt on restart; users re-prompt once per
/// device after a restart, which is acceptable.
/// </summary>
public class ChallengeStore : IDisposable
{
    private readonly ConcurrentDictionary<string, ChallengeData> _challenges = new();

    // Pre-verified keyed by (userId, deviceId). Scoped to deviceId so a
    // browser's verification can't grant another device a free pass.
    private readonly ConcurrentDictionary<string, DateTime> _preVerifiedDevices = new();

    // Blocked by access token. Jellyfin Web doesn't reliably send
    // X-Emby-Device-Id on every request, but the access token is always
    // present, so token-blocking is the actual enforcement mechanism.
    private readonly ConcurrentDictionary<string, DateTime> _blockedTokens = new();

    // Tokens that have completed 2FA at least once this process lifetime.
    // SessionStarted fires on websocket reconnects, new tabs, and idle-resume,
    // not only initial login — without this set the failsafe BlockToken would
    // re-block an already-verified token and log the user out every few minutes.
    private readonly ConcurrentDictionary<string, DateTime> _verifiedTokens = new();

    // PERF: soft cap so a botnet can't OOM us before the 60s cleanup sweep.
    private const int SoftCapPerDict = 100_000;

    private readonly Timer _cleanupTimer;
    private bool _disposed;

    // IsNullOrWhiteSpace (not IsNullOrEmpty) so a deviceId of " " can't sneak
    // past the deviceless guard and grant a user-wide pre-verify bypass.
    private static string DeviceKey(Guid userId, string? deviceId)
        => string.IsNullOrWhiteSpace(deviceId) ? $"user:{userId:N}" : $"{userId:N}|{deviceId}";

    /// <summary>Mark a specific (user, device) pair pre-verified — the next
    /// session created for this combo within the configured window is allowed.
    /// Deviceless / whitespace-only calls are ignored to avoid a user-wide
    /// bypass.</summary>
    public void MarkDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return;
        }

        var seconds = Math.Clamp(
            Plugin.Instance?.Configuration?.PreVerifyWindowSeconds ?? 120, 30, 900);
        _preVerifiedDevices[DeviceKey(userId, deviceId)] = DateTime.UtcNow.AddSeconds(seconds);
        EnforceCap(_preVerifiedDevices);
    }

    public bool IsDevicePreVerified(Guid userId, string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        return _preVerifiedDevices.TryGetValue(DeviceKey(userId, deviceId), out var exp)
            && exp > DateTime.UtcNow;
    }

    public void ConsumeDevicePreVerified(Guid userId, string? deviceId)
    {
        _preVerifiedDevices.TryRemove(DeviceKey(userId, deviceId), out _);
    }

    /// <summary>Wipe all pre-verify state for a user. Call on 2FA disable/reset
    /// so a security response fully revokes every pre-verify window immediately.
    /// Live access tokens are revoked separately via SessionTerminationService.</summary>
    public void WipeAllForUser(Guid userId)
    {
        var prefix = $"{userId:N}|";
        var userless = $"user:{userId:N}";
        foreach (var kv in _preVerifiedDevices)
        {
            if (kv.Key.StartsWith(prefix, StringComparison.Ordinal) || kv.Key == userless)
            {
                _preVerifiedDevices.TryRemove(kv.Key, out _);
            }
        }
    }

    /// <summary>Block a specific access token. RequestBlockerMiddleware 403s
    /// every request using it until the user completes 2FA and UnblockToken is
    /// called. 10-minute expiry so a token that never gets verified is unblocked
    /// by timeout (by which point the session has ended).</summary>
    public void BlockToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _blockedTokens[token] = DateTime.UtcNow.AddMinutes(10);
        EnforceCap(_blockedTokens);
    }

    public void UnblockToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _blockedTokens.TryRemove(token, out _);
    }

    public bool IsTokenBlocked(string token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        if (_blockedTokens.TryGetValue(token, out var exp))
        {
            if (exp > DateTime.UtcNow) return true;
            _blockedTokens.TryRemove(token, out _);
        }
        return false;
    }

    /// <summary>Mark an access token as having completed 2FA. The SessionStarted
    /// failsafe checks this before re-blocking so reconnects on a verified token
    /// don't cause a logout loop (issue #27).</summary>
    public void MarkTokenVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return;
        _verifiedTokens[token] = DateTime.UtcNow.AddDays(30);
        EnforceCap(_verifiedTokens);
    }

    public bool IsTokenVerified(string token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        if (_verifiedTokens.TryGetValue(token, out var exp))
        {
            if (exp > DateTime.UtcNow) return true;
            _verifiedTokens.TryRemove(token, out _);
        }
        return false;
    }

    private static void EnforceCap(ConcurrentDictionary<string, DateTime> dict)
    {
        if (dict.Count <= SoftCapPerDict) return;
        var snapshot = dict.ToArray();
        Array.Sort(snapshot, (a, b) => a.Value.CompareTo(b.Value));
        var evictCount = snapshot.Length / 10;
        for (var i = 0; i < evictCount; i++)
        {
            dict.TryRemove(snapshot[i].Key, out _);
        }
    }

    public ChallengeStore()
    {
        _cleanupTimer = new Timer(
            _ => RemoveExpired(),
            null,
            TimeSpan.FromSeconds(60),
            TimeSpan.FromSeconds(60));
    }

    public ChallengeData CreateChallenge(
        Guid userId,
        string username,
        List<string> methods,
        string? deviceId,
        string? deviceName,
        string? remoteIp,
        bool enrollmentRequired = false)
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
        var token = Base64UrlEncode(tokenBytes);

        int ttlSeconds = Plugin.Instance?.Configuration?.ChallengeTokenTtlSeconds ?? 300;
        var now = DateTime.UtcNow;

        var challenge = new ChallengeData
        {
            Token = token,
            UserId = userId,
            Username = username,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(ttlSeconds),
            AvailableMethods = methods,
            EnrollmentRequired = enrollmentRequired,
            DeviceId = deviceId,
            DeviceName = deviceName,
            RemoteIp = remoteIp,
            IsConsumed = false
        };

        _challenges[token] = challenge;
        return challenge;
    }

    public ChallengeData? GetChallenge(string token)
    {
        if (string.IsNullOrEmpty(token) || !_challenges.TryGetValue(token, out var challenge))
        {
            return null;
        }

        if (challenge.IsConsumed || challenge.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return challenge;
    }

    /// <summary>Atomically claim a challenge. Returns true exactly once across
    /// concurrent callers, so one OTP code can never mint two sessions.</summary>
    public bool ConsumeChallenge(string token)
    {
        if (string.IsNullOrEmpty(token) || !_challenges.TryGetValue(token, out var challenge))
        {
            return false;
        }

        if (challenge.ExpiresAt <= DateTime.UtcNow)
        {
            return false;
        }

        return challenge.TryConsume();
    }

    public void RemoveChallenge(string token)
    {
        _challenges.TryRemove(token, out _);
    }

    private void RemoveExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in _challenges)
        {
            if (kvp.Value.IsConsumed || kvp.Value.ExpiresAt <= now)
            {
                _challenges.TryRemove(kvp.Key, out _);
            }
        }
        foreach (var kv in _preVerifiedDevices)
        {
            if (kv.Value <= now) _preVerifiedDevices.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _blockedTokens)
        {
            if (kv.Value <= now) _blockedTokens.TryRemove(kv.Key, out _);
        }
        foreach (var kv in _verifiedTokens)
        {
            if (kv.Value <= now) _verifiedTokens.TryRemove(kv.Key, out _);
        }
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer.Dispose();
        GC.SuppressFinalize(this);
    }
}
