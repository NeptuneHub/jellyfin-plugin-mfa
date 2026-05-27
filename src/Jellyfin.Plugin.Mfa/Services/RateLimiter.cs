using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// Per-IP sliding-window rate limiter. Used on /Mfa/Verify and
/// /Mfa/Authenticate to defend against brute force on the OTP code
/// space (a million 6-digit codes is small enough that an unrestricted attacker
/// could exhaust it in minutes without rate limiting).
/// </summary>
public class RateLimiter
{
    private readonly ConcurrentDictionary<string, List<DateTime>> _hits = new();

    // v1.4 observability: bounded list of recent rate-limit trips so admins
    // can see when buckets are firing and tune limits / spot abuse. Bounded
    // at 200 — anything beyond that is recurring noise that an admin should
    // tune away rather than scroll through.
    private readonly System.Collections.Concurrent.ConcurrentQueue<RateLimitTrip> _recentTrips = new();
    private const int MaxRecentTrips = 200;

    public record RateLimitTrip(DateTime At, string Key, int Limit, int WindowSeconds, int RetryAfterSeconds);

    public IReadOnlyList<RateLimitTrip> RecentTrips() => _recentTrips.ToArray();

    /// <summary>
    /// Returns true if the request from this key (IP) should be allowed.
    /// Returns false (and the time until next allowed attempt) if rate-limited.
    /// </summary>
    public (bool allowed, int retryAfterSeconds) CheckAndRecord(string key, int maxRequests, TimeSpan window)
    {
        var now = DateTime.UtcNow;
        var cutoff = now - window;

        var bucket = _hits.GetOrAdd(key, _ => new List<DateTime>());
        lock (bucket)
        {
            bucket.RemoveAll(t => t < cutoff);

            if (bucket.Count >= maxRequests)
            {
                var oldest = bucket[0];
                var retryAfter = Math.Max(1, (int)((oldest + window) - now).TotalSeconds);
                RecordTrip(key, maxRequests, (int)window.TotalSeconds, retryAfter);
                return (false, retryAfter);
            }

            bucket.Add(now);
            return (true, 0);
        }
    }

    private void RecordTrip(string key, int limit, int windowSeconds, int retryAfter)
    {
        _recentTrips.Enqueue(new RateLimitTrip(DateTime.UtcNow, key, limit, windowSeconds, retryAfter));
        while (_recentTrips.Count > MaxRecentTrips && _recentTrips.TryDequeue(out _)) { }
    }

    /// <summary>
    /// Reset the counter for a key (e.g., after a successful login).
    /// </summary>
    public void Reset(string key)
    {
        _hits.TryRemove(key, out _);
    }

    /// <summary>Derives a per-client rate-limit key from the direct TCP peer
    /// address. We deliberately do NOT trust X-Forwarded-For ourselves — admins
    /// behind a reverse proxy should configure Jellyfin's own forwarded-headers
    /// support (KnownProxies / KnownNetworks) so RemoteIpAddress already reflects
    /// the real client. IPv6 is bucketed by /64 so an attacker can't rotate the
    /// host portion of their address to bypass the limit.</summary>
    public static string ClientKey(HttpContext context)
    {
        var effectiveIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Collapse IPv6 to /64 so per-host rotation within the same network
        // shares a bucket.
        if (IPAddress.TryParse(effectiveIp, out var parsed)
            && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var bytes = parsed.GetAddressBytes();
            for (var i = 8; i < bytes.Length; i++) bytes[i] = 0;
            return new IPAddress(bytes).ToString();
        }

        return effectiveIp;
    }
}
