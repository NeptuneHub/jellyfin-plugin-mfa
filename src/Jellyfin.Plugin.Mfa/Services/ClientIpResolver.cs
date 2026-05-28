using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// Resolves the "real" client IP when Jellyfin sits behind one or more trusted
/// reverse proxies, and collapses IPv6 to /64 so a single client rotating
/// through its /64 prefix (common on residential IPv6) can't sidestep per-IP
/// rate limits. When no trusted proxies are configured (default) the TCP peer
/// IP is returned unchanged — preserving the original direct-connect behaviour.
/// <para>
/// SECURITY: <c>X-Forwarded-For</c> is only consulted when the immediate TCP
/// peer is itself inside a configured trusted-proxy CIDR. An attacker reaching
/// the server directly cannot inject XFF to spoof their address. Empty by
/// default means trust nothing — a misconfigured fork can't accidentally enable
/// XFF parsing and weaken rate limiting.
/// </para>
/// </summary>
public static class ClientIpResolver
{
    public static string Resolve(HttpContext? ctx, IReadOnlyList<string>? trustedProxyCidrs)
    {
        var remote = ctx?.Connection.RemoteIpAddress;
        if (remote is null)
        {
            return "unknown";
        }

        if (trustedProxyCidrs is null || trustedProxyCidrs.Count == 0)
        {
            return Normalize(remote);
        }

        var cidrs = ParseCidrs(trustedProxyCidrs);
        if (cidrs.Count == 0 || !IsTrusted(remote, cidrs))
        {
            return Normalize(remote);
        }

        var xff = ctx!.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
        {
            var parts = xff.Split(',');
            for (var i = parts.Length - 1; i >= 0; i--)
            {
                if (!IPAddress.TryParse(parts[i].Trim(), out var ip))
                {
                    continue;
                }

                if (!IsTrusted(ip, cidrs))
                {
                    return Normalize(ip);
                }
            }
        }

        return Normalize(remote);
    }

    private static List<(IPAddress baseAddr, int prefixLen)> ParseCidrs(IReadOnlyList<string> raw)
    {
        var result = new List<(IPAddress, int)>(raw.Count);
        foreach (var entry in raw)
        {
            var s = entry?.Trim();
            if (string.IsNullOrEmpty(s))
            {
                continue;
            }

            string addrPart;
            int prefix;
            var slash = s.IndexOf('/');
            if (slash >= 0)
            {
                addrPart = s.Substring(0, slash);
                if (!int.TryParse(s.AsSpan(slash + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix))
                {
                    continue;
                }
            }
            else
            {
                addrPart = s;
                prefix = -1;
            }

            if (!IPAddress.TryParse(addrPart, out var addr))
            {
                continue;
            }

            if (prefix < 0)
            {
                prefix = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            }

            var max = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > max)
            {
                continue;
            }

            result.Add((addr, prefix));
        }

        return result;
    }

    private static bool IsTrusted(IPAddress ip, List<(IPAddress baseAddr, int prefixLen)> cidrs)
    {
        var ipBytes = ip.GetAddressBytes();
        foreach (var (baseAddr, prefixLen) in cidrs)
        {
            if (baseAddr.AddressFamily != ip.AddressFamily)
            {
                continue;
            }

            if (PrefixMatches(ipBytes, baseAddr.GetAddressBytes(), prefixLen))
            {
                return true;
            }
        }

        return false;
    }

    private static bool PrefixMatches(byte[] a, byte[] b, int prefixLen)
    {
        var fullBytes = prefixLen / 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        var remaining = prefixLen % 8;
        if (remaining == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remaining));
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }

    private static string Normalize(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return ip.ToString();
        }

        var bytes = ip.GetAddressBytes();
        for (var i = 8; i < bytes.Length; i++)
        {
            bytes[i] = 0;
        }

        return new IPAddress(bytes).ToString() + "/64";
    }
}
