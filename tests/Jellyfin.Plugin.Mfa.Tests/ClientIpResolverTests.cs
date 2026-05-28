using System.Collections.Generic;
using System.Net;
using Jellyfin.Plugin.Mfa.Services;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.Mfa.Tests;

/// <summary>
/// Locks in ClientIpResolver's proxy-walking + IPv6 /64 collapse behaviour.
/// These are security-sensitive: an XFF parsed when it shouldn't be lets any
/// client spoof its rate-limit bucket; a /64 not collapsed lets one residential
/// IPv6 client rotate through addresses to evade per-IP limits.
/// </summary>
public class ClientIpResolverTests
{
    private static HttpContext Context(string remoteIp, string? xff = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
        if (xff is not null)
        {
            ctx.Request.Headers["X-Forwarded-For"] = xff;
        }

        return ctx;
    }

    [Fact]
    public void No_trusted_cidrs_returns_tcp_peer_unchanged()
    {
        var ip = ClientIpResolver.Resolve(Context("203.0.113.5", xff: "1.2.3.4, 5.6.7.8"), null);
        Assert.Equal("203.0.113.5", ip);
    }

    [Fact]
    public void Empty_trusted_cidrs_returns_tcp_peer_unchanged()
    {
        var ip = ClientIpResolver.Resolve(Context("203.0.113.5", xff: "1.2.3.4"), new List<string>());
        Assert.Equal("203.0.113.5", ip);
    }

    [Fact]
    public void Untrusted_peer_with_xff_ignores_xff()
    {
        // Cardinal rule: only trust XFF when the immediate TCP peer is itself a
        // configured proxy. Otherwise any caller could forge their client IP.
        var ip = ClientIpResolver.Resolve(
            Context("203.0.113.5", xff: "1.2.3.4"),
            new List<string> { "10.0.0.0/8" });
        Assert.Equal("203.0.113.5", ip);
    }

    [Fact]
    public void Trusted_peer_walks_xff_right_to_left_returning_rightmost_untrusted()
    {
        var ip = ClientIpResolver.Resolve(
            Context("10.0.0.5", xff: "1.2.3.4, 10.0.0.99"),
            new List<string> { "10.0.0.0/8" });
        // Right-to-left: 10.0.0.99 is trusted, skip; 1.2.3.4 is the real client.
        Assert.Equal("1.2.3.4", ip);
    }

    [Fact]
    public void All_xff_hops_trusted_falls_back_to_tcp_peer()
    {
        var ip = ClientIpResolver.Resolve(
            Context("10.0.0.5", xff: "10.0.0.10, 10.0.0.20"),
            new List<string> { "10.0.0.0/8" });
        Assert.Equal("10.0.0.5", ip);
    }

    [Fact]
    public void Trusted_peer_with_no_xff_falls_back_to_tcp_peer()
    {
        var ip = ClientIpResolver.Resolve(
            Context("10.0.0.5"),
            new List<string> { "10.0.0.0/8" });
        Assert.Equal("10.0.0.5", ip);
    }

    [Fact]
    public void Bare_ip_cidr_is_treated_as_exact_match()
    {
        // "127.0.0.1" without /32 — same as 127.0.0.1/32.
        var trusted = ClientIpResolver.Resolve(
            Context("127.0.0.1", xff: "1.2.3.4"),
            new List<string> { "127.0.0.1" });
        Assert.Equal("1.2.3.4", trusted);

        var notTrusted = ClientIpResolver.Resolve(
            Context("127.0.0.2", xff: "1.2.3.4"),
            new List<string> { "127.0.0.1" });
        Assert.Equal("127.0.0.2", notTrusted);
    }

    [Fact]
    public void Malformed_cidrs_are_skipped_silently()
    {
        var ip = ClientIpResolver.Resolve(
            Context("10.0.0.5", xff: "1.2.3.4"),
            new List<string> { "not-a-cidr", "10.0.0.0/8", "300.0.0.0/8", "10.0.0.0/99" });
        Assert.Equal("1.2.3.4", ip);
    }

    [Fact]
    public void Malformed_xff_entries_are_skipped()
    {
        var ip = ClientIpResolver.Resolve(
            Context("10.0.0.5", xff: "1.2.3.4, garbage, 10.0.0.99"),
            new List<string> { "10.0.0.0/8" });
        // Right-to-left: 10.0.0.99 trusted, "garbage" skipped, 1.2.3.4 returned.
        Assert.Equal("1.2.3.4", ip);
    }

    [Fact]
    public void IPv6_client_is_collapsed_to_slash_64()
    {
        // One residential client typically gets a whole /64; per-IP rate
        // limiting must aggregate them or it's trivially evaded.
        var ip = ClientIpResolver.Resolve(
            Context("2001:db8:1234:5678:dead:beef:cafe:f00d"),
            null);
        Assert.Equal("2001:db8:1234:5678::/64", ip);
    }

    [Fact]
    public void IPv6_through_trusted_proxy_collapses_real_client_to_slash_64()
    {
        var ip = ClientIpResolver.Resolve(
            Context("::1", xff: "2001:db8:abcd:ef01::1234"),
            new List<string> { "::1/128" });
        Assert.Equal("2001:db8:abcd:ef01::/64", ip);
    }

    [Fact]
    public void IPv4_cidr_does_not_match_IPv6_peer_or_vice_versa()
    {
        // Cross-family CIDRs must not falsely match: an IPv6 peer mustn't be
        // treated as trusted by an IPv4 CIDR (and vice versa).
        var notTrusted = ClientIpResolver.Resolve(
            Context("2001:db8::1", xff: "1.2.3.4"),
            new List<string> { "0.0.0.0/0" });
        Assert.Equal("2001:db8::/64", notTrusted);
    }

    [Fact]
    public void Null_context_returns_unknown()
    {
        Assert.Equal("unknown", ClientIpResolver.Resolve(null, null));
    }
}
