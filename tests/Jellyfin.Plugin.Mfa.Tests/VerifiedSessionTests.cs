using System;
using System.Collections.Generic;
using Jellyfin.Plugin.Mfa.Models;
using Jellyfin.Plugin.Mfa.Services;
using Xunit;

namespace Jellyfin.Plugin.Mfa.Tests;

/// <summary>
/// Tests for persistent 2FA pass-through (verified sessions): the on-disk record
/// that lets a device survive a Jellyfin restart without re-authenticating.
/// Covers the security-critical matching logic — token hashing, expiry, the
/// sliding-refresh signal, and device binding.
/// </summary>
public class VerifiedSessionTests
{
    private const string Token = "a9e248aa19144adaba6430efdf3b2957";
    private const string DeviceA = "device-aaa";
    private const string DeviceB = "device-bbb";

    private static UserTwoFactorData WithSession(VerifiedSession s)
        => new() { UserId = Guid.NewGuid(), VerifiedSessions = new List<VerifiedSession> { s } };

    [Fact]
    public void HashToken_is_deterministic_and_never_contains_the_token()
    {
        var h1 = UserTwoFactorStore.HashToken(Token);
        var h2 = UserTwoFactorStore.HashToken(Token);

        Assert.Equal(h1, h2);
        Assert.NotEqual(Token, h1);
        Assert.DoesNotContain(Token, h1, StringComparison.Ordinal);
        Assert.NotEqual(h1, UserTwoFactorStore.HashToken(Token + "x"));
    }

    [Fact]
    public void Valid_unexpired_token_is_verified()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = DeviceA,
            ExpiresAt = now.AddDays(30),
        });

        Assert.True(UserTwoFactorStore.IsSessionVerified(ud, Token, DeviceA, now, out var refreshSoon));
        Assert.False(refreshSoon);
    }

    [Fact]
    public void Expired_token_is_not_verified()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = DeviceA,
            ExpiresAt = now.AddSeconds(-1),
        });

        Assert.False(UserTwoFactorStore.IsSessionVerified(ud, Token, DeviceA, now, out _));
    }

    [Fact]
    public void Different_token_is_not_verified()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = DeviceA,
            ExpiresAt = now.AddDays(30),
        });

        Assert.False(UserTwoFactorStore.IsSessionVerified(ud, "some-other-token", DeviceA, now, out _));
    }

    [Fact]
    public void Token_replayed_from_a_different_device_is_rejected()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = DeviceA,
            ExpiresAt = now.AddDays(30),
        });

        // Same token, different device → must re-prompt.
        Assert.False(UserTwoFactorStore.IsSessionVerified(ud, Token, DeviceB, now, out _));
    }

    [Fact]
    public void No_stored_device_binds_to_token_only()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = null,
            ExpiresAt = now.AddDays(30),
        });

        Assert.True(UserTwoFactorStore.IsSessionVerified(ud, Token, DeviceB, now, out _));
    }

    [Fact]
    public void RefreshSoon_is_set_when_entry_nears_expiry()
    {
        var now = DateTime.UtcNow;
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            DeviceId = DeviceA,
            ExpiresAt = now.AddDays(3), // inside the 7-day refresh threshold
        });

        Assert.True(UserTwoFactorStore.IsSessionVerified(ud, Token, DeviceA, now, out var refreshSoon));
        Assert.True(refreshSoon);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Empty_token_is_never_verified(string? token)
    {
        var ud = WithSession(new VerifiedSession
        {
            TokenHash = UserTwoFactorStore.HashToken(Token),
            ExpiresAt = DateTime.UtcNow.AddDays(30),
        });

        Assert.False(UserTwoFactorStore.IsSessionVerified(ud, token, DeviceA, DateTime.UtcNow, out _));
    }
}
