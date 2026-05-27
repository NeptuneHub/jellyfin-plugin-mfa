using System;
using Jellyfin.Plugin.Mfa.Models;
using Jellyfin.Plugin.Mfa.Services;
using Jellyfin.Plugin.Mfa.Tests.Helpers;
using Xunit;

namespace Jellyfin.Plugin.Mfa.Tests;

/// <summary>
/// SEC S6: the audit-log integrity chain must be a keyed HMAC, not a bare
/// SHA-256, so it cannot be silently recomputed by a tamperer who can write
/// audit.json but cannot read the per-instance audit.key.
/// </summary>
public class AuditHashTests
{
    private static AuditEntry SampleEntry() => new()
    {
        PreviousHash = new string('0', 64),
        Timestamp = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
        UserId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Username = "alice",
        RemoteIp = "203.0.113.5",
        DeviceId = "dev-1",
        DeviceName = "Living Room",
        Result = AuditResult.Success,
        Method = "totp",
    };

    [Fact]
    public void Hash_is_deterministic_for_same_entry_and_key()
    {
        using var store = new UserTwoFactorStore(TestApplicationPaths.Create());
        var e = SampleEntry();

        var h1 = store.ComputeAuditEntryHash(e);
        var h2 = store.ComputeAuditEntryHash(e);

        Assert.Equal(h1, h2);
        Assert.Equal(64, h1.Length); // HMAC-SHA256 → 32 bytes → 64 hex chars
    }

    [Fact]
    public void Hash_differs_across_instances_with_different_keys()
    {
        // Two stores in separate sandboxes get independent audit.key files. A
        // keyed HMAC must therefore produce different hashes for the same entry;
        // a bare SHA-256 would (incorrectly) produce identical hashes.
        using var a = new UserTwoFactorStore(TestApplicationPaths.Create());
        using var b = new UserTwoFactorStore(TestApplicationPaths.Create());
        var e = SampleEntry();

        Assert.NotEqual(a.ComputeAuditEntryHash(e), b.ComputeAuditEntryHash(e));
    }

    [Fact]
    public void Hash_is_stable_across_reload_with_same_key()
    {
        // Same sandbox → same persisted audit.key → same hash after re-loading.
        var paths = TestApplicationPaths.Create(out _);
        string h1, h2;
        var e = SampleEntry();
        using (var store1 = new UserTwoFactorStore(paths)) { h1 = store1.ComputeAuditEntryHash(e); }
        using (var store2 = new UserTwoFactorStore(paths)) { h2 = store2.ComputeAuditEntryHash(e); }

        Assert.Equal(h1, h2);
    }

    [Theory]
    [InlineData("username")]
    [InlineData("ip")]
    [InlineData("result")]
    [InlineData("method")]
    [InlineData("previous")]
    public void Hash_changes_when_any_field_is_tampered(string field)
    {
        using var store = new UserTwoFactorStore(TestApplicationPaths.Create());
        var baseHash = store.ComputeAuditEntryHash(SampleEntry());

        var tampered = SampleEntry();
        switch (field)
        {
            case "username": tampered.Username = "mallory"; break;
            case "ip": tampered.RemoteIp = "198.51.100.9"; break;
            case "result": tampered.Result = AuditResult.Failed; break;
            case "method": tampered.Method = "recovery"; break;
            case "previous": tampered.PreviousHash = new string('1', 64); break;
        }

        Assert.NotEqual(baseHash, store.ComputeAuditEntryHash(tampered));
    }
}
