using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.Mfa.Models;
using Jellyfin.Plugin.Mfa.Services;
using Xunit;

namespace Jellyfin.Plugin.Mfa.Tests;

/// <summary>
/// Regression tests for v2.4 security fixes in ChallengeStore + ChallengeData.
/// </summary>
public class ChallengeStoreTests
{
    // ---- L2: atomic single-consume -----------------------------------------

    [Fact]
    public void TryConsume_returns_true_once_and_false_thereafter()
    {
        var data = new ChallengeData
        {
            Token = "any",
            UserId = Guid.NewGuid(),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };

        Assert.True(data.TryConsume());
        Assert.False(data.TryConsume());
        Assert.False(data.TryConsume());
        Assert.True(data.IsConsumed);
    }

    [Fact]
    public async Task TryConsume_is_thread_safe_under_concurrent_callers()
    {
        // SEC v2.4 L2: previously two concurrent /Verify requests could both
        // pass the check-then-set guard and both succeed, minting two sessions
        // from one OTP code. TryConsume must succeed for exactly one caller
        // across N parallel attempts.
        for (var trial = 0; trial < 50; trial++)
        {
            var data = new ChallengeData
            {
                Token = "any",
                UserId = Guid.NewGuid(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            };

            const int parallelism = 32;
            var tasks = new Task<bool>[parallelism];
            using var gate = new System.Threading.Barrier(parallelism);
            for (var i = 0; i < parallelism; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    gate.SignalAndWait();
                    return data.TryConsume();
                });
            }

            var results = await Task.WhenAll(tasks);
            var successCount = 0;
            foreach (var r in results) if (r) successCount++;
            Assert.Equal(1, successCount);
        }
    }

    [Fact]
    public void ConsumeChallenge_through_store_is_single_use()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(
            Guid.NewGuid(),
            "alice",
            new List<string> { "totp" },
            "dev-1",
            "Living Room",
            "203.0.113.5");

        Assert.True(store.ConsumeChallenge(c.Token));
        Assert.False(store.ConsumeChallenge(c.Token));
        Assert.False(store.ConsumeChallenge(c.Token));
    }

    [Fact]
    public void ConsumeChallenge_rejects_expired()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(
            Guid.NewGuid(),
            "alice",
            new List<string> { "totp" },
            "dev-1",
            "Living Room",
            "203.0.113.5");

        c.ExpiresAt = DateTime.UtcNow.AddSeconds(-1);
        Assert.False(store.ConsumeChallenge(c.Token));
    }

    [Fact]
    public void ConsumeChallenge_rejects_unknown_token()
    {
        using var store = new ChallengeStore();
        Assert.False(store.ConsumeChallenge("not-a-token"));
        Assert.False(store.ConsumeChallenge(string.Empty));
    }

    // ---- L7: deviceless / whitespace pre-verify guard ---------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData("   ")]
    public void MarkDevicePreVerified_ignores_empty_or_whitespace_deviceId(string? deviceId)
    {
        // SEC v2.4 L7: previously IsNullOrEmpty was used, so a single space or
        // tab deviceId would pass and grant a user-wide pre-verify bypass via
        // the "user:<id>" key.
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkDevicePreVerified(userId, deviceId);

        Assert.False(store.IsDevicePreVerified(userId, deviceId));
        Assert.False(store.IsDevicePreVerified(userId, "device-1"));
    }

    [Fact]
    public void MarkDevicePreVerified_with_real_deviceId_records_correctly()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkDevicePreVerified(userId, "device-real");

        Assert.True(store.IsDevicePreVerified(userId, "device-real"));
        Assert.False(store.IsDevicePreVerified(userId, "device-other"));
        Assert.False(store.IsDevicePreVerified(Guid.NewGuid(), "device-real"));
    }

    [Fact]
    public void ConsumeDevicePreVerified_is_single_use()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();
        store.MarkDevicePreVerified(userId, "device-1");

        Assert.True(store.IsDevicePreVerified(userId, "device-1"));
        store.ConsumeDevicePreVerified(userId, "device-1");
        Assert.False(store.IsDevicePreVerified(userId, "device-1"));
    }

    // ---- General correctness of challenge issuance ------------------------

    [Fact]
    public void CreateChallenge_generates_unique_tokens()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        var a = store.CreateChallenge(userId, "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");
        var b = store.CreateChallenge(userId, "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");

        Assert.NotEqual(a.Token, b.Token);
        Assert.False(string.IsNullOrEmpty(a.Token));
        Assert.DoesNotContain('=', a.Token);
        Assert.DoesNotContain('+', a.Token);
        Assert.DoesNotContain('/', a.Token);
    }

    [Fact]
    public void GetChallenge_returns_null_after_consumed()
    {
        using var store = new ChallengeStore();
        var c = store.CreateChallenge(Guid.NewGuid(), "alice", new List<string> { "totp" }, "d1", "TV", "1.2.3.4");

        Assert.NotNull(store.GetChallenge(c.Token));
        store.ConsumeChallenge(c.Token);
        Assert.Null(store.GetChallenge(c.Token));
    }

    // ---- Token / device blocking primitives -------------------------------

    [Fact]
    public void BlockToken_then_IsTokenBlocked_returns_true_until_unblocked()
    {
        using var store = new ChallengeStore();
        const string token = "abc123";

        Assert.False(store.IsTokenBlocked(token));
        store.BlockToken(token);
        Assert.True(store.IsTokenBlocked(token));
        store.UnblockToken(token);
        Assert.False(store.IsTokenBlocked(token));
    }

    [Fact]
    public void MarkTokenVerified_then_IsTokenVerified_returns_true()
    {
        using var store = new ChallengeStore();
        const string token = "tok-verified";

        Assert.False(store.IsTokenVerified(token));
        store.MarkTokenVerified(token);
        Assert.True(store.IsTokenVerified(token));
    }

    // ---- S7: atomic attempt counter ---------------------------------------

    [Fact]
    public void IncrementAttempts_returns_incrementing_values()
    {
        var data = new ChallengeData { Token = "any", UserId = Guid.NewGuid() };

        Assert.Equal(0, data.AttemptCount);
        Assert.Equal(1, data.IncrementAttempts());
        Assert.Equal(2, data.IncrementAttempts());
        Assert.Equal(2, data.AttemptCount);
    }

    // ---- S3: enrollment-in-progress guard (block-only vs revoke) ----------

    [Fact]
    public void EnrollmentInProgress_is_scoped_to_user_and_device()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkEnrollmentInProgress(userId, "dev-1");

        Assert.True(store.IsEnrollmentInProgress(userId, "dev-1"));
        Assert.False(store.IsEnrollmentInProgress(userId, "dev-2"));
        Assert.False(store.IsEnrollmentInProgress(Guid.NewGuid(), "dev-1"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void MarkEnrollmentInProgress_ignores_empty_deviceId(string? deviceId)
    {
        // Deviceless calls must not mark — the failsafe then falls back to the
        // safe default (revoke) rather than block-only.
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();

        store.MarkEnrollmentInProgress(userId, deviceId);

        Assert.False(store.IsEnrollmentInProgress(userId, deviceId));
    }

    [Fact]
    public void ClearEnrollmentInProgress_removes_the_mark()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();
        store.MarkEnrollmentInProgress(userId, "dev-1");

        store.ClearEnrollmentInProgress(userId, "dev-1");

        Assert.False(store.IsEnrollmentInProgress(userId, "dev-1"));
    }

    [Fact]
    public void WipeAllForUser_clears_enrollment_marks()
    {
        using var store = new ChallengeStore();
        var userId = Guid.NewGuid();
        store.MarkEnrollmentInProgress(userId, "dev-1");

        store.WipeAllForUser(userId);

        Assert.False(store.IsEnrollmentInProgress(userId, "dev-1"));
    }

    [Fact]
    public async Task IncrementAttempts_is_thread_safe_no_lost_updates()
    {
        // SEC S7: a plain AttemptCount++ could lose increments under concurrent
        // /Verify calls, letting an attacker exceed the per-challenge cap. The
        // atomic increment must count every caller exactly once.
        for (var trial = 0; trial < 20; trial++)
        {
            var data = new ChallengeData { Token = "any", UserId = Guid.NewGuid() };

            const int parallelism = 64;
            var tasks = new Task[parallelism];
            using var gate = new System.Threading.Barrier(parallelism);
            for (var i = 0; i < parallelism; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    gate.SignalAndWait();
                    data.IncrementAttempts();
                });
            }

            await Task.WhenAll(tasks);
            Assert.Equal(parallelism, data.AttemptCount);
        }
    }
}
