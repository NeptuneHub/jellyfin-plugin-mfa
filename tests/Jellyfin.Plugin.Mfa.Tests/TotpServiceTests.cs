using System;
using Jellyfin.Plugin.Mfa.Services;
using Jellyfin.Plugin.Mfa.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.Mfa.Tests;

public class TotpServiceTests
{
    private static TotpService NewService()
    {
        var paths = TestApplicationPaths.Create();
        return new TotpService(paths, Substitute.For<ILogger<TotpService>>());
    }

    private static string NewBase32Secret()
    {
        var bytes = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(bytes);
    }

    private static string CurrentCode(string base32Secret)
    {
        var bytes = Base32Encoding.ToBytes(base32Secret);
        return new Totp(bytes, step: 30, totpSize: 6).ComputeTotp();
    }

    // ---- Input validation --------------------------------------------------

    [Theory]
    [InlineData("12345")]      // too short
    [InlineData("1234567")]    // too long
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateCode_rejects_wrong_length(string code)
    {
        var svc = NewService();
        var secret = NewBase32Secret();

        Assert.False(svc.ValidateCode(secret, code, "user-A"));
    }

    [Fact]
    public void ValidateCode_rejects_invalid_base32_secret()
    {
        var svc = NewService();
        Assert.False(svc.ValidateCode("not!valid!base32!", "123456", "user-A"));
    }

    [Fact]
    public void ValidateCode_rejects_wrong_code()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        Assert.False(svc.ValidateCode(secret, "000000", "user-A"));
    }

    // ---- Happy path --------------------------------------------------------

    [Fact]
    public void ValidateCode_accepts_current_code()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A"));
    }

    // ---- Replay protection -------------------------------------------------

    [Fact]
    public void ValidateCode_rejects_replay_of_same_step()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A", 0, out var acceptedStep));
        Assert.True(acceptedStep > 0);

        // Same code, same user, same step — must be rejected as a replay.
        Assert.False(svc.ValidateCode(secret, code, "user-A", 0, out _));
    }

    [Fact]
    public void ValidateCode_replay_protection_is_per_user()
    {
        var svc = NewService();
        var secretA = NewBase32Secret();
        var codeA = CurrentCode(secretA);
        var secretB = NewBase32Secret();
        var codeB = CurrentCode(secretB);

        Assert.True(svc.ValidateCode(secretA, codeA, "user-A"));
        // user-B has a separate replay cache — fresh slate.
        Assert.True(svc.ValidateCode(secretB, codeB, "user-B"));
    }

    [Fact]
    public void ValidateCode_rejects_code_at_or_below_persisted_floor()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A", 0, out var step));

        // Reset cache and replay with the floor = matched step — must reject.
        svc.ResetReplayCache("user-A");
        Assert.False(svc.ValidateCode(secret, code, "user-A", step, out _));
    }

    [Fact]
    public void ResetReplayCache_allows_revalidation_after_secret_rotation()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A"));
        Assert.False(svc.ValidateCode(secret, code, "user-A"));

        svc.ResetReplayCache("user-A");
        Assert.True(svc.ValidateCode(secret, code, "user-A"));
    }

    // ---- Encryption (AES-GCM with userId AAD) ------------------------------

    [Fact]
    public void EncryptSecret_uses_v2_format_bound_to_user()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var encrypted = svc.EncryptSecret(secret, userId);
        Assert.StartsWith("v2:", encrypted);
        Assert.Equal(secret, svc.DecryptSecret(encrypted, userId));
    }

    [Fact]
    public void EncryptSecret_rejects_empty_userId()
    {
        var svc = NewService();
        Assert.Throws<ArgumentException>(() => svc.EncryptSecret(NewBase32Secret(), Guid.Empty));
    }

    [Fact]
    public void DecryptSecret_rejects_empty_userId()
    {
        var svc = NewService();
        var encrypted = svc.EncryptSecret(NewBase32Secret(), Guid.NewGuid());
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => svc.DecryptSecret(encrypted, Guid.Empty));
    }

    [Fact]
    public void DecryptSecret_rejects_non_v2_format()
    {
        // Legacy v1 (no-AAD) blobs and any other format are no longer accepted —
        // a plain base64 string without the v2 prefix must be rejected.
        var svc = NewService();
        var bogus = Convert.ToBase64String(new byte[40]);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => svc.DecryptSecret(bogus, Guid.NewGuid()));
    }

    [Fact]
    public void DecryptSecret_v2_with_wrong_userId_throws()
    {
        // AAD binding means swapping the v2 ciphertext to a different user's
        // record fails authentication, blocking on-disk identity swap.
        var svc = NewService();
        var secret = NewBase32Secret();
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var encrypted = svc.EncryptSecret(secret, userA);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => svc.DecryptSecret(encrypted, userB));
    }

    [Fact]
    public void Encrypted_secret_persists_across_service_restarts()
    {
        // The persistent secret.key allows new service instances pointed at the
        // same plugin directory to decrypt ciphertexts produced by an earlier
        // instance. Without this, every Jellyfin restart would invalidate every
        // TOTP enrollment — the exact bug v1.0.15 fixed.
        var paths = TestApplicationPaths.Create();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var first = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        var ciphertext = first.EncryptSecret(secret, userId);

        var second = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        Assert.Equal(secret, second.DecryptSecret(ciphertext, userId));
    }
}
