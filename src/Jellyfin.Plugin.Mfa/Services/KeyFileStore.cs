using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// Loads (or creates) a persistent random key file with locked-down permissions.
/// Extracted verbatim from the original TotpService key handling so multiple
/// services can own distinct keys (TOTP encryption, audit-log HMAC) without
/// duplicating the platform-specific ACL logic. Each call re-applies restrictive
/// permissions: Unix chmod 0600; Windows an explicit DACL granting only the
/// running account + SYSTEM + Administrators with inheritance disabled.
/// </summary>
public static class KeyFileStore
{
    /// <summary>Load a key of <paramref name="sizeBytes"/> bytes from
    /// <paramref name="keyPath"/>, creating it (and its parent directory) with a
    /// fresh CSPRNG value if it is missing or the wrong length. Permissions are
    /// re-locked on every load.</summary>
    public static byte[] LoadOrCreate(string keyPath, int sizeBytes, ILogger? logger = null)
    {
        var dir = Path.GetDirectoryName(keyPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        if (File.Exists(keyPath))
        {
            try
            {
                var bytes = File.ReadAllBytes(keyPath);
                if (bytes.Length == sizeBytes)
                {
                    // Reapply restrictive perms on every load. A file created by
                    // an older plugin version, restored from a backup, or copied
                    // by the admin may have lax perms. Cheap and idempotent.
                    Restrict(keyPath, logger);
                    return bytes;
                }
                logger?.LogWarning("Existing key file {Path} is not {Size} bytes — regenerating", keyPath, sizeBytes);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to read existing key file {Path} — regenerating", keyPath);
            }
        }

        var key = RandomNumberGenerator.GetBytes(sizeBytes);
        File.WriteAllBytes(keyPath, key);
        Restrict(keyPath, logger);

        logger?.LogInformation("Generated new persistent key at {Path}", keyPath);
        return key;
    }

    private static void Restrict(string path, ILogger? logger)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                RestrictWindows(path);
            }
            else
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception ex)
        {
            // Best effort — never fail startup over an ACL tweak, but surface it
            // so an admin can harden a multi-user host manually if needed.
            logger?.LogWarning(ex, "[2FA] Could not restrict permissions on {Path}; ensure the plugin data dir is readable only by the Jellyfin service account", path);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictWindows(string path)
    {
        var fileInfo = new FileInfo(path);
        var security = new FileSecurity();

        // Disable inheritance and drop any inherited ACEs so only the explicit
        // grants below apply.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var grantees = new List<IdentityReference>();
        var current = WindowsIdentity.GetCurrent().User;
        if (current is not null)
        {
            grantees.Add(current);
        }
        grantees.Add(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        grantees.Add(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));

        foreach (var who in grantees)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                who, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        fileInfo.SetAccessControl(security);
    }
}
