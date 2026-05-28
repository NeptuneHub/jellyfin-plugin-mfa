using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Jellyfin.Data.Enums;
using Jellyfin.Plugin.Mfa.Configuration;
using Jellyfin.Plugin.Mfa.Models;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Mfa.Services;

/// <summary>
/// Blocks authenticated requests from users who logged in without completing 2FA.
/// v2.4.12: returns 403 (was 401 pre-v2.4.12). 403 is more semantically correct
/// — we DO know who the caller is, they just lack permission until 2FA completes
/// — and crucially SWAG's default nginx-unauthorized fail2ban jail (and similar
/// nginx-only-watches-401 setups) does not count 403s, so a single legitimate
/// 2FA login no longer trips a brute-force ban on the reverse proxy. The injected
/// inject.js still recognises the response shape (twoFactorRequired:true) and
/// short-circuits subsequent in-flight API calls so the browser stops hammering
/// the server while the user completes the challenge. Issue #36 (Wibbles42).
/// Our own /Mfa/* paths are always allowed through so users can reach /Login.
///
/// Since we run before Jellyfin's auth middleware in the pipeline, we invoke
/// authentication manually via context.AuthenticateAsync to get the user claims.
/// </summary>
public class RequestBlockerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ChallengeStore _challengeStore;
    private readonly UserTwoFactorStore _store;
    private readonly ILogger<RequestBlockerMiddleware> _logger;

    public RequestBlockerMiddleware(
        RequestDelegate next,
        ChallengeStore challengeStore,
        UserTwoFactorStore store,
        ILogger<RequestBlockerMiddleware> logger)
    {
        _next = next;
        _challengeStore = challengeStore;
        _store = store;
        _logger = logger;
    }

    // Specific endpoints needed for a blocked user to complete 2FA — must NOT be blocked.
    // We deliberately do NOT exempt the entire /Mfa/* prefix; admin endpoints
    // under that prefix require admin auth and should also be blocked while mid-2FA.
    private static readonly string[] AlwaysAllowedPaths = new[]
    {
        "/Mfa/Login",
        "/Mfa/Setup",
        "/Mfa/Authenticate",
        "/Mfa/Verify",
        "/Mfa/Challenge",
        "/Mfa/inject.js",
    };

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        // SEC v2.4 L3: tolerate trailing-slash variants. Some clients / reverse
        // proxies (especially Caddy on directory rewrites) append a trailing
        // slash to GETs — without this, `/Mfa/Login/` wouldn't match
        // the `/Mfa/Login` exempt entry and would 401 the user mid-2FA.
        var normalizedPath = path.Length > 1 ? path.TrimEnd('/') : path;

        foreach (var allowed in AlwaysAllowedPaths)
        {
            if (normalizedPath.Equals(allowed, StringComparison.OrdinalIgnoreCase))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }
        }

        var config = Plugin.Instance?.Configuration;
        if (config is null || !config.Enabled)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Pre-mint enforcement: refuse the native Jellyfin login endpoints BEFORE
        // a token is minted for any user who must satisfy 2FA, so there is no
        // window where a password-only token is briefly usable (the SessionStarted
        // failsafe only blocks AFTER the token exists). Users with no 2FA
        // obligation pass straight through and log in normally on every client.
        // Quick Connect carries no username pre-auth, so it still relies on the
        // SessionStarted failsafe.
        if (config.BlockNativeLoginForEnforcedUsers
            && HttpMethods.IsPost(context.Request.Method)
            && await TryBlockNativeLoginAsync(context, config, normalizedPath).ConfigureAwait(false))
        {
            return;
        }

        // Only care about requests carrying Jellyfin auth — skip unauthenticated ones
        var token = GetAccessToken(context);
        if (string.IsNullOrEmpty(token))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Ask Jellyfin's CustomAuthentication handler to resolve claims for this request
        Guid userId = Guid.Empty;
        try
        {
            var authResult = await context.AuthenticateAsync("CustomAuthentication").ConfigureAwait(false);
            if (authResult.Succeeded && authResult.Principal is not null)
            {
                var claim = authResult.Principal.FindFirst("Jellyfin-UserId")
                    ?? authResult.Principal.FindFirst(ClaimTypes.NameIdentifier);
                if (claim is not null)
                {
                    _ = Guid.TryParse(claim.Value, out userId);
                }
            }
        }
        catch
        {
            // Jellyfin auth failed — not our concern, let the real pipeline handle it
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Quick Connect pass-through (opt-in). When a verified user authorizes a
        // Quick Connect code on this (already-signed-in) device, the INCOMING
        // device's session has a different deviceId but the SAME userId. Set a
        // single-consume, user-scoped flag so the next SessionStarted for this user
        // is allowed through by the failsafe instead of revoked. Gated on the admin
        // toggle; default off keeps the revoke-on-QC behaviour.
        if (config.AllowQuickConnectForEnrolledUsers
            && userId != Guid.Empty
            && path.Contains("/QuickConnect/Authorize", StringComparison.OrdinalIgnoreCase))
        {
            _challengeStore.MarkQuickConnectPending(userId);
            _logger.LogInformation(
                "[2FA] QuickConnect authorize by {UserId} — one-shot allow for incoming session", userId);
        }

        if (userId != Guid.Empty && !string.IsNullOrEmpty(token) && _challengeStore.IsTokenBlocked(token))
        {
            _logger.LogInformation("[2FA] BLOCKED {Path} user={UserId} (token-scoped) — 2FA not completed",
                path, userId);
            // v2.4.12 issue #36: 403 instead of 401. fail2ban's nginx-unauthorized
            // jail (SWAG default) matches the literal status 401 in the access log
            // and trips after 5 occurrences. A legitimate 2FA login generates
            // ~15 blocked-token responses (every post-login API call from the
            // browser is gated until the user verifies), so every clean login
            // tripped the jail and banned the reverse proxy / Cloudflare / Docker
            // gateway, breaking all services behind it. 403 communicates the
            // same "not allowed" outcome without the brute-force semantics.
            // The "twoFactorRequired" marker in the body is what inject.js's
            // client-side short-circuit looks for to set its tfaPending flag.
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Two-factor authentication required. Visit /Mfa/Login to complete sign in.\",\"twoFactorRequired\":true}"
            ).ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// If <paramref name="normalizedPath"/> is a native Jellyfin password-login
    /// endpoint and the target user must satisfy 2FA, writes a 403
    /// <c>twoFactorRequired</c> response and returns true (so no token is minted).
    /// Returns false to let the request continue (user has no 2FA obligation, or
    /// the user/endpoint couldn't be identified — the SessionStarted failsafe is
    /// the backstop for the latter).
    /// </summary>
    private async Task<bool> TryBlockNativeLoginAsync(HttpContext context, PluginConfiguration config, string normalizedPath)
    {
        var userManager = context.RequestServices.GetService<IUserManager>();
        if (userManager is null)
        {
            return false;
        }

        Jellyfin.Data.Entities.User? user;
        try
        {
            if (normalizedPath.Equals("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase))
            {
                var username = await ReadUsernameFromBodyAsync(context).ConfigureAwait(false);
                if (string.IsNullOrEmpty(username))
                {
                    return false;
                }

                user = userManager.GetUserByName(username);
            }
            else if (TryGetNativeAuthUserId(normalizedPath, out var userId))
            {
                user = userManager.GetUserById(userId);
            }
            else
            {
                return false; // not a native password-login endpoint
            }
        }
        catch (Exception ex)
        {
            // Couldn't identify the user — fail open to the native flow; the
            // SessionStarted failsafe still blocks the minted token afterwards.
            _logger.LogDebug(ex, "[2FA] Native-login pre-check could not resolve user");
            return false;
        }

        if (user is null)
        {
            return false; // unknown user → let Jellyfin reject it normally
        }

        var userData = await _store.GetUserDataAsync(user.Id).ConfigureAwait(false);
        var isEnrolled = userData.TotpEnabled && userData.TotpVerified;

        // SEC S5: fail CLOSED if the admin lookup throws — an unresolved admin
        // under a non-Optional scope is assumed to require 2FA rather than waved
        // straight through to the native login endpoint.
        bool mustEnforce;
        try
        {
            var isAdmin = userManager.GetUserById(user.Id)?.HasPermission(PermissionKind.IsAdministrator) ?? false;
            mustEnforce = config.ShouldEnforceFor(isAdmin);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] Native-login pre-check could not resolve admin status — failing closed");
            mustEnforce = config.EnforcementScope != EnforcementScope.Optional;
        }

        // No 2FA obligation → unaffected; every client logs in as before.
        if (!isEnrolled && !mustEnforce)
        {
            return false;
        }

        _logger.LogInformation(
            "[2FA] Pre-mint block of native login for {Name} — 2FA required, must use /Mfa/Login", user.Username);

        await _store.AddAuditEntryAsync(new AuditEntry
        {
            Timestamp = DateTime.UtcNow,
            UserId = user.Id,
            Username = user.Username ?? string.Empty,
            RemoteIp = ClientIpResolver.Resolve(context, Plugin.Instance?.Configuration?.TrustedProxyCidrs),
            Result = AuditResult.ChallengeIssued,
            Method = "native_blocked",
        }).ConfigureAwait(false);

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            "{\"message\":\"Two-factor authentication required. Visit /Mfa/Login to complete sign in.\",\"twoFactorRequired\":true}"
        ).ConfigureAwait(false);
        return true;
    }

    /// <summary>Matches the legacy <c>/Users/{guid}/Authenticate</c> by-id login
    /// endpoint and extracts the user id from the path (no body read needed).</summary>
    private static bool TryGetNativeAuthUserId(string normalizedPath, out Guid userId)
    {
        userId = Guid.Empty;
        const string Prefix = "/Users/";
        const string Suffix = "/Authenticate";
        if (normalizedPath.Length <= Prefix.Length + Suffix.Length
            || !normalizedPath.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)
            || !normalizedPath.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var idPart = normalizedPath.Substring(Prefix.Length, normalizedPath.Length - Prefix.Length - Suffix.Length);
        return Guid.TryParse(idPart, out userId) && userId != Guid.Empty;
    }

    /// <summary>Buffers and reads the JSON login body to extract the
    /// <c>Username</c> field, then rewinds the stream so MVC model binding can
    /// re-read it. Returns null on any malformed/oversized body.</summary>
    private static async Task<string?> ReadUsernameFromBodyAsync(HttpContext context)
    {
        try
        {
            context.Request.EnableBuffering();
            context.Request.Body.Position = 0;
            using var reader = new StreamReader(
                context.Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var body = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);
            context.Request.Body.Position = 0;

            if (string.IsNullOrWhiteSpace(body) || body.Length > 8192)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.Equals("Username", StringComparison.OrdinalIgnoreCase)
                    && prop.Value.ValueKind == JsonValueKind.String)
                {
                    return prop.Value.GetString();
                }
            }
        }
        catch (Exception)
        {
            // Malformed/oversized body or unbuffered stream — let the native flow
            // handle/reject it; the SessionStarted failsafe is the backstop.
        }

        return null;
    }

    private static string? GetAccessToken(HttpContext ctx)
    {
        var token = ctx.Request.Headers["X-Emby-Token"].FirstOrDefault();
        if (!string.IsNullOrEmpty(token)) return token;

        var apiKeyQ = ctx.Request.Query["api_key"].FirstOrDefault()
            ?? ctx.Request.Query["ApiKey"].FirstOrDefault();
        if (!string.IsNullOrEmpty(apiKeyQ)) return apiKeyQ;

        // X-Emby-Authorization is a metadata header carrying Client=, Device=,
        // DeviceId=, Version= even on UNAUTHENTICATED login attempts. Only use
        // it if it actually contains a Token=... segment.
        var embyAuth = ctx.Request.Headers["X-Emby-Authorization"].FirstOrDefault()
            ?? ctx.Request.Headers["Authorization"].FirstOrDefault();
        var headerToken = ParseEmbyAuth(embyAuth, "Token");
        if (!string.IsNullOrEmpty(headerToken))
        {
            return headerToken;
        }

        if (!string.IsNullOrWhiteSpace(embyAuth)
            && embyAuth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return embyAuth.Substring("Bearer ".Length).Trim();
        }

        return null;
    }

    /// <summary>Pull a key (Token / Client / Device / DeviceId) out of an
    /// X-Emby-Authorization header. Jellyfin Web and Tizen clients pack the
    /// token in here rather than the dedicated header.</summary>
    private static string? ParseEmbyAuth(string? header, string key)
    {
        if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(key)) return null;
        var needle = key + "=";
        var idx = header.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        if (idx > 0)
        {
            var prev = header[idx - 1];
            if (prev != ',' && prev != ' ') return null;
        }
        var rest = header.Substring(idx + needle.Length);
        if (rest.StartsWith("\"", StringComparison.Ordinal))
        {
            var end = rest.IndexOf('"', 1);
            return end > 0 ? rest.Substring(1, end - 1) : null;
        }
        var comma = rest.IndexOf(',');
        return (comma > 0 ? rest.Substring(0, comma) : rest).Trim();
    }
}
