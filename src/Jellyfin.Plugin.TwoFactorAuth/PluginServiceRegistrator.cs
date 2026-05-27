using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Jellyfin.Plugin.TwoFactorAuth;

public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<UserTwoFactorStore>();
        serviceCollection.AddSingleton<ChallengeStore>();
        serviceCollection.AddSingleton<TotpService>();
        serviceCollection.AddSingleton<RecoveryCodeService>();
        serviceCollection.AddSingleton<RateLimiter>();
        serviceCollection.AddSingleton<SessionTerminationService>();

        serviceCollection.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        serviceCollection.AddSingleton<IStartupFilter, TwoFactorStartupFilter>();

        // Server-side enforcement failsafe: subscribes to ISessionManager.SessionStarted
        // and blocks any session that completed a password login without 2FA.
        serviceCollection.AddHostedService<AuthenticationEventHandler>();
    }
}
