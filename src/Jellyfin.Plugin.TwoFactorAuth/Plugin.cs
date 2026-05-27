using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.TwoFactorAuth;

public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    public static Plugin? Instance { get; private set; }

    public override string Name => "Two-Factor Authentication";

    public override string Description => "Per-user two-factor authentication for Jellyfin: TOTP authenticator enrollment with single-use recovery codes, enforced at sign-in for enrolled users.";

    public override Guid Id => new("94879a0c-da24-4eb1-aa06-f28b4b9333b1");

    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = "TwoFactorAuth",
                EmbeddedResourcePath = GetType().Namespace + ".Pages.admin.html",
            },
        };
    }
}
