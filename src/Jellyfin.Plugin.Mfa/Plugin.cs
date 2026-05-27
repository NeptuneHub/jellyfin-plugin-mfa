using System;
using System.Collections.Generic;
using Jellyfin.Plugin.Mfa.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.Mfa;

public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    public static Plugin? Instance { get; private set; }

    public override string Name => "Multi-Factor Authentication (MFA)";

    public override string Description => "Per-user multi-factor authentication for Jellyfin: TOTP authenticator enrollment with single-use recovery codes, enforced at sign-in for enrolled users.";

    public override Guid Id => new("fab665d5-38e6-4db1-b5fc-0640510fd02d");

    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = "Mfa",
                EmbeddedResourcePath = GetType().Namespace + ".Pages.admin.html",
            },
        };
    }
}
