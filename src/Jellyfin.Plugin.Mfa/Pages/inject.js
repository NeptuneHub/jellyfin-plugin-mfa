(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js v3.3.0 loaded');

    // ============================================================
    // 1a. TFA-pending sessionStorage flag + client-side short-circuit.
    //     Once the server has signalled "two-factor authentication
    //     required" for this tab, suppress subsequent non-allowlisted
    //     API calls so the browser stops hammering the server with
    //     blocked-token requests while the user completes the challenge.
    //     The server-side 403 (RequestBlockerMiddleware) covers any calls
    //     that race ahead of this short-circuit.
    // ============================================================
    var TFA_PENDING_KEY = '__tfa_pending';
    var TFA_PENDING_TTL_MS = 5 * 60 * 1000;
    // Mirror RequestBlockerMiddleware.AlwaysAllowedPaths[] verbatim — any
    // divergence soft-locks users mid-2FA. Lowercase + trailing-slash-normalised.
    var TFA_ALWAYS_ALLOWED = [
        '/mfa/login',
        '/mfa/setup',
        '/mfa/authenticate',
        '/mfa/verify',
        '/mfa/challenge',
        '/mfa/inject.js'
    ];
    function isTfaPending() {
        try {
            var v = sessionStorage.getItem(TFA_PENDING_KEY);
            if (!v) return false;
            var ts = parseInt(v, 10);
            if (!ts || isNaN(ts)) return false;
            if (Date.now() - ts > TFA_PENDING_TTL_MS) {
                sessionStorage.removeItem(TFA_PENDING_KEY);
                return false;
            }
            return true;
        } catch (e) { return false; }
    }
    function setTfaPending() {
        try { sessionStorage.setItem(TFA_PENDING_KEY, String(Date.now())); } catch (e) {}
    }
    function clearTfaPending() {
        try { sessionStorage.removeItem(TFA_PENDING_KEY); } catch (e) {}
    }
    function isAlwaysAllowedPath(url) {
        if (!url) return true;
        try {
            var pathname = new URL(String(url), window.location.origin).pathname.toLowerCase();
            if (pathname.length > 1 && pathname.charAt(pathname.length - 1) === '/') {
                pathname = pathname.substring(0, pathname.length - 1);
            }
            for (var i = 0; i < TFA_ALWAYS_ALLOWED.length; i++) {
                if (pathname === TFA_ALWAYS_ALLOWED[i]) return true;
            }
            return false;
        } catch (e) { return false; }
    }
    function syntheticTfaBlockedResponse() {
        var body = '{"message":"Two-factor authentication required. Visit /Mfa/Login to complete sign in.","twoFactorRequired":true,"_tfaShortCircuit":true}';
        return new Response(body, {
            status: 403,
            statusText: 'Forbidden',
            headers: { 'Content-Type': 'application/json' }
        });
    }
    function isTfaCompletionPath(url) {
        if (!url) return false;
        var u = String(url).toLowerCase();
        return u.indexOf('/mfa/verify') >= 0
            || u.indexOf('/mfa/authenticate') >= 0;
    }

    var STYLE_ID = '__twofactor_styles';
    var SIDEBAR_ID = '__twofactor_sidebar';
    var SETTINGS_TILE_ID = '__twofactor_settings_tile';
    var MENU_ITEM_ID = '__twofactor_menu_item';
    var SETUP_URL = '/Mfa/Setup';

    // ============================================================
    // 1. Intercept fetch + XHR. If Jellyfin's auth endpoint returns
    //    401 with twoFactorRequired:true, redirect to the challenge page.
    // ============================================================

    function isAuthPath(url) {
        if (!url) return false;
        var u = String(url).toLowerCase();
        return u.indexOf('/users/authenticatebyname') >= 0
            || u.indexOf('/users/authenticatewithquickconnect') >= 0
            || /\/users\/[0-9a-f-]+\/authenticate(\?|$)/i.test(u);
    }
    // Read the access token Jellyfin Web stashed in localStorage so we can both
    // detect a logged-in shell and probe whether its token is still alive.
    function getStoredAccessToken() {
        try {
            var raw = localStorage.getItem('jellyfin_credentials');
            if (!raw) return null;
            var creds = JSON.parse(raw);
            var servers = creds && creds.Servers;
            if (servers && servers.length) {
                for (var i = 0; i < servers.length; i++) {
                    if (servers[i] && servers[i].AccessToken) return servers[i].AccessToken;
                }
            }
        } catch (e) {}
        return null;
    }
    // Kill the stale client-side session. The server has already ended the
    // session (its token is blocked), but Jellyfin Web still holds that dead
    // token in localStorage and keeps rendering a logged-in — but link-less —
    // shell while every API call 403s. Wiping the stored token forces the SPA
    // back to a logged-out state so it can't keep using the dead token.
    function killJellyfinSession() {
        try {
            var raw = localStorage.getItem('jellyfin_credentials');
            if (!raw) return;
            try {
                var creds = JSON.parse(raw);
                if (creds && creds.Servers) {
                    creds.Servers.forEach(function (s) {
                        if (s) { s.AccessToken = null; s.UserId = null; }
                    });
                    localStorage.setItem('jellyfin_credentials', JSON.stringify(creds));
                } else {
                    localStorage.removeItem('jellyfin_credentials');
                }
            } catch (e) {
                localStorage.removeItem('jellyfin_credentials');
            }
        } catch (e) {}
    }
    function handleTwoFactorBody(body) {
        if (!body || typeof body !== 'object') return false;
        if (!body.TwoFactorRequired && !body.twoFactorRequired) return false;
        if (window.__tfa_redirecting) return true;
        window.__tfa_redirecting = true;
        // Hardcode the redirect path — never trust a server-supplied URL. The
        // challenge token is the only variable part. A challenge token is only
        // present for the enrollment case (/Authenticate).
        var token = body.ChallengeToken || body.challengeToken || '';
        var url;
        if (token) {
            url = '/Mfa/Challenge?token=' + encodeURIComponent(token);
        } else {
            // Token-block failsafe (RequestBlockerMiddleware 403) carries no
            // token: the session is dead. Clear the stale client session so the
            // user isn't stranded on a broken shell, then send them to /Login to
            // re-enter username + password + code.
            killJellyfinSession();
            url = '/Mfa/Login';
        }
        console.log('[2FA] Two-factor required — redirecting to ' + url);
        // replace() so the broken/blocked page doesn't linger in history.
        window.location.replace(url);
        return true;
    }
    // Ensure every auth request carries a STABLE DeviceId so the session the
    // server creates in AuthenticateNewSession matches the deviceId this browser
    // uses on later API calls (otherwise the failsafe blocks the wrong token).
    function getStableDeviceId() {
        var id = null;
        try { id = localStorage.getItem('_deviceId2'); } catch (e) {}
        if (!id) {
            try {
                id = crypto.getRandomValues
                    ? Array.from(crypto.getRandomValues(new Uint8Array(16)))
                        .map(function(b){return b.toString(16).padStart(2,'0');}).join('')
                    : String(Date.now()) + Math.random().toString(36).slice(2);
                localStorage.setItem('_deviceId2', id);
            } catch (e) {}
        }
        return id;
    }
    function injectDeviceId(headers) {
        if (!headers) return headers;
        var id = getStableDeviceId();
        if (!id) return headers;
        try {
            if (headers instanceof Headers) {
                var existing = headers.get('X-Emby-Authorization') || '';
                if (existing && /DeviceId=/i.test(existing)) {
                    existing = existing.replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                    headers.set('X-Emby-Authorization', existing);
                }
                headers.set('X-Emby-Device-Id', id);
            } else if (typeof headers === 'object') {
                headers['X-Emby-Device-Id'] = id;
                if (headers['X-Emby-Authorization'] && /DeviceId=/i.test(headers['X-Emby-Authorization'])) {
                    headers['X-Emby-Authorization'] = headers['X-Emby-Authorization']
                        .replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                }
            }
        } catch (e) {}
        return headers;
    }

    var origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (origFetch) {
        window.fetch = function (input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';

            if (isTfaPending() && !isAlwaysAllowedPath(url) && !isAuthPath(url)) {
                return Promise.resolve(syntheticTfaBlockedResponse());
            }

            if (isAuthPath(url)) {
                init = init || {};
                init.headers = injectDeviceId(init.headers || new Headers());
            }
            var p = origFetch(input, init);
            return p.then(function (resp) {
                if (resp.ok && isTfaCompletionPath(url)) {
                    clearTfaPending();
                    return resp;
                }
                if (resp.status !== 401 && resp.status !== 403) return resp;
                var clone = resp.clone();
                return clone.json().then(function (body) {
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                        // Redirect to complete 2FA — works for both the auth-path
                        // enrollment challenge (carries a token) and the token-block
                        // failsafe 403 from any endpoint (no token → /Login).
                        if (handleTwoFactorBody(body)) {
                            return new Promise(function () {});
                        }
                    }
                    return resp;
                }).catch(function () { return resp; });
            });
        };
    }
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    var origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function (method, url) {
        this.__tfa_url = url;
        this.__tfa_authHeader = null;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
        if (typeof name === 'string' && name.toLowerCase() === 'x-emby-authorization') {
            this.__tfa_authHeader = value;
        }
        return origSetHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (isAuthPath(xhr.__tfa_url)) {
            try {
                var id = getStableDeviceId();
                if (id) {
                    origSetHeader.call(xhr, 'X-Emby-Device-Id', id);
                    if (xhr.__tfa_authHeader && /DeviceId=/i.test(xhr.__tfa_authHeader)) {
                        var patched = xhr.__tfa_authHeader.replace(/DeviceId="[^"]*"/i, 'DeviceId="' + id + '"');
                        origSetHeader.call(xhr, 'X-Emby-Authorization', patched);
                    }
                }
            } catch (e) {}
            xhr.addEventListener('readystatechange', function () {
                if (xhr.readyState !== 4) return;
                if (xhr.status !== 401 && xhr.status !== 403) return;
                try {
                    var body = JSON.parse(xhr.responseText || '{}');
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                    }
                    handleTwoFactorBody(body);
                } catch (e) {}
            });
        } else {
            xhr.addEventListener('readystatechange', function () {
                if (xhr.readyState !== 4) return;
                if (xhr.status !== 401 && xhr.status !== 403) return;
                try {
                    var body = JSON.parse(xhr.responseText || '{}');
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        setTfaPending();
                        handleTwoFactorBody(body);
                    }
                } catch (e) {}
            });
        }
        return origSend.apply(this, arguments);
    };

    // ============================================================
    // 2. Sidebar / dashboard / settings entries pointing at the
    //    Setup page and the admin config page.
    // ============================================================

    var DASHBOARD_NAV_ID = '__twofactor_dashnav';
    function injectDashboardNav() {
        try {
            var hash = (window.location.hash || '').toLowerCase();
            if (hash.indexOf('dashboard') < 0 && hash.indexOf('plugin') < 0
                && hash.indexOf('scheduledtask') < 0 && hash.indexOf('users') < 0
                && hash.indexOf('library') < 0 && hash.indexOf('configuration') < 0
                && hash.indexOf('serveractivity') < 0 && hash.indexOf('apikeys') < 0) {
                return;
            }
            if (document.getElementById(DASHBOARD_NAV_ID)) return;
            try {
                if (window.ApiClient && ApiClient.getCurrentUser) {
                    ApiClient.getCurrentUser().then(function(u) {
                        var isAdmin = u && u.Policy && u.Policy.IsAdministrator;
                        if (!isAdmin) return;
                        injectDashboardNavInner();
                    });
                    return;
                }
            } catch (e) { /* fall through */ }
            injectDashboardNavInner();
        } catch (outerE) {
            console.error('[2FA] injectDashboardNav outer error:', outerE);
        }
    }
    function injectDashboardNavInner() {
        try {
            if (document.getElementById(DASHBOARD_NAV_ID)) return;

            var anchor = null;
            var navLinks = document.querySelectorAll('a.navMenuOption, a.navDrawer-button, a[href*="/dashboard"]');
            for (var i = 0; i < navLinks.length; i++) {
                var t = (navLinks[i].textContent || '').trim().toLowerCase();
                if (t === 'plugins' || t.indexOf('plugins') === 0) { anchor = navLinks[i]; break; }
            }
            if (!anchor) return;

            var parent = anchor.parentElement;
            if (!parent) return;

            var a = document.createElement('a');
            a.id = DASHBOARD_NAV_ID;
            a.href = '#';
            a.className = anchor.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            a.addEventListener('click', function (e) {
                e.preventDefault();
                window.location.assign('/web/index.html#!/configurationpage?name=Mfa');
            });
            a.innerHTML =
                '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                '<span class="navMenuOptionText">Two-Factor Auth</span>';

            if (anchor.nextSibling) parent.insertBefore(a, anchor.nextSibling);
            else parent.appendChild(a);
        } catch (e) {
            console.error('[2FA] injectDashboardNav error:', e);
        }
    }

    function injectSidebar() {
        try {
            if (document.getElementById(SIDEBAR_ID)) return;
            var allItems = document.querySelectorAll('.navMenuOption');
            if (!allItems.length) return;

            var anchorItem = null;
            var placement = 'after';
            for (var i = 0; i < allItems.length; i++) {
                var txt = (allItems[i].textContent || '').trim().toLowerCase();
                if (txt === 'settings' || txt === 'preferences' || txt === 'profile') {
                    anchorItem = allItems[i]; placement = 'after'; break;
                }
            }
            if (!anchorItem) {
                for (var j = 0; j < allItems.length; j++) {
                    var href = (allItems[j].getAttribute('href') || '').toLowerCase();
                    if (href.indexOf('mypreferencesmenu') >= 0 || href.indexOf('myprofile') >= 0) {
                        anchorItem = allItems[j]; placement = 'after'; break;
                    }
                }
            }
            if (!anchorItem) { anchorItem = allItems[0]; placement = 'before'; }

            var parent = anchorItem.parentElement;
            if (!parent) return;

            var a = document.createElement('a');
            a.id = SIDEBAR_ID;
            // Don't set href — Jellyfin's emby-linkbutton + SPA router would
            // rewrite /Mfa/Setup into the hash route /web/index.html#/Mfa/Setup,
            // which 404s. Use a click handler for a hard navigation that leaves
            // the SPA entirely (same lesson as injectSettingsTile).
            a.className = anchorItem.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
            a.addEventListener('click', function (e) {
                e.preventDefault();
                window.location.assign(SETUP_URL);
            });
            a.innerHTML =
                '<span class="material-icons navMenuOptionIcon" style="font-family:Material Icons;" aria-hidden="true">security</span>' +
                '<span class="navMenuOptionText">Two-Factor Auth</span>';

            if (placement === 'after') {
                if (anchorItem.nextSibling) parent.insertBefore(a, anchorItem.nextSibling);
                else parent.appendChild(a);
            } else {
                parent.insertBefore(a, anchorItem);
            }
        } catch (e) {
            console.error('[2FA] injectSidebar error:', e);
        }
    }

    function injectSettingsTile() {
        try {
            var hash = (window.location.hash || '').toLowerCase();
            var onPrefsPage = hash.indexOf('mypreferencesmenu') >= 0
                || hash.indexOf('userprofile') >= 0
                || hash.indexOf('myprofile') >= 0
                || hash.indexOf('preferences') >= 0;
            if (!onPrefsPage) return;
            if (document.getElementById(SETTINGS_TILE_ID)) return;

            var profile = null;
            var all = document.querySelectorAll('a, button');
            for (var i = 0; i < all.length; i++) {
                var txt = (all[i].textContent || '').trim().toLowerCase();
                if (txt === 'profile' || txt.indexOf('profile') === 0) {
                    profile = all[i];
                    break;
                }
            }
            if (!profile) return;

            var template = profile;
            var container = profile.parentElement;
            while (container && container !== document.body) {
                var siblingTiles = 0;
                var children = container.children || [];
                for (var j = 0; j < children.length; j++) {
                    var c = children[j];
                    if (c === template) continue;
                    var tn = c.tagName ? c.tagName.toLowerCase() : '';
                    if (tn === 'a' || tn === 'button' || (c.className && /listItem|cardBox|button-link/i.test(c.className))) {
                        siblingTiles++;
                        if (siblingTiles >= 1) break;
                    }
                }
                if (siblingTiles >= 1) break;
                template = container;
                container = container.parentElement;
            }
            if (!container || container === document.body) return;

            var tile = document.createElement('a');
            tile.id = SETTINGS_TILE_ID;
            tile.style.cursor = 'pointer';
            tile.addEventListener('click', function (e) {
                e.preventDefault();
                window.location.assign('/Mfa/Setup');
            });
            tile.className = 'listItem listItem-border listItem-button';
            tile.innerHTML =
                '<span class="material-icons listItemIcon listItemIcon-transparent" aria-hidden="true" style="font-family:\'Material Icons\';">security</span>' +
                '<div class="listItemBody">' +
                    '<div class="listItemBodyText">Two-Factor Authentication</div>' +
                '</div>' +
                '<span class="material-icons" aria-hidden="true" style="font-family:\'Material Icons\';margin-left:auto;opacity:0.5;">chevron_right</span>';

            if (template.nextSibling) container.insertBefore(tile, template.nextSibling);
            else container.appendChild(tile);
        } catch (e) {
            console.error('[2FA] injectSettingsTile error:', e);
        }
    }

    // ============================================================
    // 2b. User-menu link — add a "Two-Factor Auth" entry next to every
    //     profile/settings link Jellyfin renders, so signed-in users can
    //     reach the Setup (enroll/disable) page from the avatar dropdown /
    //     side drawer. Themed skins relocate the settings link and several
    //     drawers can be visible at once, so we don't guess which is "the"
    //     menu — we mirror every settings anchor we find.
    // ============================================================
    function addUserMenuLink() {
        try {
            // Match any anchor whose href targets the user preferences/profile
            // pages. Covers vanilla Jellyfin, Jellyfin-Vue, and most themes.
            var anchors = document.querySelectorAll(
                'a[href*="mypreferencesmenu"],' +
                ' a[href*="myprofile"],' +
                ' a[href*="userprofile"],' +
                ' a[href*="useredit"],' +
                ' a[href*="quickconnect"]'
            );
            if (!anchors.length) return;

            var added = 0;
            anchors.forEach(function (anchor) {
                var container = anchor.parentNode;
                if (!container) return;
                // Don't double-inject within the same container.
                if (container.querySelector('[data-mfa-link="1"]')) return;

                // Deep-clone the real menu anchor so our entry inherits the
                // EXACT markup, classes and (class-based) hover styling of its
                // siblings — building markup by hand left it smaller, misaligned
                // and without the hover highlight.
                var item = anchor.cloneNode(true);
                item.setAttribute('data-mfa-link', '1');
                item.id = MENU_ITEM_ID + '_' + added;
                // Drop the cloned href + any router data so Jellyfin's SPA can't
                // hijack the click into a 404 hash route; navigate hard instead.
                item.removeAttribute('href');
                item.removeAttribute('data-href');
                item.style.cursor = 'pointer';
                item.addEventListener('click', function (e) {
                    e.preventDefault();
                    window.location.assign(SETUP_URL);
                });

                // Keep the cloned item's own icon exactly as-is. Don't rewrite its
                // glyph: many Jellyfin icons get their glyph from a CSS class on the
                // span, so setting textContent renders a SECOND ligature glyph that
                // overlaps the label. We only need `icon` below to skip its text
                // node when relabelling.
                var icon = item.querySelector('.material-icons');

                // Swap the label: prefer a known text container, else replace the
                // longest text node that isn't the icon glyph.
                var labelEl = item.querySelector(
                    '.navMenuOptionText, .listItemBodyText, .actionSheetMenuItemText, .button-text');
                if (labelEl) {
                    labelEl.textContent = 'Two-Factor Auth';
                } else {
                    var walker = document.createTreeWalker(item, NodeFilter.SHOW_TEXT, null);
                    var best = null, bestLen = -1, n;
                    while ((n = walker.nextNode())) {
                        if (icon && icon.contains(n)) continue;
                        var t = (n.nodeValue || '').trim();
                        if (t.length > bestLen) { best = n; bestLen = t.length; }
                    }
                    if (best) { best.nodeValue = 'Two-Factor Auth'; }
                    else { item.appendChild(document.createTextNode('Two-Factor Auth')); }
                }

                if (anchor.nextSibling) container.insertBefore(item, anchor.nextSibling);
                else container.appendChild(item);
                added++;
            });
        } catch (e) {
            console.error('[2FA] addUserMenuLink error:', e);
        }
    }

    // ============================================================
    // 3. Native login form — inject a "2FA code" field and reroute the
    //    submit through /Mfa/Authenticate, so the standard Jellyfin web
    //    login page is the ONE login page (username + password + code).
    //    Third-party clients never load this script and are unaffected.
    // ============================================================

    var CODE_FIELD_ID = '__mfa_code_field';
    var CODE_ERROR_ID = '__mfa_login_error';

    function isLoginPage() {
        var hash = window.location.hash || '';
        return hash.indexOf('login') >= 0 || hash === '' || hash === '#';
    }
    function getLoginUsernameInput() {
        return document.querySelector('input#txtManualName, .manualLoginForm input[type="text"], input[name="username"], input#username');
    }
    function getLoginPasswordInput() {
        return document.querySelector('input#txtManualPassword, .manualLoginForm input[type="password"], input[name="password"], input#password');
    }
    function addStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent =
            '#' + CODE_FIELD_ID + ' { letter-spacing:0.3em; }' +
            '.__mfa-toggle { display:inline-block; margin:2px 0 6px; font-size:0.85em; color:#00a4dc; cursor:pointer; text-decoration:none; }' +
            '.__mfa-toggle:hover { text-decoration:underline; }' +
            '#' + CODE_ERROR_ID + ' { color:#f44336; font-size:0.85em; margin:4px 0 8px; display:none; }' +
            '#' + CODE_ERROR_ID + '.show { display:block; }';
        document.head.appendChild(style);
    }

    // Inject the code field + recovery toggle into the manual login form,
    // styled by cloning the password field's container so it matches the active
    // theme exactly. Idempotent; re-runs harmlessly via the bootstrap observer.
    function injectLoginCodeField() {
        if (!isLoginPage()) return;
        if (document.getElementById(CODE_FIELD_ID)) return;
        var pw = getLoginPasswordInput();
        if (!pw) return; // manual form not in the DOM (e.g. avatar picker shown)
        addStyles();

        var pwContainer = (pw.closest && pw.closest('.inputContainer')) || pw.parentElement;
        if (!pwContainer || !pwContainer.parentNode) return;

        var container = pwContainer.cloneNode(true);
        var input = container.querySelector('input');
        if (!input) return;
        input.id = CODE_FIELD_ID;
        input.setAttribute('type', 'text');
        input.setAttribute('inputmode', 'numeric');
        input.setAttribute('autocomplete', 'one-time-code');
        input.setAttribute('maxlength', '6');
        input.setAttribute('placeholder', '000000');
        input.removeAttribute('required');
        input.removeAttribute('name');
        input.value = '';

        var lbl = container.querySelector('label');
        if (lbl) { lbl.removeAttribute('for'); lbl.textContent = "2FA code (leave blank if you haven't set it up)"; }
        var desc = container.querySelector('.fieldDescription');
        if (desc && desc.parentNode) desc.parentNode.removeChild(desc);

        var recovery = { on: false };
        input.addEventListener('input', function () {
            if (recovery.on) {
                input.value = input.value.toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 14);
            } else {
                input.value = input.value.replace(/\D/g, '').slice(0, 6);
            }
        });

        var toggle = document.createElement('a');
        toggle.className = '__mfa-toggle';
        toggle.href = '#';
        toggle.textContent = 'Use a recovery code instead';
        toggle.addEventListener('click', function (e) {
            e.preventDefault();
            recovery.on = !recovery.on;
            if (recovery.on) {
                input.setAttribute('maxlength', '14');
                input.setAttribute('placeholder', 'XXXXX-XXXXX');
                input.setAttribute('inputmode', 'text');
                if (lbl) lbl.textContent = 'Recovery code (format: XXXXX-XXXXX)';
                toggle.textContent = 'Use 6-digit code instead';
            } else {
                input.setAttribute('maxlength', '6');
                input.setAttribute('placeholder', '000000');
                input.setAttribute('inputmode', 'numeric');
                if (lbl) lbl.textContent = "2FA code (leave blank if you haven't set it up)";
                toggle.textContent = 'Use a recovery code instead';
            }
            input.value = '';
            input.focus();
        });

        var err = document.createElement('div');
        err.id = CODE_ERROR_ID;

        pwContainer.parentNode.insertBefore(container, pwContainer.nextSibling);
        container.parentNode.insertBefore(toggle, container.nextSibling);
        toggle.parentNode.insertBefore(err, toggle.nextSibling);
    }

    function showLoginError(msg) {
        var el = document.getElementById(CODE_ERROR_ID);
        if (el) { el.textContent = msg; el.classList.add('show'); }
    }
    function clearLoginError() {
        var el = document.getElementById(CODE_ERROR_ID);
        if (el) el.classList.remove('show');
    }

    // Persist the AccessToken so the SPA loads logged-in after we reload /web.
    // Ported from login.html's storeCredentials().
    function storeMfaCredentials(authData) {
        return fetch('/System/Info/Public').then(function (r) { return r.ok ? r.json() : null; }).then(function (info) {
            var serverId = authData.ServerId || (info && info.Id) || '';
            var serverName = (info && info.ServerName) || 'Jellyfin';
            var serverAddress = window.location.origin;
            var creds;
            try { creds = JSON.parse(localStorage.getItem('jellyfin_credentials') || '{}'); } catch (e) { creds = {}; }
            if (!creds.Servers) creds.Servers = [];
            var existing = creds.Servers.find(function (s) { return s.Id === serverId; });
            var now = Date.now();
            if (existing) {
                existing.AccessToken = authData.AccessToken;
                existing.UserId = authData.User && authData.User.Id;
                existing.DateLastAccessed = now;
                if (!existing.ManualAddress) existing.ManualAddress = serverAddress;
                if (!existing.Name) existing.Name = serverName;
            } else {
                creds.Servers.unshift({
                    Id: serverId, Name: serverName,
                    AccessToken: authData.AccessToken,
                    UserId: authData.User && authData.User.Id,
                    ManualAddress: serverAddress, DateLastAccessed: now, LastConnectionMode: 1
                });
            }
            localStorage.setItem('jellyfin_credentials', JSON.stringify(creds));
        }).catch(function () { /* best effort */ });
    }

    // Run the plugin login flow for a manual web sign-in.
    function submitMfaLogin(username, password, code, submitBtn) {
        if (window.__mfa_submitting) return;
        window.__mfa_submitting = true;
        clearLoginError();
        var restore = submitBtn ? submitBtn.innerHTML : null;
        if (submitBtn) submitBtn.disabled = true;

        function reenable() {
            window.__mfa_submitting = false;
            if (submitBtn) { submitBtn.disabled = false; if (restore != null) submitBtn.innerHTML = restore; }
        }

        var deviceId = getStableDeviceId();
        fetch('/Mfa/Authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Emby-Device-Id': deviceId,
                'X-Emby-Device-Name': 'Jellyfin Web'
            },
            body: JSON.stringify({ username: username, password: password, code: code })
        }).then(function (r) {
            if (r.ok) return r.json();
            return r.json().catch(function () { return { message: 'Sign in failed (' + r.status + ').' }; }).then(function (body) {
                if (body && (body.TwoFactorRequired || body.twoFactorRequired)) {
                    // Enrollment required — go enroll, then come back signed in.
                    var ct = body.ChallengeToken || body.challengeToken || '';
                    window.location.assign('/Mfa/Challenge?token=' + encodeURIComponent(ct));
                    return null;
                }
                reenable();
                showLoginError((body && body.message) || 'Sign in failed.');
                return null;
            });
        }).then(function (authData) {
            if (!authData) return;
            storeMfaCredentials(authData).then(function () {
                window.location.assign('/web/index.html');
            });
        }).catch(function () {
            reenable();
            showLoginError('Network error. Check your connection and try again.');
        });
    }

    // Capture-phase interception of the native manual-login submit so it flows
    // through /Mfa/Authenticate (password + code validated together, token only
    // minted after). Idempotent; re-wires if the SPA replaced the form node.
    function wireLoginSubmitInterception() {
        if (!isLoginPage()) return;
        var pw = getLoginPasswordInput();
        if (!pw) return;
        var form = (pw.closest && pw.closest('form')) || document.querySelector('.manualLoginForm, #loginPage form');
        var btn = document.querySelector('.manualLoginForm button[type="submit"], #loginPage form button[type="submit"], form button[type="submit"]');

        function handler(e) {
            // Only intercept once our field exists (confirms this is our manual form).
            if (!document.getElementById(CODE_FIELD_ID)) return;
            var userInput = getLoginUsernameInput();
            var passInput = getLoginPasswordInput();
            var codeInput = document.getElementById(CODE_FIELD_ID);
            var username = userInput && userInput.value ? userInput.value.trim() : '';
            var password = passInput ? passInput.value : '';
            // Leave empty creds to Jellyfin's own field validation.
            if (!username || !password) return;
            e.preventDefault();
            e.stopImmediatePropagation();
            submitMfaLogin(username, password, codeInput ? codeInput.value.trim() : '', btn);
        }

        if (form && !form.__mfaWired) {
            form.addEventListener('submit', handler, true);
            form.__mfaWired = true;
        }
        if (btn && !btn.__mfaWired) {
            btn.addEventListener('click', handler, true);
            btn.__mfaWired = true;
        }
    }

    // ============================================================
    // Bootstrap — MutationObserver + 1s polling for 60s.
    // ============================================================

    function tryInject() {
        injectLoginCodeField();
        wireLoginSubmitInterception();
        injectSidebar();
        injectDashboardNav();
        injectSettingsTile();
        addUserMenuLink();
    }

    // Self-heal a stranded session. If this tab loaded into a logged-in shell
    // whose token is blocked (an old password-only session, or the SPA fired its
    // post-load API burst before this script installed its fetch/XHR hooks), the
    // user can end up on a link-less page where every call 403s and there's no
    // way out. Probe one authenticated endpoint on load; if it reports
    // twoFactorRequired, handleTwoFactorBody() kills the dead session and bounces
    // to /Mfa/Login. Only runs when a stored token exists (i.e. apparently
    // logged in); healthy sessions get a 200 and nothing happens.
    function selfHealIfBlocked() {
        var token = getStoredAccessToken();
        if (!token) return;
        try {
            (origFetch || window.fetch)('/Users/Me', {
                headers: { 'X-Emby-Token': token },
                cache: 'no-store'
            }).then(function (resp) {
                if (!resp || (resp.status !== 401 && resp.status !== 403)) return;
                return resp.clone().json().then(function (body) {
                    if (body && (body.twoFactorRequired || body.TwoFactorRequired)) {
                        handleTwoFactorBody(body);
                    }
                }).catch(function () {});
            }).catch(function () {});
        } catch (e) {}
    }

    function start() {
        selfHealIfBlocked();
        tryInject();

        var attempts = 0;
        var maxAttempts = 60;
        var poll = setInterval(function () {
            attempts++;
            tryInject();
            if (attempts >= maxAttempts || (document.getElementById(SIDEBAR_ID))) clearInterval(poll);
        }, 1000);

        var moPending = false;
        var mo = new MutationObserver(function () {
            if (moPending) return;
            moPending = true;
            setTimeout(function () { moPending = false; tryInject(); }, 250);
        });
        mo.observe(document.body, { childList: true, subtree: true });

        window.addEventListener('hashchange', tryInject);
        window.addEventListener('popstate', tryInject);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
