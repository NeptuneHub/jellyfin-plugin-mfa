(function () {
    if (window.__twofactor_injected) return;
    window.__twofactor_injected = true;

    console.log('[2FA] inject.js v3.0.0 loaded');

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
        '/twofactorauth/login',
        '/twofactorauth/setup',
        '/twofactorauth/authenticate',
        '/twofactorauth/verify',
        '/twofactorauth/challenge',
        '/twofactorauth/inject.js'
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
        var body = '{"message":"Two-factor authentication required. Visit /TwoFactorAuth/Login to complete sign in.","twoFactorRequired":true,"_tfaShortCircuit":true}';
        return new Response(body, {
            status: 403,
            statusText: 'Forbidden',
            headers: { 'Content-Type': 'application/json' }
        });
    }
    function isTfaCompletionPath(url) {
        if (!url) return false;
        var u = String(url).toLowerCase();
        return u.indexOf('/twofactorauth/verify') >= 0
            || u.indexOf('/twofactorauth/authenticate') >= 0;
    }

    var BUTTON_ID = '__twofactor_login_btn';
    var STYLE_ID = '__twofactor_styles';
    var SIDEBAR_ID = '__twofactor_sidebar';
    var SETTINGS_TILE_ID = '__twofactor_settings_tile';

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
    function handleTwoFactorBody(body) {
        if (!body || typeof body !== 'object') return false;
        if (!body.TwoFactorRequired && !body.twoFactorRequired) return false;
        if (window.__tfa_redirecting) return true;
        window.__tfa_redirecting = true;
        // Hardcode the redirect path — never trust a server-supplied URL. The
        // challenge token is the only variable part. A challenge token is only
        // present for the enrollment case (/Authenticate). The token-block
        // failsafe (RequestBlockerMiddleware 403) carries no token, so route
        // those to /Login where the user re-enters username + password + code.
        var token = body.ChallengeToken || body.challengeToken || '';
        var url = token
            ? '/TwoFactorAuth/Challenge?token=' + encodeURIComponent(token)
            : '/TwoFactorAuth/Login';
        console.log('[2FA] Two-factor required — redirecting to ' + url);
        window.location.href = url;
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
                window.location.assign('/web/index.html#!/configurationpage?name=TwoFactorAuth');
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
            a.href = '/TwoFactorAuth/Setup';
            a.className = anchorItem.className || 'navMenuOption emby-button';
            a.setAttribute('role', 'menuitem');
            a.style.cursor = 'pointer';
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
                window.location.assign('/TwoFactorAuth/Setup');
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
    // 3. Login-form button — "Sign in with Two-Factor Authentication".
    // ============================================================

    function addStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent =
            '#' + BUTTON_ID + ' {' +
                'display:block;box-sizing:border-box;width:100%;' +
                'padding:0.9em 1em;margin-top:0.5em;' +
                'background:transparent;color:inherit;' +
                'border:1px solid rgba(255,255,255,0.2);border-radius:0.2em;' +
                'font-family:inherit;font-size:inherit;font-weight:inherit;line-height:inherit;letter-spacing:inherit;' +
                'text-transform:inherit;text-decoration:none;text-align:center;' +
                'cursor:pointer;-webkit-appearance:none;appearance:none;' +
                'transition:background-color 0.15s ease;' +
            '}' +
            '#' + BUTTON_ID + ':hover { background:rgba(255,255,255,0.08); }' +
            '#' + BUTTON_ID + ' .tfa-icon { margin-right:0.4em;vertical-align:middle; }';
        document.head.appendChild(style);
    }
    function isLoginPage() {
        var hash = window.location.hash || '';
        return hash.indexOf('login') >= 0 || hash === '' || hash === '#';
    }
    function findUsername() {
        var input = document.querySelector('input#txtManualName, input[name="username"], input#username, .manualLoginForm input[type="text"]:not([type="password"])');
        return input && input.value ? input.value.trim() : '';
    }
    function addLoginButton() {
        if (!isLoginPage()) return;
        if (document.getElementById(BUTTON_ID)) return;
        var signInBtn = document.querySelector('.manualLoginForm button[type="submit"], .manualLoginForm .raised, form button[type="submit"]');
        if (!signInBtn) return;
        addStyles();
        var btn = document.createElement('a');
        btn.id = BUTTON_ID;
        btn.setAttribute('is', 'emby-linkbutton');
        btn.className = (signInBtn.className || 'raised block').replace(/button-submit|button-cancel|emby-button/g, '').trim();
        btn.innerHTML = '<span class="tfa-icon">🔐</span>Sign in with Two-Factor Authentication';
        btn.href = '/TwoFactorAuth/Login';
        function updateHref() {
            var u = findUsername();
            btn.href = u ? '/TwoFactorAuth/Login?username=' + encodeURIComponent(u) : '/TwoFactorAuth/Login';
        }
        btn.addEventListener('click', function (e) { e.preventDefault(); updateHref(); window.location.assign(btn.href); });
        var userInput = document.querySelector('input#txtManualName, input[name="username"], input#username');
        if (userInput) ['input', 'change', 'blur'].forEach(function (ev) { userInput.addEventListener(ev, updateHref); });
        var parent = signInBtn.parentNode;
        if (signInBtn.nextSibling) parent.insertBefore(btn, signInBtn.nextSibling);
        else parent.appendChild(btn);
    }

    // ============================================================
    // Bootstrap — MutationObserver + 1s polling for 60s.
    // ============================================================

    function tryInject() {
        addLoginButton();
        injectSidebar();
        injectDashboardNav();
        injectSettingsTile();
    }

    function start() {
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
