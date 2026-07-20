/**
 * Theme management. Load in <head> BEFORE CSS to prevent flash of wrong theme.
 */
(function () {
    const KEY = 'shadowsensor-theme';
    const DEFAULT = 'dark';

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        const btn = document.getElementById('theme-toggle-btn');
        if (btn) {
            const icon = btn.querySelector('.theme-icon');
            if (icon) {
                icon.textContent = theme === 'dark' ? '☀' : '☾';
            }
            btn.title = theme === 'dark' ? 'Switch to light' : 'Switch to dark';
        }
    }

    function saved() {
        try { return localStorage.getItem(KEY) || DEFAULT; } catch { return DEFAULT; }
    }

    window.toggleTheme = function () {
        const cur = document.documentElement.getAttribute('data-theme') || DEFAULT;
        const next = cur === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(KEY, next); } catch {}
        applyTheme(next);
    };

    applyTheme(saved());
})();
