// =========================================================
//  AI SHIELD — Theme Manager
// =========================================================

const THEME_KEY = 'ai-shield-theme';

/**
 * Apply theme to body and sync toggle state
 * @param {string} theme - 'dark' | 'light'
 */
function applyTheme(theme) {
    const body = document.body;
    const toggle = document.getElementById('themeToggle');

    if (theme === 'light') {
        body.classList.add('light-mode');
        if (toggle) toggle.checked = false; // unchecked = light
    } else {
        body.classList.remove('light-mode');
        if (toggle) toggle.checked = true;  // checked = dark (default)
    }
}

/**
 * Toggle handler — called from checkbox onchange
 */
function toggleTheme() {
    const toggle = document.getElementById('themeToggle');
    const isDark = toggle ? toggle.checked : true;

    const newTheme = isDark ? 'dark' : 'light';
    applyTheme(newTheme);
    localStorage.setItem(THEME_KEY, newTheme);
}

/**
 * Initialize theme on page load
 */
function initTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);

    // Default to dark if nothing saved
    const theme = savedTheme || 'dark';
    applyTheme(theme);
}

// Run on DOM ready
window.addEventListener('DOMContentLoaded', initTheme);