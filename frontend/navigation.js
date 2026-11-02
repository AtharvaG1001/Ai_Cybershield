// =========================================================
//  AI SHIELD — Navigation & Sidebar Manager
// =========================================================

const SIDEBAR_KEY = 'ai-shield-sidebar';

/* ============================= */
/* PAGE SWITCHING                */
/* ============================= */

function showPage(page, element) {

    const pages = [
        'dashboardPage',
        'emailPage',
        'historyPage',
        'reportsPage',
        'settingsPage'
    ];

    pages.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    document.querySelectorAll('.menu-item').forEach(item => {
        item.classList.remove('active');
    });

    const target = document.getElementById(page + 'Page');

    if (target) {
        target.style.display = 'block';
        target.style.animation = 'fadeIn 0.4s ease';
    }

    if (element) element.classList.add('active');

    if (page === 'history' && typeof loadHistory === 'function') {
        loadHistory();
    }

    if (window.innerWidth <= 900) {
        closeSidebar();
    }
}

/* ============================= */
/* SIDEBAR TOGGLE                */
/* ============================= */

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const main = document.querySelector('.main-content');
    const btn = document.getElementById('sidebarToggle');
    const overlay = document.getElementById('sidebarOverlay');

    if (!sidebar) return;

    const isCollapsed = !sidebar.classList.contains('collapsed');

    if (isCollapsed) {
        sidebar.classList.add('collapsed');
        if (main) main.classList.add('sidebar-collapsed');
        if (btn) btn.classList.add('collapsed');
        if (overlay && window.innerWidth <= 900) overlay.classList.remove('active');
    } else {
        sidebar.classList.remove('collapsed');
        if (main) main.classList.remove('sidebar-collapsed');
        if (btn) btn.classList.remove('collapsed');
        if (overlay && window.innerWidth <= 900) overlay.classList.add('active');
    }

    // Update icon
    if (btn) {
        const icon = btn.querySelector('i');
        if (icon) {
            icon.className = isCollapsed
                ? 'fa-solid fa-chevron-right'
                : 'fa-solid fa-chevron-left';
        }
    }

    localStorage.setItem(SIDEBAR_KEY, isCollapsed ? 'collapsed' : 'expanded');
}

function openSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const main = document.querySelector('.main-content');
    const btn = document.getElementById('sidebarToggle');
    const overlay = document.getElementById('sidebarOverlay');

    if (sidebar) sidebar.classList.remove('collapsed');
    if (main) main.classList.remove('sidebar-collapsed');
    if (btn) btn.classList.remove('collapsed');
    if (overlay) overlay.classList.add('active');

    const icon = btn?.querySelector('i');
    if (icon) icon.className = 'fa-solid fa-chevron-left';

    localStorage.setItem(SIDEBAR_KEY, 'expanded');
}

function closeSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const main = document.querySelector('.main-content');
    const btn = document.getElementById('sidebarToggle');
    const overlay = document.getElementById('sidebarOverlay');

    if (sidebar) sidebar.classList.add('collapsed');
    if (main) main.classList.add('sidebar-collapsed');
    if (btn) btn.classList.add('collapsed');
    if (overlay) overlay.classList.remove('active');

    const icon = btn?.querySelector('i');
    if (icon) icon.className = 'fa-solid fa-chevron-right';

    localStorage.setItem(SIDEBAR_KEY, 'collapsed');
}

function initSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const btn = document.getElementById('sidebarToggle');
    const savedState = localStorage.getItem(SIDEBAR_KEY);
    const isMobile = window.innerWidth <= 900;

    // Default: expanded on desktop, collapsed on mobile
    const shouldCollapse = savedState
        ? savedState === 'collapsed'
        : isMobile;

    if (shouldCollapse) {
        sidebar?.classList.add('collapsed');
        document.querySelector('.main-content')?.classList.add('sidebar-collapsed');
        btn?.classList.add('collapsed');
        const icon = btn?.querySelector('i');
        if (icon) icon.className = 'fa-solid fa-chevron-right';
    } else {
        sidebar?.classList.remove('collapsed');
        document.querySelector('.main-content')?.classList.remove('sidebar-collapsed');
        btn?.classList.remove('collapsed');
        const icon = btn?.querySelector('i');
        if (icon) icon.className = 'fa-solid fa-chevron-left';
    }
}

/* ============================= */
/* MOBILE OVERLAY                */
/* ============================= */

function initMobileOverlay() {
    if (!document.getElementById('sidebarOverlay')) {
        const overlay = document.createElement('div');
        overlay.id = 'sidebarOverlay';
        overlay.className = 'sidebar-overlay';
        overlay.onclick = closeSidebar;
        document.body.appendChild(overlay);
    }
}

/* ============================= */
/* KEYBOARD SHORTCUTS            */
/* ============================= */

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        toggleSidebar();
    }
    if (e.altKey) {
        const menuItems = document.querySelectorAll('.menu-item');
        const num = parseInt(e.key);
        if (num >= 1 && num <= menuItems.length) {
            e.preventDefault();
            menuItems[num - 1].click();
        }
    }
});

/* ============================= */
/* INIT                          */
/* ============================= */

window.addEventListener('DOMContentLoaded', () => {
    initMobileOverlay();
    initSidebar();

    const firstMenu = document.querySelector('.menu-item');
    if (firstMenu) showPage('dashboard', firstMenu);
});

window.addEventListener('resize', () => {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;

    const isMobile = window.innerWidth <= 900;
    const overlay = document.getElementById('sidebarOverlay');

    if (isMobile) {
        sidebar.classList.add('collapsed');
        if (overlay) overlay.classList.remove('active');
    } else {
        const saved = localStorage.getItem(SIDEBAR_KEY);
        if (saved === 'expanded') {
            sidebar.classList.remove('collapsed');
        }
    }
});