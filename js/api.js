// Shared auth + API helpers for all Quizzery pages
(function () {
  let _token = localStorage.getItem('quizzery-token');
  let _user = localStorage.getItem('quizzery-user');

  window.getToken = () => _token;
  window.getCurrentUser = () => _user;

  window.setAuth = function (token, username) {
    _token = token;
    _user = username;
    localStorage.setItem('quizzery-token', token);
    localStorage.setItem('quizzery-user', username);
  };

  window.clearAuth = function () {
    _token = null;
    _user = null;
    localStorage.removeItem('quizzery-token');
    localStorage.removeItem('quizzery-user');
  };

  window.api = async function (method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (_token) opts.headers['Authorization'] = `Bearer ${_token}`;
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (res.status === 401) {
      clearAuth();
      window.location.href = '/';
      return null;
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  };

  window.doLogout = function () {
    clearAuth();
    window.location.href = '/';
  };

  window.requireAuth = function () {
    if (!_token) {
      window.location.href = '/';
      return false;
    }
    return true;
  };

  window.initSidebar = function (activePage) {
    const navPages = [
      { page: 'memorize', label: 'Memorize', href: '/memorize' },
      { page: 'read',     label: 'Read',     href: '/read'     },
    ];

    const navLinks = navPages.map(p =>
      `<a class="sidebar-link${p.page === activePage ? ' active' : ''}" data-page="${p.page}" href="${p.href}">${p.label}</a>`
    ).join('');

    const layout = document.querySelector('.layout');

    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    overlay.id = 'sidebarOverlay';
    layout.parentNode.insertBefore(overlay, layout);

    layout.insertAdjacentHTML('afterbegin', `
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">
          <span class="sidebar-title">Don't Forget!</span>
          <span class="sidebar-subtitle">Bible</span>
        </div>
        <nav class="sidebar-nav">${navLinks}</nav>
        <div class="sidebar-footer">
          <span class="sidebar-username" id="sidebarUser"></span>
          <a class="btn-view-profile" href="/profile">View Profile</a>
          <button class="btn-logout" id="sidebarLogout">Log out</button>
        </div>
      </aside>
    `);

    document.querySelector('.page-content').insertAdjacentHTML('afterbegin', `
      <div class="mobile-topbar">
        <button class="hamburger-btn" id="hamburgerBtn">&#9776;</button>
        <span class="mobile-topbar-title">Don't Forget!</span>
      </div>
    `);

    document.getElementById('sidebarUser').textContent = _user || '';
    document.getElementById('sidebarLogout').addEventListener('click', doLogout);

    const sidebar = document.getElementById('sidebar');
    const hamburger = document.getElementById('hamburgerBtn');
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('visible');
    });
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('visible');
    });
  };
})();
