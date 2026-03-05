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
    document.getElementById('sidebarUser').textContent = _user || '';

    document.querySelectorAll('.sidebar-link').forEach(link => {
      link.classList.toggle('active', link.dataset.page === activePage);
    });

    document.getElementById('sidebarLogout').addEventListener('click', doLogout);

    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const hamburger = document.getElementById('hamburgerBtn');
    if (hamburger && sidebar && overlay) {
      hamburger.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('visible');
      });
      overlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
      });
    }
  };
})();
