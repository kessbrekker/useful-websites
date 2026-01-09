const state = {
    user: null,
    websites: [],
    favorites: [],
};

const API_BASE = '/api';

// --- API Client ---
const api = {
    async request(endpoint, method = 'GET', body = null) {
        const headers = { 'Content-Type': 'application/json' };
        const token = localStorage.getItem('token');
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const config = { method, headers };
        if (body) config.body = JSON.stringify(body);

        const res = await fetch(`${API_BASE}${endpoint}`, config);
        const data = await res.json();
        return { status: res.status, data };
    },

    async login(email, password) {
        return this.request('/auth/login', 'POST', { email, password });
    },

    async register(email, password) {
        return this.request('/auth/register', 'POST', { email, password });
    },

    async getMe() {
        return this.request('/auth/me');
    },

    async updateMe(email, password) {
        return this.request('/auth/me', 'PUT', { email, password });
    },

    async deleteMe() {
        return this.request('/auth/me', 'DELETE');
    },

    async getWebsites() {
        return this.request('/websites');
    },

    async addWebsite(url, token = null) {
        return this.request('/websites', 'POST', { url, token });
    },

    async getFavorites() {
        return this.request('/websites/favorites');
    },

    async toggleFavorite(websiteId) {
        return this.request('/websites/favorites', 'POST', { website_id: websiteId });
    },
};

// --- Router & Rendering ---
const app = document.getElementById('app');

const routes = {
    '/': renderHome, // Favorites
    '/discover': renderDiscover, // All
    '/account': renderAccount,
    '/add': renderAdd,
    '/login': renderLogin,
    '/register': renderRegister,
};

function navigate(path) {
    window.history.pushState({}, '', path);
    router();
}

async function router() {
    const path = window.location.pathname;
    const renderer = routes[path] || routes['/discover']; // Default to discover if not found, or home? user said Home=Favorites. If not logged in, maybe Discover is better default.

    // Auth Guard
    if (!state.user && path !== '/login' && path !== '/register') {
        // Try to load user
        const token = localStorage.getItem('token');
        if (token) {
            const res = await api.getMe();
            if (res.status === 200) {
                state.user = res.data.user;
                // If we were going to login, redirect to home
                if (path === '/login') {
                    navigate('/');
                    return;
                }
            } else {
                localStorage.removeItem('token');
                navigate('/login');
                return;
            }
        } else {
            // Allow Discover without login? User requirements implied "Home (Favorites): Display ... logged-in user".
            // "Discover: ... Display all websites".
            // Let's allow public access to Discover? Or enforce login?
            // "Home (Favorites): Display only the websites that the logged-in user has marked as favorites." -> implied login needed for Home.
            // "Discover: ... Display all ... " -> Doesn't explicitly say public, but usually is.
            // Let's redirect to /login if strict, but let's be modern: allow public Discover.
            if (path === '/' || path === '/account' || path === '/add') {
                navigate('/login');
                return;
            }
        }
    }

    // Pre-fetch data
    if (path === '/' && state.user) await loadFavorites();
    if (path === '/discover') await loadWebsites();

    renderLayout(renderer);
}

async function loadWebsites() {
    const res = await api.getWebsites();
    if (res.status === 200) state.websites = res.data.websites;
}

async function loadFavorites() {
    const res = await api.getFavorites();
    if (res.status === 200) state.favorites = res.data.favorites;
}

function renderLayout(viewIdx) {
    app.innerHTML = `
    <nav class="sidebar">
      <div class="logo">
         Directory
      </div>
      <ul class="nav-links">
        ${state.user ? `
        <li><a href="/" class="nav-link ${window.location.pathname === '/' ? 'active' : ''}" data-link>Favorites</a></li>
        ` : ''}
        <li><a href="/discover" class="nav-link ${window.location.pathname === '/discover' ? 'active' : ''}" data-link>Discover</a></li>
        ${state.user ? `
        <li><a href="/add" class="nav-link ${window.location.pathname === '/add' ? 'active' : ''}" data-link>Add Website</a></li>
        <li><a href="/account" class="nav-link ${window.location.pathname === '/account' ? 'active' : ''}" data-link>Account</a></li>
        <li><a href="#" id="logout-btn" class="nav-link">Logout</a></li>
        ` : `
        <li><a href="/login" class="nav-link ${window.location.pathname === '/login' ? 'active' : ''}" data-link>Login</a></li>
        `}
      </ul>
    </nav>
    <main class="main-content">
      <div id="view-container"></div>
    </main>
  `;

    viewIdx(document.getElementById('view-container'));

    // Bind Events
    document.querySelectorAll('a[data-link]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            navigate(a.getAttribute('href'));
        });
    });

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('token');
            state.user = null;
            state.favorites = [];
            navigate('/login');
        });
    }
}

// --- Views ---

function renderDiscover(container) {
    container.innerHTML = `
    <header class="page-header">
      <h1 class="page-title">Discover</h1>
    </header>
    <div class="grid">
      ${state.websites.map(w => renderCard(w)).join('')}
    </div>
  `;
    bindFavoriteButtons();
}

function renderHome(container) {
    container.innerHTML = `
    <header class="page-header">
      <h1 class="page-title">My Favorites</h1>
    </header>
    <div class="grid">
      ${state.favorites.length ? state.favorites.map(w => renderCard(w, true)).join('') : '<p>No favorites yet.</p>'}
    </div>
  `;
    bindFavoriteButtons();
}

function renderCard(website, isFavView = false) {
    // Check if favorited (if not in Fav View, need to check efficiently)
    // For simplicity, we might not show filled heart in Discover unless we cross-ref favorites.
    // Ideally, load favorites once and check.
    const isFav = isFavView || state.favorites.some(f => f.id === website.id);

    return `
    <div class="card">
      <img src="${website.screenshot_url || 'https://via.placeholder.com/300x180?text=No+Image'}" class="card-img" alt="${website.title}">
      ${state.user ? `
      <button class="fav-btn ${isFav ? 'active' : ''}" data-id="${website.id}">
        ♥
      </button>
      ` : ''}
      <div class="card-content">
        <h3 class="card-title">${website.title || 'Untitled'}</h3>
        <a href="${website.url}" target="_blank" class="card-link">${new URL(website.url).hostname}</a>
      </div>
    </div>
  `;
}

function bindFavoriteButtons() {
    document.querySelectorAll('.fav-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const id = btn.dataset.id;
            // Optimistic UI
            btn.classList.toggle('active');
            await api.toggleFavorite(id);
            // Refresh favorites in background to stay synced
            loadFavorites();
        });
    });
}

function renderLogin(container) {
    container.innerHTML = `
    <div class="auth-container">
      <div class="auth-box">
        <h2 style="margin-bottom: 1.5rem;">Login</h2>
        <form id="login-form">
          <div class="form-group">
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-input" required>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-input" required>
          </div>
          <button type="submit" class="btn">Login</button>
          <p style="margin-top: 1rem; text-align: center;">
            Don't have an account? <a href="/register" data-link>Register</a>
          </p>
        </form>
      </div>
    </div>
  `;

    document.getElementById('login-form').addEventListener('submit', async e => {
        e.preventDefault();
        const email = e.target.email.value;
        const password = e.target.password.value;
        const res = await api.login(email, password);
        if (res.status === 200) {
            localStorage.setItem('token', res.data.token);
            state.user = res.data.user;
            navigate('/');
        } else {
            alert(res.data.error || 'Login failed');
        }
    });

    // Re-bind links because layout didn't render navigation sidebar for login page (it did, but inside main-content? No logic handled that)
    // Wait, renderLayout renders sidebar AND main-content. 
    // But for Login, maybe we want full screen?
    // My logic puts login inside main-content. That's fine for now.
    // Just need to ensure data-link works inside the form.
    container.querySelectorAll('a[data-link]').forEach(a => {
        a.addEventListener('click', ev => {
            ev.preventDefault();
            navigate(a.getAttribute('href'));
        });
    });
}

function renderRegister(container) {
    container.innerHTML = `
    <div class="auth-container">
      <div class="auth-box">
        <h2 style="margin-bottom: 1.5rem;">Register</h2>
        <form id="register-form">
          <div class="form-group">
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-input" required>
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-input" required>
          </div>
          <button type="submit" class="btn">Register</button>
          <p style="margin-top: 1rem; text-align: center;">
             Already have an account? <a href="/login" data-link>Login</a>
          </p>
        </form>
      </div>
    </div>
  `;

    document.getElementById('register-form').addEventListener('submit', async e => {
        e.preventDefault();
        const email = e.target.email.value;
        const password = e.target.password.value;
        const res = await api.register(email, password);
        if (res.status === 201) {
            alert('Registration successful! Please login.');
            navigate('/login');
        } else {
            alert(res.data.error || 'Registration failed');
        }
    });

    container.querySelectorAll('a[data-link]').forEach(a => {
        a.addEventListener('click', ev => {
            ev.preventDefault();
            navigate(a.getAttribute('href'));
        });
    });
}

function renderAccount(container) {
    if (!state.user) return; // Should be handled by guard

    container.innerHTML = `
    <header class="page-header">
      <h1 class="page-title">Account Settings</h1>
    </header>
    <div style="background: white; padding: 2rem; border-radius: 12px; max-width: 500px; box-shadow: var(--shadow);">
        <form id="update-form">
            <div class="form-group">
                <label class="form-label">Email</label>
                <input type="email" name="email" class="form-input" value="${state.user.email}">
            </div>
            <div class="form-group">
                <label class="form-label">New Password (leave blank to keep current)</label>
                <input type="password" name="password" class="form-input">
            </div>
            <button type="submit" class="btn">Update Profile</button>
        </form>
        <hr style="margin: 2rem 0; border: 0; border-top: 1px solid #eee;">
        <button id="delete-btn" class="btn" style="background-color: #ef4444;">Delete Account</button>
    </div>
  `;

    document.getElementById('update-form').addEventListener('submit', async e => {
        e.preventDefault();
        const email = e.target.email.value;
        const password = e.target.password.value;
        const res = await api.updateMe(email, password);
        if (res.status === 200) {
            alert('Profile updated');
            state.user = res.data.user;
        } else {
            alert(res.data.error || 'Update failed');
        }
    });

    document.getElementById('delete-btn').addEventListener('click', async () => {
        if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
            const res = await api.deleteMe();
            if (res.status === 200) {
                localStorage.removeItem('token');
                state.user = null;
                navigate('/login');
            } else {
                alert(res.data.error || 'Deletion failed');
            }
        }
    });
}

function renderAdd(container) {
    container.innerHTML = `
    <header class="page-header">
      <h1 class="page-title">Add Website</h1>
    </header>
    <div class="add-options">
      ${state.user.is_admin ? `
      <div class="add-card">
        <h3>Admin: Direct Add</h3>
        <p style="margin-bottom: 1rem; color: #666;">Enter a URL to automatically fetch metadata.</p>
        <form id="admin-add-form">
            <div class="form-group">
                <input type="url" name="url" placeholder="https://example.com" class="form-input" required>
            </div>
            <button type="submit" class="btn">Add Website</button>
        </form>
      </div>
      ` : ''}
      
      <div class="add-card">
        <h3>Add with Token</h3>
        <p style="margin-bottom: 1rem; color: #666;">Enter a URL and your Contributor Token.</p>
        <form id="token-add-form">
            <div class="form-group">
                <input type="url" name="url" placeholder="https://example.com" class="form-input" required>
            </div>
            <div class="form-group">
                 <input type="text" name="token" placeholder="Secret Token" class="form-input" required>
            </div>
            <button type="submit" class="btn">Submit</button>
        </form>
      </div>
    </div>
  `;

    const adminForm = document.getElementById('admin-add-form');
    if (adminForm) {
        adminForm.addEventListener('submit', async e => {
            e.preventDefault();
            const url = e.target.url.value;
            const res = await api.addWebsite(url);
            if (res.status === 201) {
                alert('Website added!');
                e.target.reset();
            } else {
                alert(res.data.error || 'Failed to add');
            }
        });
    }

    const tokenForm = document.getElementById('token-add-form');
    if (tokenForm) {
        tokenForm.addEventListener('submit', async e => {
            e.preventDefault();
            const url = e.target.url.value;
            const token = e.target.token.value;
            const res = await api.addWebsite(url, token);
            if (res.status === 201) {
                alert('Website added!');
                e.target.reset();
            } else {
                alert(res.data.error || 'Failed to add');
            }
        });
    }
}

// Init
// Init
async function init() {
    const token = localStorage.getItem('token');
    if (token) {
        // Optimistically set a flag or try to fetch user immediately
        const res = await api.getMe();
        if (res.status === 200) {
            state.user = res.data.user;
        } else {
            localStorage.removeItem('token');
        }
    }
    window.addEventListener('popstate', router);
    router();
}

init();
