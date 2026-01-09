import { jsonResponse, hashPassword, comparePassword, generateToken, getUserFromRequest } from '../../utils';

export const onRequestPost = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname.split('/').pop(); // simple routing based on last segment or use switch

    // Parse body
    let body;
    try {
        body = await request.json();
    } catch (e) {
        return jsonResponse({ error: 'Invalid JSON' }, 400);
    }

    if (url.pathname.endsWith('/login')) {
        const { email, password } = body;
        if (!email || !password) return jsonResponse({ error: 'Missing fields' }, 400);

        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        if (!user) return jsonResponse({ error: 'Invalid credentials' }, 401);

        const valid = await comparePassword(password, user.password_hash);
        if (!valid) return jsonResponse({ error: 'Invalid credentials' }, 401);

        const token = generateToken({ id: user.id, email: user.email, is_admin: user.is_admin }, env.JWT_SECRET);
        return jsonResponse({ token, user: { id: user.id, email: user.email, is_admin: user.is_admin } });
    }

    if (url.pathname.endsWith('/register')) {
        const { email, password } = body;
        if (!email || !password) return jsonResponse({ error: 'Missing fields' }, 400);

        // Check if user exists
        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existing) return jsonResponse({ error: 'User already exists' }, 409);

        const hash = await hashPassword(password);
        // First user is admin automatically? Or manual? Let's just default to 0. 
        // User requested "Implement a check to identify 'Admin' status via a specific email or database flag."
        // Let's make 'admin@example.com' admin by default for testing.
        const isAdmin = email === 'admin@example.com' ? 1 : 0;

        const result = await env.DB.prepare('INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)')
            .bind(email, hash, isAdmin)
            .run();

        if (!result.success) return jsonResponse({ error: 'Failed to register' }, 500);

        // Auto login? or just return success
        return jsonResponse({ message: 'User created' }, 201);
    }

    return jsonResponse({ error: 'Not found' }, 404);
};

export const onRequestPut = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);

    if (url.pathname.endsWith('/me')) {
        const user = await getUserFromRequest(request, env.JWT_SECRET);
        if (!user) return jsonResponse({ error: 'Unauthorized' }, 401);

        const body = await request.json();
        const { email, password } = body;

        let updates = [];
        let params = [];

        if (email) {
            updates.push('email = ?');
            params.push(email);
        }
        if (password) {
            const hash = await hashPassword(password);
            updates.push('password_hash = ?');
            params.push(hash);
        }

        if (updates.length > 0) {
            params.push(user.id);
            await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`)
                .bind(...params).run();
            // Refetch to return clean user
            const freshUser = await env.DB.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').bind(user.id).first();
            return jsonResponse({ message: 'Profile updated', user: freshUser });
        }
        return jsonResponse({ message: 'No changes' });
    }
    return jsonResponse({ error: 'Method not allowed' }, 405);
};

export const onRequestDelete = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);

    if (url.pathname.endsWith('/me')) {
        const user = await getUserFromRequest(request, env.JWT_SECRET);
        if (!user) return jsonResponse({ error: 'Unauthorized' }, 401);

        await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
        // Also clean up favorites and websites? 
        // Websites have 'added_by_user_id', checking schema it is simple FK, maybe set null?
        // Favorites cascade? Schema didn't specify ON DELETE CASCADE.
        // Let's manually cleanup favorites for cleanliness.
        await env.DB.prepare('DELETE FROM favorites WHERE user_id = ?').bind(user.id).run();

        return jsonResponse({ message: 'Account deleted' });
    }
    return jsonResponse({ error: 'Method not allowed' }, 405);
};

export const onRequestGet = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);

    if (url.pathname.endsWith('/me')) {
        const user = await getUserFromRequest(request, env.JWT_SECRET);
        if (!user) return jsonResponse({ error: 'Unauthorized' }, 401);

        // Fetch fresh data
        const freshUser = await env.DB.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').bind(user.id).first();
        return jsonResponse({ user: freshUser });
    }

    return jsonResponse({ error: 'Not found' }, 404);
}
