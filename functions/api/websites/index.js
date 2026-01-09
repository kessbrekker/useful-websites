import { jsonResponse, getUserFromRequest, fetchWebsiteMetadata } from '../../utils';

export const onRequestGet = async (context) => {
    const { env } = context;
    const { results } = await env.DB.prepare('SELECT * FROM websites ORDER BY created_at DESC').all();

    // Also check if user is logged in to mark favorites? 
    // Frontend can fetch favorites separately and merge, or we can do it here.
    // For simplicity, let's keep it clean: just return websites.
    return jsonResponse({ websites: results });
};

export const onRequestPost = async (context) => {
    const { request, env } = context;
    const body = await request.json();
    const { url, token } = body;

    if (!url) return jsonResponse({ error: 'URL is required' }, 400);

    let addedByUserId = null;

    // Check Auth: Admin or Token
    const user = await getUserFromRequest(request, env.JWT_SECRET);

    if (user && user.is_admin) {
        addedByUserId = user.id;
    } else {
        // Check Token
        if (token !== env.ADMIN_SECRET_TOKEN) {
            return jsonResponse({ error: 'Unauthorized: Invalid Token or not Admin' }, 401);
        }
        // If added by token, we might not have a user ID. 
        // The schema allows added_by_user_id to be nullable? 
        // Checking schema.sql: "added_by_user_id INTEGER" -> it's nullable.
    }

    // Fetch Metadata
    const metadata = await fetchWebsiteMetadata(url);

    // Insert into DB
    try {
        const result = await env.DB.prepare(
            'INSERT INTO websites (url, title, screenshot_url, added_by_user_id) VALUES (?, ?, ?, ?)'
        ).bind(metadata.url, metadata.title, metadata.screenshot_url, addedByUserId).run();

        if (result.success) {
            return jsonResponse({ message: 'Website added', website: metadata }, 201);
        } else {
            throw new Error('DB execution failed');
        }
    } catch (e) {
        return jsonResponse({ error: e.message }, 500);
    }
};
