import { jsonResponse, getUserFromRequest } from '../../utils';

export const onRequestGet = async (context) => {
    const { request, env } = context;
    const user = await getUserFromRequest(request, env.JWT_SECRET);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, 401);

    const { results } = await env.DB.prepare(`
    SELECT w.* 
    FROM websites w
    JOIN favorites f ON w.id = f.website_id
    WHERE f.user_id = ?
    ORDER BY f.created_at DESC
  `).bind(user.id).all();

    return jsonResponse({ favorites: results });
};

export const onRequestPost = async (context) => {
    const { request, env } = context;
    const user = await getUserFromRequest(request, env.JWT_SECRET);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, 401);

    const { website_id } = await request.json();
    if (!website_id) return jsonResponse({ error: 'Website ID required' }, 400);

    // Check if exists
    const exists = await env.DB.prepare('SELECT * FROM favorites WHERE user_id = ? AND website_id = ?').bind(user.id, website_id).first();

    if (exists) {
        // Remove
        await env.DB.prepare('DELETE FROM favorites WHERE user_id = ? AND website_id = ?').bind(user.id, website_id).run();
        return jsonResponse({ message: 'Removed from favorites', specific_status: 'removed' });
    } else {
        // Add
        await env.DB.prepare('INSERT INTO favorites (user_id, website_id) VALUES (?, ?)').bind(user.id, website_id).run();
        return jsonResponse({ message: 'Added to favorites', specific_status: 'added' });
    }
};
