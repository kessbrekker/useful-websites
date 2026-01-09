import { SignJWT, jwtVerify } from 'jose';

export const jsonResponse = (data, status = 200) => {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
};

// --- Web Crypto Password Hashing ---
const ENCODING = new TextEncoder();

export const hashPassword = async (password) => {
    const saltArr = new Uint8Array(16);
    crypto.getRandomValues(saltArr);
    // Convert salt to hex
    const salt = Array.from(saltArr).map(b => b.toString(16).padStart(2, '0')).join('');

    const keyMaterial = await crypto.subtle.importKey("raw", ENCODING.encode(password), "PBKDF2", false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: ENCODING.encode(salt), iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        256
    );
    const hashFn = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${salt}.${hashFn(derivedBits)}`;
};

export const comparePassword = async (password, storedUrl) => {
    const [salt, originalHash] = storedUrl.split('.');
    const keyMaterial = await crypto.subtle.importKey("raw", ENCODING.encode(password), "PBKDF2", false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: ENCODING.encode(salt), iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        256
    );
    const hashFn = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hashFn(derivedBits) === originalHash;
};


// --- Auth / JOSE ---

export const generateToken = async (payload, secret) => {
    const secretKey = new TextEncoder().encode(secret);
    const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('30d')
        .sign(secretKey);
    return token;
};

export const verifyToken = async (token, secret) => {
    try {
        const secretKey = new TextEncoder().encode(secret);
        const { payload } = await jwtVerify(token, secretKey);
        return payload;
    } catch (e) {
        return null;
    }
};

export const getUserFromRequest = async (request, secret) => {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.split(' ')[1];
    return await verifyToken(token, secret);
};

export const fetchWebsiteMetadata = async (targetUrl) => {
    try {
        if (!targetUrl.startsWith('http')) {
            targetUrl = 'https://' + targetUrl;
        }
        const api = `https://api.microlink.io?url=${encodeURIComponent(targetUrl)}&screenshot=true&meta=true`;
        const res = await fetch(api);
        const data = await res.json();

        if (data.status === 'success') {
            return {
                title: data.data.title || targetUrl,
                screenshot_url: data.data.screenshot?.url || null,
                url: data.data.url
            };
        }
        return { title: targetUrl, screenshot_url: null, url: targetUrl };
    } catch (e) {
        console.error('Metadata fetch failed:', e);
        return { title: targetUrl, screenshot_url: null, url: targetUrl };
    }
};
