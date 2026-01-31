const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const userStore = require('./users');

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY_DAYS = 30;

if (!process.env.JWT_SECRET) {
    console.log('[Security] JWT_SECRET not set, using random secret (tokens will invalidate on restart)');
}

// JWT Utilities (no external dependencies)
function base64UrlEncode(data) {
    return Buffer.from(data).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64').toString();
}

function createToken(username) {
    const role = username.toLowerCase() === 'admin' ? 'admin' : 'user';
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
        username,
        role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (JWT_EXPIRY_DAYS * 24 * 60 * 60)
    };

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signature = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    return `${headerB64}.${payloadB64}.${signature}`;
}

function verifyToken(token) {
    if (!token) return null;

    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signature] = parts;

    // Verify signature
    const expectedSig = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    if (signature !== expectedSig) {
        console.log('[JWT] Invalid signature');
        return null;
    }

    // Decode and check expiry
    try {
        const payload = JSON.parse(base64UrlDecode(payloadB64));
        if (payload.exp < Math.floor(Date.now() / 1000)) {
            console.log('[JWT] Token expired');
            return null;
        }
        return payload; // Return full payload including role
    } catch (e) {
        console.log('[JWT] Invalid payload');
        return null;
    }
}

// Extract token from Authorization header
function getAuthenticatedUser(req) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return verifyToken(authHeader.slice(7));
}

const PORT = process.env.PORT || 3000;
const HTML_FILE = path.join(__dirname, 'index.html');

// Dynamic RP ID and origin based on request host
function getWebAuthnConfig(req) {
    const host = req.headers.host || `localhost:${PORT}`;
    const hostname = host.split(':')[0];
    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
    const protocol = isLocalhost ? 'http' : 'https';
    // For HTTPS (production), origin should be just protocol://hostname without port
    // For HTTP (localhost), include the port
    const origin = isLocalhost ? `${protocol}://${host}` : `${protocol}://${hostname}`;
    console.log(`[WebAuthn] Host: ${host}, rpID: ${hostname}, origin: ${origin}`);
    return {
        rpID: hostname,
        origin: origin
    };
}

// In-memory challenge store (in a real app, this should be in a session/db)
const challenges = new Map();

const server = http.createServer(async (req, res) => {
    // CORS headers - reflect origin (safe since JWT provides access control)
    // This allows the app to be deployed anywhere while maintaining security
    const origin = req.headers.origin;
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

    // 1. Serve the HTML App
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        fs.readFile(HTML_FILE, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end('Error loading HTML file');
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(data);
            }
        });
        return;
    }

    // --- WebAuthn Registration ---
    if (req.method === 'GET' && url.pathname === '/api/auth/register-options') {
        const username = (url.searchParams.get('username') || '').toLowerCase().trim();
        console.log(`[Auth] Registration options requested for: ${username}`);
        if (!username) {
            res.writeHead(400);
            res.end('Username required');
            return;
        }

        const user = userStore.getUser(username);
        const userDevices = (user && user.devices) ? user.devices.filter(d => d.credentialID) : [];

        try {
            const { rpID } = getWebAuthnConfig(req);
            const options = await generateRegistrationOptions({
                rpName: 'EchoCurve',
                rpID,
                userID: Buffer.from(username),
                userName: username,
                attestationType: 'none',
                excludeCredentials: userDevices.map(dev => ({
                    id: dev.credentialID, // Already stored as Base64URL
                    type: 'public-key',
                    transports: dev.transports,
                })),
            });

            challenges.set(username, options.challenge);
            console.log(`[Auth] Registration options generated for ${username}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(options));
        } catch (error) {
            console.error(`[Auth] Registration options error for ${username}:`, error);
            res.writeHead(500);
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/verify-registration') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            const { username: rawUsername, registrationResponse } = JSON.parse(body);
            const username = (rawUsername || '').toLowerCase().trim();
            console.log(`[Auth] Verifying registration for: ${username}`);
            const expectedChallenge = challenges.get(username);

            try {
                const { rpID, origin } = getWebAuthnConfig(req);
                const verification = await verifyRegistrationResponse({
                    response: registrationResponse,
                    expectedChallenge,
                    expectedOrigin: origin,
                    expectedRPID: rpID,
                });

                if (verification.verified) {
                    const { registrationInfo } = verification;
                    console.log(`[Auth] Verification info:`, JSON.stringify(registrationInfo, (key, value) => {
                        if (value instanceof Uint8Array) return Array.from(value);
                        return value;
                    }, 2));

                    // SimpleWebAuthn v13+ structure
                    // credential.id is already a Base64URL string
                    // credential.publicKey is a Uint8Array
                    const { credential } = registrationInfo;

                    const user = userStore.getUser(username) || { username, devices: [] };

                    // Store credentials - ID is already Base64URL, publicKey needs conversion
                    user.devices.push({
                        credentialID: credential.id, // Already Base64URL string
                        credentialPublicKey: Buffer.from(credential.publicKey).toString('base64'),
                        counter: credential.counter,
                        transports: registrationResponse.response.transports,
                    });

                    userStore.saveUser(user);
                    const token = createToken(username);
                    console.log(`[Auth] Registration successful for ${username}, token issued`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ verified: true, token }));
                } else {
                    console.warn(`[Auth] Registration verification failed for ${username}`);
                    res.writeHead(400);
                    res.end(JSON.stringify({ verified: false }));
                }
            } catch (error) {
                console.error(`[Auth] Registration verification error for ${username}:`, error);
                res.writeHead(500);
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // --- WebAuthn Authentication ---
    if (req.method === 'GET' && url.pathname === '/api/auth/login-options') {
        const username = (url.searchParams.get('username') || '').toLowerCase().trim();
        console.log(`[Auth] Login options requested for: ${username}`);
        const user = userStore.getUser(username);
        if (!user) {
            console.warn(`[Auth] Login failed: User ${username} not found`);
            res.writeHead(404);
            res.end(JSON.stringify({ error: 'User not found' }));
            return;
        }

        const userDevices = (user && user.devices) ? user.devices.filter(d => d.credentialID) : [];
        if (userDevices.length === 0) {
            console.warn(`[Auth] Login failed: No passkeys for ${username}`);
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'No passkeys registered for this user' }));
            return;
        }

        try {
            const allowedCreds = userDevices.map(dev => ({
                id: dev.credentialID, // Already stored as Base64URL
                type: 'public-key',
                // transports: dev.transports, // Removing transports to avoid potential mismatches
            }));

            console.log('[Auth] Allowing credentials:', JSON.stringify(allowedCreds));

            const { rpID } = getWebAuthnConfig(req);
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: allowedCreds,
                userVerification: 'preferred',
            });

            challenges.set(username, options.challenge);
            console.log(`[Auth] Login options generated for ${username}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(options));
        } catch (error) {
            console.error(`[Auth] Login options error for ${username}:`, error);
            res.writeHead(500);
            res.end(JSON.stringify({ error: error.message }));
        }
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/verify-authentication') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            const { username: rawUsername, authenticationResponse } = JSON.parse(body);
            const username = (rawUsername || '').toLowerCase().trim();
            console.log(`[Auth] Verifying login for: ${username}`);
            console.log(`[Auth] Full auth response:`, JSON.stringify(authenticationResponse, null, 2));
            const user = userStore.getUser(username);
            const expectedChallenge = challenges.get(username);

            if (!user) {
                res.writeHead(404);
                res.end(JSON.stringify({ error: 'User not found' }));
                return;
            }

            // credentialID is stored as Base64URL, authenticationResponse.id is also Base64URL
            console.log(`[Auth] Response credential ID: "${authenticationResponse.id}"`);
            console.log(`[Auth] Stored credential IDs: ${JSON.stringify(user.devices.map(d => d.credentialID))}`);

            const dbAuthenticator = user.devices.find(dev =>
                dev.credentialID === authenticationResponse.id
            );

            if (!dbAuthenticator) {
                console.warn(`[Auth] Authenticator not found for ${username}`);
                console.log(`[Auth] Looking for: ${authenticationResponse.id}`);
                console.log(`[Auth] Available IDs: ${user.devices.map(d => d.credentialID).join(', ')}`);
                res.writeHead(400);
                res.end(JSON.stringify({ error: 'Authenticator not found' }));
                return;
            }

            try {
                // Decode Base64URL to Buffer for the library
                const credIdBuffer = Buffer.from(dbAuthenticator.credentialID.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

                const { rpID, origin } = getWebAuthnConfig(req);
                const verification = await verifyAuthenticationResponse({
                    response: authenticationResponse,
                    expectedChallenge,
                    expectedOrigin: origin,
                    expectedRPID: rpID,
                    credential: {
                        id: dbAuthenticator.credentialID,
                        publicKey: Buffer.from(dbAuthenticator.credentialPublicKey, 'base64'),
                        counter: dbAuthenticator.counter,
                    },
                });

                if (verification.verified) {
                    dbAuthenticator.counter = verification.authenticationInfo.newCounter;
                    userStore.saveUser(user);
                    const token = createToken(username);
                    console.log(`[Auth] Login successful for ${username}, token issued`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ verified: true, token }));
                } else {
                    console.warn(`[Auth] Login verification failed for ${username}`);
                    res.writeHead(400);
                    res.end(JSON.stringify({ verified: false }));
                }
            } catch (error) {
                console.error(`[Auth] Login verification error for ${username}:`, error);
                res.writeHead(500);
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // --- Google Cloud TTS Endpoint (JWT protected) ---
    if (req.method === 'POST' && url.pathname === '/api/tts') {
        // Require authentication to prevent API abuse
        const ttsUser = getAuthenticatedUser(req);
        if (!ttsUser) {
            res.writeHead(401);
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                const apiKey = process.env.GCP_KEY;

                if (!apiKey) {
                    res.writeHead(503);
                    res.end(JSON.stringify({ error: 'TTS not configured' }));
                    return;
                }

                const ttsResponse = await fetch(
                    `https://texttospeech.googleapis.com/v1/text:synthesize?key=${apiKey}`,
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            input: { text },
                            voice: {
                                languageCode: 'en-US',
                                name: 'en-US-Neural2-F', // High-quality mature female voice
                                ssmlGender: 'FEMALE'
                            },
                            audioConfig: {
                                audioEncoding: 'MP3',
                                speakingRate: 1.0,
                                pitch: 0
                            }
                        })
                    }
                );

                if (!ttsResponse.ok) {
                    const errText = await ttsResponse.text();
                    console.error('[TTS] Google API error:', errText);
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'TTS failed' }));
                    return;
                }

                const data = await ttsResponse.json();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ audioContent: data.audioContent }));
            } catch (error) {
                console.error('[TTS] Error:', error);
                res.writeHead(500);
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // ... (JWT logic remains same)

    // --- Public Library Endpoints ---

    if (req.method === 'GET' && url.pathname === '/api/public-library') {
        const dialogs = publicStore.getDialogs();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(dialogs));
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/public-library/import') {
        const authenticatedUser = getAuthenticatedUser(req);
        if (!authenticatedUser || authenticatedUser.role !== 'admin') {
            res.writeHead(403);
            res.end(JSON.stringify({ error: 'Admin access required' }));
            return;
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const { title, text } = JSON.parse(body);
                if (!title || !text) throw new Error('Missing title or text');

                // Split multi-line text into sentences
                const sentences = text.split('\n')
                    .map(s => s.trim())
                    .filter(s => s.length > 0);

                const newDialog = publicStore.addDialog(title, sentences);
                res.writeHead(201, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(newDialog));
            } catch (e) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: e.message }));
            }
        });
        return;
    }

    // --- Data Endpoints (User-specific, JWT protected) ---

    const authenticatedUser = getAuthenticatedUser(req);

    if (req.method === 'GET' && url.pathname === '/api/data') {
        if (!authenticatedUser) {
            res.writeHead(401);
            res.end('Unauthorized');
            return;
        }

        const data = userStore.getUserData(authenticatedUser.username);
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
        });
        res.end(data);
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/data') {
        if (!authenticatedUser) {
            res.writeHead(401);
            res.end('Unauthorized');
            return;
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                JSON.parse(body);
                userStore.saveUserData(authenticatedUser.username, body);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (e) {
                res.writeHead(400);
                res.end('Invalid JSON');
            }
        });
        return;
    }

    // 404
    res.writeHead(404);
    res.end('Not found');
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});