const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_PATH || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'english-data.json');
const HTML_FILE = path.join(__dirname, 'index.html');

// Ensure directory exists
if (!fs.existsSync(DATA_DIR)) {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`Created directory: ${DATA_DIR}`);
    } catch (e) {
        console.error(`Error creating directory ${DATA_DIR}:`, e);
    }
}

// Ensure data file exists
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, '[]', 'utf8');
    console.log(`Created new data file at: ${DATA_FILE}`);
}

const server = http.createServer((req, res) => {
    // CORS headers (just in case)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // 1. Serve the HTML App
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
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

    // 2. GET Data (Load from G: Drive)
    if (req.method === 'GET' && req.url.startsWith('/api/data')) {
        // Disable caching headers
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        fs.readFile(DATA_FILE, 'utf8', (err, data) => {
            if (err) {
                console.error('Read Error:', err);
                res.writeHead(500);
                res.end('Error reading data');
            } else {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(data || '[]');
            }
        });
        return;
    }

    // 3. POST Data (Save to G: Drive)
    if (req.method === 'POST' && req.url === '/api/data') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                // Verify it's valid JSON before writing
                JSON.parse(body);
                fs.writeFile(DATA_FILE, body, 'utf8', (err) => {
                    if (err) {
                        console.error('Write Error:', err);
                        res.writeHead(500);
                        res.end('Error writing data');
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true }));
                    }
                });
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
    console.log(`Saving data to: ${DATA_FILE}`);
});