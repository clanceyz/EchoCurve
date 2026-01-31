const fs = require('fs');
const path = require('path');

// Use Render's persistent disk at /data if available, otherwise use local ./data
function getDataDir() {
    // Check for Render persistent disk
    const renderDataPath = '/data';
    try {
        if (fs.existsSync(renderDataPath) && fs.statSync(renderDataPath).isDirectory()) {
            console.log('[Storage] Using Render persistent disk at /data');
            return renderDataPath;
        }
    } catch (e) {
        // /data not accessible (Windows or no persistent disk)
    }
    
    // Fall back to local data directory
    const localPath = path.join(__dirname, 'data');
    console.log(`[Storage] Using local storage at ${localPath}`);
    return localPath;
}

const DATA_DIR = process.env.DATA_PATH || getDataDir();
const USERS_DIR = path.join(DATA_DIR, 'users');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_DIR)) fs.mkdirSync(USERS_DIR, { recursive: true });

function getUserPath(username) {
    return path.join(USERS_DIR, `${username}.json`);
}

function getUserDataPath(username) {
    return path.join(USERS_DIR, `${username}-data.json`);
}

const userStore = {
    getUser: (username) => {
        const filePath = getUserPath(username);
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
        return null;
    },
    saveUser: (user) => {
        const filePath = getUserPath(user.username);
        fs.writeFileSync(filePath, JSON.stringify(user, null, 2), 'utf8');
    },
    getUserData: (username) => {
        const filePath = getUserDataPath(username);
        if (fs.existsSync(filePath)) {
            return fs.readFileSync(filePath, 'utf8');
        }
        return '[]';
    },
    saveUserData: (username, data) => {
        const filePath = getUserDataPath(username);
        fs.writeFileSync(filePath, data, 'utf8');
    }
};

module.exports = userStore;
