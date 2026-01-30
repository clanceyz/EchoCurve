const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_PATH || path.join(__dirname, 'data');
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
