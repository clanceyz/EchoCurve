const fs = require('fs');
const path = require('path');

// Use same data directory pattern as users.js
function getDataDir() {
    const renderDataPath = '/data';
    try {
        if (fs.existsSync(renderDataPath) && fs.statSync(renderDataPath).isDirectory()) {
            return renderDataPath;
        }
    } catch (e) { }
    return path.join(__dirname, 'data');
}

const DATA_DIR = process.env.DATA_PATH || getDataDir();
const PUBLIC_FILE = path.join(DATA_DIR, 'public_library.json');

// Ensure directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const publicStore = {
    getDialogs: () => {
        if (fs.existsSync(PUBLIC_FILE)) {
            try {
                return JSON.parse(fs.readFileSync(PUBLIC_FILE, 'utf8'));
            } catch (e) {
                console.error('[PublicStore] Error reading file:', e);
                return [];
            }
        }
        return [];
    },
    saveDialogs: (dialogs) => {
        fs.writeFileSync(PUBLIC_FILE, JSON.stringify(dialogs, null, 2), 'utf8');
    },
    addDialog: (title, sentences) => {
        const dialogs = publicStore.getDialogs();
        const newDialog = {
            id: Date.now(),
            title,
            sentences: sentences.map(s => ({
                text: s,
                interval: 0.5,
                stage: 0
            }))
        };
        dialogs.push(newDialog);
        publicStore.saveDialogs(dialogs);
        return newDialog;
    }
};

module.exports = publicStore;
