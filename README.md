# 🌊 EchoCurve

**EchoCurve** is a personal Spaced Repetition System (SRS) for language learning, focusing on listening comprehension and vocabulary building.

## Features

*   **🎧 Audio-First Review:** Cards auto-play audio (TTS) so you can practice listening before revealing the text.
*   **🧠 Spaced Repetition:** Uses a 12-step Ebbinghaus-inspired schedule to optimize memory retention.
*   **📚 Library Management:** Add, edit, and search for sentences.
*   **🔍 Integrated Dictionary:** Built-in word lookup with pronunciation and example sentences (powered by Free Dictionary API).
*   **💾 Local & Cloud Sync:** Runs locally with a Node.js backend that saves data to a JSON file (designed to sync via Google Drive/Dropbox).

## Getting Started

### Prerequisites
*   Node.js (v14+) installed.

### Installation

1.  Clone the repository.
2.  Open a terminal in the project folder.
3.  (Optional) Set your data path in your environment:
    *   Windows: `$env:DATA_PATH="C:\path\to\data"`
    *   Linux/Mac: `export DATA_PATH="/path/to/data"`
4.  Run the server:
    ```bash
    npm start
    ```
5.  Open your browser to: `http://localhost:3000`

## Running as a Persistent Service

To keep EchoCurve running in the background automatically, we recommend using **PM2**:

1.  Install PM2: `npm install pm2 -g`
2.  Start the service: `pm2 start server.js --name "echocurve"`
3.  Save the process list: `pm2 save`

## Data Storage

By default, the server attempts to save data to `G:\My Drive\ClawdBot\english-data.json`.
You can modify the `DATA_DIR` constant in `server.js` to change the save location.

## License

MIT
