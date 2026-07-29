import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("Sites serves the restored EchoCurve interface", async () => {
  const page = await readFile(new URL("app/page.tsx", root), "utf8");
  const legacy = await readFile(new URL("public/legacy.html", root), "utf8");
  const worker = await readFile(new URL("worker/index.ts", root), "utf8");

  assert.match(page, /src="\/legacy\.html"/);
  assert.match(legacy, /EchoCurve - SRS Practice/);
  assert.match(legacy, /Mark as learnt/);
  assert.match(legacy, /Sites user/);
  assert.doesNotMatch(legacy, /Your library is empty/);
  assert.doesNotMatch(legacy, /Delete this sentence\?/);
  assert.match(legacy, /dialogTitle: item\.dialogTitle/);
  assert.match(legacy, /existing\.dialogTitle = item\.dialogTitle/);
  assert.match(legacy, /indexedDB\.open\(AUDIO_DB_NAME/);
  assert.match(legacy, /await cacheAudio\(text, blob\)/);
  assert.match(legacy, /await loadNaturalSpeech\(text\)/);
  assert.match(worker, /CREATE TABLE IF NOT EXISTS user_data/);
  assert.match(worker, /oai-authenticated-user-email/);
  assert.match(worker, /https:\/\/api\.openai\.com\/v1\/audio\/speech/);
  assert.match(worker, /model: "gpt-4o-mini-tts"/);
  assert.match(worker, /voice: "marin"/);
});

test("the original local server remains available", async () => {
  const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  const server = await readFile(new URL("server.cjs", root), "utf8");

  assert.equal(packageJson.scripts.start, "node server.cjs");
  assert.match(server, /require\('\.\/users\.cjs'\)/);
});
