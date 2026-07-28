import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("EchoCurve page contains the core study workflow", async () => {
  const page = await readFile(new URL("app/page.tsx", root), "utf8");
  const css = await readFile(new URL("app/globals.css", root), "utf8");
  const layout = await readFile(new URL("app/layout.tsx", root), "utf8");

  assert.match(page, /EchoCurve/);
  assert.match(page, /Review queue/);
  assert.match(page, /Starter dialogs/);
  assert.match(page, /localStorage/);
  assert.match(page, /speechSynthesis/);
  assert.match(page, /dictionaryapi\.dev/);
  assert.match(css, /\.review-band/);
  assert.match(css, /\.library-list/);
  assert.match(layout, /title: "EchoCurve"/);
});

test("the legacy local server keeps its CommonJS entrypoint", async () => {
  const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
  const server = await readFile(new URL("server.cjs", root), "utf8");

  assert.equal(packageJson.main, "server.cjs");
  assert.equal(packageJson.scripts.start, "node server.cjs");
  assert.match(server, /require\("\.\/users\.cjs"\)|require\('\.\/users\.cjs'\)/);
});
