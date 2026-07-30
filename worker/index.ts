/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  AUDIO: R2Bucket;
  DB: D1Database;
  OPENAI_API_KEY?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const schemaSql = `CREATE TABLE IF NOT EXISTS user_data (
  user_id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`;

function userId(request: Request): string {
  return request.headers.get("oai-authenticated-user-email") || "site-owner";
}

async function handleDataApi(request: Request, env: Env): Promise<Response> {
  await env.DB.prepare(schemaSql).run();
  const id = userId(request);

  if (request.method === "GET") {
    const row = await env.DB.prepare("SELECT payload FROM user_data WHERE user_id = ?")
      .bind(id)
      .first<{ payload: string }>();
    return new Response(row?.payload || "[]", {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }

  if (request.method === "POST") {
    const payload = await request.text();
    if (payload.length > 5_000_000) return new Response("Payload too large", { status: 413 });
    try {
      const parsed = JSON.parse(payload);
      if (!Array.isArray(parsed)) throw new Error("Expected an array");
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }
    await env.DB.prepare(
      `INSERT INTO user_data (user_id, payload, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP`,
    )
      .bind(id, payload)
      .run();
    return Response.json({ success: true });
  }

  return new Response("Method not allowed", { status: 405 });
}

const ttsCacheVersion = "gpt-4o-mini-tts:marin:learner-v1";

async function ttsCacheKey(request: Request, text: string): Promise<string> {
  const source = `${userId(request)}\n${ttsCacheVersion}\n${text}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(source));
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `speech/${hash}.mp3`;
}

async function handleTtsApi(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
  if (!env.OPENAI_API_KEY) return Response.json({ error: "TTS is not configured" }, { status: 503 });

  let text = "";
  try {
    const body = (await request.json()) as { text?: unknown };
    if (typeof body.text !== "string") throw new Error("Invalid text");
    text = body.text.trim();
  } catch {
    return Response.json({ error: "Invalid request" }, { status: 400 });
  }

  if (!text || text.length > 4096) {
    return Response.json({ error: "Text must contain 1 to 4096 characters" }, { status: 400 });
  }

  const cacheKey = await ttsCacheKey(request, text);
  const cached = await env.AUDIO.get(cacheKey);
  if (cached) {
    return new Response(cached.body, {
      headers: {
        "content-type": "audio/mpeg",
        "cache-control": "private, max-age=31536000, immutable",
        "x-echocurve-tts-cache": "hit",
      },
    });
  }

  const response = await fetch("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini-tts",
      voice: "marin",
      input: text,
      instructions:
        "Speak in warm, natural, conversational American English. Use clear pronunciation, gentle pacing, and natural intonation for a language learner.",
      response_format: "mp3",
      speed: 0.95,
    }),
  });

  if (!response.ok || !response.body) {
    console.error("[TTS] OpenAI request failed", response.status);
    return Response.json({ error: "Speech generation failed" }, { status: 502 });
  }

  const audioForStorage = response.clone();
  ctx.waitUntil(
    env.AUDIO.put(cacheKey, audioForStorage.body, {
      httpMetadata: { contentType: "audio/mpeg" },
    }),
  );

  return new Response(response.body, {
    headers: {
      "content-type": "audio/mpeg",
      "cache-control": "private, max-age=31536000, immutable",
      "x-echocurve-tts-cache": "miss",
    },
  });
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/data") return handleDataApi(request, env);

    if (url.pathname === "/api/public-library" && request.method === "GET") {
      return env.ASSETS.fetch(new Request(new URL("/public_library.json", request.url)));
    }

    if (url.pathname === "/api/tts") return handleTtsApi(request, env, ctx);

    if (url.pathname.startsWith("/api/auth/")) {
      return Response.json({ error: "Sites access provides authentication" }, { status: 410 });
    }

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    return handler.fetch(request, env, ctx);
  },
};

export default worker;
