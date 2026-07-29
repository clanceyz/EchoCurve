/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
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

    if (url.pathname === "/api/tts") {
      return Response.json({ error: "Browser speech synthesis is used on Sites" }, { status: 503 });
    }

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
