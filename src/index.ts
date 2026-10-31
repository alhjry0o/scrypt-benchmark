import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";

interface ScryptConfig {
  name: string;
  N: number;
  r: number;
  p: number;
  owasp: "minimum" | "listed-alternative";
}

const CONFIGS: ScryptConfig[] = [
  { name: "OWASP minimum N=2^17", N: 131072, r: 8, p: 1, owasp: "minimum" },
  { name: "OWASP alt N=2^16 p=2", N: 65536, r: 8, p: 2, owasp: "listed-alternative" },
  { name: "OWASP alt N=2^15 p=3", N: 32768, r: 8, p: 3, owasp: "listed-alternative" },
  { name: "OWASP alt N=2^14 p=5", N: 16384, r: 8, p: 5, owasp: "listed-alternative" },
  { name: "OWASP alt N=2^13 p=10", N: 8192, r: 8, p: 10, owasp: "listed-alternative" },
];

// الحد الأقصى لخيار maxmem الممرر إلى scrypt.
// هذا ليس حد ذاكرة Cloudflare Worker.
const MAX_SCRYPT_MAXMEM_BYTES = 128 * 1024 * 1024;

// هامش إضافي فوق متطلب الذاكرة التقريبي 128*N*r.
const MAXMEM_HEADROOM_BYTES = 32 * 1024 * 1024;

const KEY_LEN = 64;
const SALT_LEN = 16;

export default {
  async fetch(
    request: Request,
    env: {
      BENCHMARK_KEY?: string;
      BENCHMARK_LIMITER?: {
        limit: (opts: { key: string }) => Promise<{ success: boolean }>;
      };
    }
  ): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "POST" }
      });
    }

    // التحقق من مفتاح الاختبار.
    const provided = request.headers.get("X-Benchmark-Key") ?? "";
    const expected = env.BENCHMARK_KEY ?? "";

    if (!expected || provided.length !== expected.length) {
      return new Response("Unauthorized", { status: 401 });
    }

    const a = Buffer.from(provided);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return new Response("Unauthorized", { status: 401 });
    }

    // تحديد عدد الطلبات.
    if (env.BENCHMARK_LIMITER) {
      const rl = await env.BENCHMARK_LIMITER.limit({
        key: "benchmark"
      });

      if (!rl.success) {
        return new Response("Too Many Requests", { status: 429 });
      }
    }

    // اختيار إعداد scrypt المراد اختباره.
    const configParam = new URL(request.url).searchParams.get("config") ?? "0";

    if (!/^[0-4]$/.test(configParam)) {
      return Response.json(
        {
          error: "config must be 0..4",
          configs: CONFIGS.map((c, i) => ({
            i,
            name: c.name
          }))
        },
        { status: 400 }
      );
    }

    const idx = Number(configParam);
    const cfg = CONFIGS[idx];

    // حساب الذاكرة التقريبية المطلوبة.
    const coreMemory = 128 * cfg.N * cfg.r;

    const maxmem = Math.min(
      MAX_SCRYPT_MAXMEM_BYTES,
      Math.max(
        coreMemory + MAXMEM_HEADROOM_BYTES,
        16 * 1024 * 1024
      )
    );

    // كلمة مرور تجريبية وليست كلمة مرور مستخدم حقيقي.
    const password = "BenchmarkPassword-NotReal-2026";
    const salt = randomBytes(SALT_LEN);

    let completed = false;
    let error: string | null = null;
    let wallMs = 0;

    const start = performance.now();

    try {
      const key = scryptSync(
        Buffer.from(password.normalize("NFKC"), "utf8"),
        salt,
        KEY_LEN,
        {
          N: cfg.N,
          r: cfg.r,
          p: cfg.p,
          maxmem
        }
      );

      completed = key.length === KEY_LEN;

    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);

    } finally {
      wallMs = Math.round(
        (performance.now() - start) * 100
      ) / 100;
    }

    return Response.json({
      config: cfg.name,
      params: {
        N: cfg.N,
        r: cfg.r,
        p: cfg.p
      },
      owasp: cfg.owasp,
      completed,
      wallTimeMs: wallMs,
      coreMemoryBytes: coreMemory,
      maxmemUsed: maxmem,
      error,
      note: "wallTimeMs measures elapsed wall time only. Check Cloudflare Invocation Logs for CPU time, including $workers.cpuTimeMs when available."
    });
  }
};
