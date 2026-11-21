import { createClient, type Client } from "@libsql/client";

function stripQuotesAndTrim(raw: string | undefined): string {
  if (!raw) return "";
  let s = raw.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function normalizeDatabaseUrl(rawUrl: string | undefined): string {
  const cleaned = stripQuotesAndTrim(rawUrl);
  if (!cleaned || cleaned === "undefined" || cleaned === "null") {
    return "file:kpis.db";
  }
  if (cleaned.startsWith("file:")) {
    return cleaned;
  }

  let parsed: URL;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error(
      "صيغة متغير TURSO_DATABASE_URL غير صالحة. يجب أن يكون بالصيغة: libsql://your-db-org.turso.io"
    );
  }

  const host = (parsed.hostname || "").toLowerCase();
  if (host === "turso.tech" || host === "app.turso.tech" || host.endsWith(".turso.tech")) {
    throw new Error(
      "رابط TURSO_DATABASE_URL يشير إلى لوحة تحكم Turso (turso.tech) وليس إلى رابط قاعدة البيانات. يرجى نسخ رابط القاعدة الذي يبدأ بـ libsql://...turso.io"
    );
  }

  // Normalize protocol + host only (strip accidental trailing paths or slashes that cause HTTP 404)
  const portPart = parsed.port ? `:${parsed.port}` : "";
  return `${parsed.protocol}//${parsed.hostname}${portPart}`;
}

function normalizeAuthToken(rawToken: string | undefined): string | undefined {
  let cleaned = stripQuotesAndTrim(rawToken);
  if (!cleaned || cleaned === "undefined" || cleaned === "null") {
    return undefined;
  }
  if (/^bearer\s+/i.test(cleaned)) {
    cleaned = cleaned.replace(/^bearer\s+/i, "").trim();
  }
  return cleaned || undefined;
}

export function getConfiguredDbHost(): string {
  try {
    const cleaned = stripQuotesAndTrim(process.env.TURSO_DATABASE_URL);
    if (!cleaned || cleaned === "undefined" || cleaned.startsWith("file:")) {
      return "local-sqlite";
    }
    const parsed = new URL(cleaned);
    return parsed.hostname || cleaned;
  } catch {
    return "invalid-url";
  }
}

let lastTursoHttpDetail: { status: number; detail: string } | null = null;

export function getLastTursoHttpDetail(): { status: number; detail: string } | null {
  return lastTursoHttpDetail;
}

const diagnosticFetch: typeof fetch = async (input, init) => {
  const resp = await globalThis.fetch(input, init);
  if (resp.ok) {
    lastTursoHttpDetail = null;
  } else {
    try {
      const cloned = resp.clone();
      const rawText = (await cloned.text()).trim();
      let detail = rawText;
      if (rawText.startsWith("{")) {
        try {
          const parsed = JSON.parse(rawText);
          if (typeof parsed?.error === "string" && parsed.error.trim()) {
            detail = parsed.error.trim();
          } else if (typeof parsed?.message === "string" && parsed.message.trim()) {
            detail = parsed.message.trim();
          }
        } catch {
          // keep rawText
        }
      }
      lastTursoHttpDetail = {
        status: resp.status,
        detail: detail.slice(0, 260),
      };
    } catch {
      lastTursoHttpDetail = { status: resp.status, detail: "" };
    }
  }
  return resp;
};

function getClient(): Client {
  const url = normalizeDatabaseUrl(process.env.TURSO_DATABASE_URL);
  const authToken = normalizeAuthToken(process.env.TURSO_AUTH_TOKEN);

  if (url.startsWith("file:")) {
    return createClient({ url });
  }

  return createClient({ url, authToken, fetch: diagnosticFetch });
}

let clientInstance: Client | null = null;

export function getDb(): Client {
  if (!clientInstance) {
    clientInstance = getClient();
  }
  return clientInstance;
}

export function resetDb(): void {
  if (clientInstance) {
    try {
      clientInstance.close();
    } catch (e) {
      // ignore close errors
    }
    clientInstance = null;
  }
}

// Proxy to allow existing `db.execute(...)` and `db.batch(...)` calls to work seamlessly
export const db: Client = new Proxy({} as Client, {
  get(_target, prop) {
    const client = getDb();
    const value = (client as any)[prop];
    if (typeof value === "function") {
      return value.bind(client);
    }
    return value;
  }
});
