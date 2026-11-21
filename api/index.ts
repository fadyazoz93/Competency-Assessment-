/**
 * ============================================================================
 * مواصفات التصميم المعماري لتحسين استهلاك قاعدة البيانات وضمان الترشيد والعزل
 * Database Optimization, Multi-Center Isolation & Legacy Turso Migration
 * ============================================================================
 * 1. عزل كامل لبيانات كل مركز (center_id) في الجداول والاستعلامات والكاش.
 * 2. فهارس مركّبة إلزامية تبدأ بـ center_id لمنع المسح الكامل للجداول.
 * 3. طبقة تخزين مؤقت في الذاكرة معزولة لكل مركز (Per-Center In-Memory Cache).
 * 4. استعلامات محددة الأعمدة فقط (بدون SELECT *) ومقيدة بـ LIMIT.
 * 5. جلب واستيراد آمن لبيانات المراكز من قواعد بيانات Turso سابقة.
 * ============================================================================
 */

import { createClient, type Client } from "@libsql/client";
import { db, resetDb } from "./lib/db.js";
import fs from "fs";
import path from "path";
import crypto from "crypto";

let isInitialized = false;

const DEFAULT_HOSPITAL_NAME = "مستشفى المنيا الجامعي للعيون";
const DEFAULT_CENTER_ID = "ctr_default";

const DEFAULT_INSPECTORS = ["د. محمد", "مس سارة"];
const DEFAULT_DEPARTMENTS = ["طوارئ", "عناية مركزة", "حضانات", "عمليات", "داخلي"];
const DEFAULT_CATEGORIES = ["أطباء", "تمريض", "عمال", "فنيين"];
const DEFAULT_INDICATORS = [
  {
    indicator: "نظافة الأيدي",
    procedure: "غسل الأيدي وتطهيرها",
    question: "هل قام بغسل الأيدي (اللحظة 1)؟",
    note: "لم يلتزم قبل لمس المريض",
    cats: ["أطباء", "تمريض"],
    depts: [],
  },
  {
    indicator: "الواقيات الشخصية",
    procedure: "ارتداء القفازات الواقية",
    question: "هل يرتدي القفازات عند اللزوم؟",
    note: "لم يرتدي القفازات",
    cats: ["تمريض", "عمال"],
    depts: [],
  },
];

const ALLOWED_SETTING_KEYS = [
  "hospital_name",
  "logo_right_url",
  "logo_left_url",
  "inspectors",
  "departments",
  "categories",
  "indicators",
  "indicator_targets",
] as const;

function sanitizeLogoUrl(raw: any): string {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) return "";
  if (trimmed.length > 2048) {
    throw new Error("رابط اللوجو طويل جداً (الحد الأقصى 2048 حرفاً).");
  }
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return trimmed;
    }
  } catch {
    // invalid URL
  }
  throw new Error("رابط اللوجو غير صالح. يرجى إدخال رابط صورة يبدأ بـ https:// أو http://");
}

// Helper to create default settings map for a center
function buildStarterSettings(centerName: string, emptyTemplate = false): Record<string, any> {
  if (emptyTemplate) {
    return {
      hospital_name: centerName,
      logo_right_url: "",
      logo_left_url: "",
      inspectors: [],
      departments: [],
      categories: [],
      indicators: [],
      indicator_targets: {},
    };
  }
  return {
    hospital_name: centerName,
    logo_right_url: "",
    logo_left_url: "",
    inspectors: [...DEFAULT_INSPECTORS],
    departments: [...DEFAULT_DEPARTMENTS],
    categories: [...DEFAULT_CATEGORIES],
    indicators: JSON.parse(JSON.stringify(DEFAULT_INDICATORS)),
    indicator_targets: {},
  };
}

async function seedCenterSettings(centerId: string, settingsObj: Record<string, any>) {
  const stmts = ALLOWED_SETTING_KEYS.map((k) => {
    let val = settingsObj[k];
    if (val === undefined) {
      if (k === "hospital_name") val = DEFAULT_HOSPITAL_NAME;
      else if (k === "logo_right_url" || k === "logo_left_url") val = "";
      else if (k === "indicator_targets") val = {};
      else val = [];
    }
    const serialized = typeof val === "string" ? val : JSON.stringify(val);
    return {
      sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
      args: [centerId, k, serialized],
    };
  });
  await db.batch(stmts, "write");
}

// Parse answer score supporting both 0..3 numeric scale and legacy Yes/No/NA
function parseAnswerPoints(ansRaw: any): { earned: number; max: number; isLow: boolean; numericVal: number | null } {
  const s = String(ansRaw ?? "").trim();
  if (s === "0" || s === "1" || s === "2" || s === "3") {
    const n = Number(s);
    return { earned: n, max: 3, isLow: n <= 1, numericVal: n };
  }
  if (s === "Yes") return { earned: 1, max: 1, isLow: false, numericVal: null };
  if (s === "No") return { earned: 0, max: 1, isLow: true, numericVal: null };
  return { earned: 0, max: 0, isLow: false, numericVal: null };
}

// Validate external Turso URL strictly to block SSRF & local file reads
function validateTursoUrl(rawUrl: string): string {
  const trimmed = String(rawUrl || "").trim();
  if (!trimmed) {
    throw new Error("يرجى إدخال رابط قاعدة بيانات Turso السابقة.");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("صيغة رابط قاعدة بيانات Turso غير صالحة. مثال: libsql://your-db.turso.io");
  }

  if (parsed.protocol !== "libsql:" && parsed.protocol !== "https:") {
    throw new Error("يُسمح فقط بروابط Turso الآمنة التي تبدأ بـ libsql:// أو https://");
  }

  const host = (parsed.hostname || "").toLowerCase().trim();
  if (!host || !host.includes(".")) {
    throw new Error("اسم النطاق في رابط Turso غير صالح.");
  }

  const blockedHosts = new Set([
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    "169.254.169.254",
    "metadata.google.internal",
  ]);
  if (
    blockedHosts.has(host) ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".localhost") ||
    /^10\./.test(host) ||
    /^127\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^0\./.test(host) ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host) ||
    /^\[?(fc|fd|fe80)/i.test(host)
  ) {
    throw new Error("رابط الخادم غير مسموح به لأسباب أمنية. يرجى استخدام رابط قاعدة بيانات Turso سحابي صالح.");
  }

  return trimmed;
}

// Ensure database tables, multi-center schema, migration from legacy tables, and indexes exist
async function ensureInitialized(retryCount = 0): Promise<void> {
  if (isInitialized) return;

  try {
    // 1. جدول المراكز
    await db.execute(`
      CREATE TABLE IF NOT EXISTS centers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );
    `);

    // 2. جدول إعدادات كل مركز (معزول تماماً بـ center_id)
    await db.execute(`
      CREATE TABLE IF NOT EXISTS center_settings (
        center_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT,
        PRIMARY KEY (center_id, key)
      );
    `);

    // 3. جدول بيانات مؤشرات الأداء
    await db.execute(`
      CREATE TABLE IF NOT EXISTS kpis_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        center_id TEXT,
        Date TEXT,
        Month INTEGER,
        Year INTEGER,
        Inspector TEXT,
        Department TEXT,
        Category TEXT,
        Session_Number INTEGER,
        Indicator TEXT,
        Procedure TEXT,
        Question TEXT,
        Answer TEXT,
        Note TEXT,
        Timestamp TEXT,
        Target_Name TEXT,
        Target_Job_ID TEXT,
        Recommendations TEXT,
        Reevaluation_Date TEXT
      );
    `);

    // التأكد من وجود الأعمدة المضافة في القواعد القديمة
    try {
      await db.execute("ALTER TABLE kpis_data ADD COLUMN Procedure TEXT");
    } catch {
      // Column already exists
    }
    try {
      await db.execute("ALTER TABLE kpis_data ADD COLUMN center_id TEXT");
    } catch {
      // Column already exists
    }
    try {
      await db.execute("ALTER TABLE kpis_data ADD COLUMN Recommendations TEXT");
    } catch {
      // Column already exists
    }
    try {
      await db.execute("ALTER TABLE kpis_data ADD COLUMN Reevaluation_Date TEXT");
    } catch {
      // Column already exists
    }

    // 4. إنشاء الفهارس المركّبة الإلزامية المعزولة بـ center_id
    try {
      await db.execute("CREATE INDEX IF NOT EXISTS idx_center_settings_cid ON center_settings (center_id);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center ON kpis_data (center_id);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_my ON kpis_data (center_id, Month, Year);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_my_ind ON kpis_data (center_id, Month, Year, Indicator);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_ind_year ON kpis_data (center_id, Indicator, Year);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_ind_proc ON kpis_data (center_id, Indicator, Procedure);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_ind_q ON kpis_data (center_id, Indicator, Question);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_session ON kpis_data (center_id, Month, Year, Indicator, Session_Number);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_center_target ON kpis_data (center_id, Target_Name, Target_Job_ID);");
      await db.execute("CREATE INDEX IF NOT EXISTS idx_kpis_data_date ON kpis_data (Date);");
    } catch (idxErr) {
      console.warn("Index creation notice:", idxErr);
    }

    // 5. التحقق من وجود مراكز أو ترحيل البيانات السابقة تلقائياً
    const centersCheck = await db.execute("SELECT COUNT(*) as count FROM centers");
    const centersCount = Number(centersCheck.rows[0].count);

    if (centersCount === 0) {
      let legacySettings: Record<string, any> = {};
      try {
        const legacyTableCheck = await db.execute(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='kpis_settings' LIMIT 1"
        );
        if (legacyTableCheck.rows.length > 0) {
          const legacyRows = await db.execute("SELECT key, value FROM kpis_settings LIMIT 100");
          for (const r of legacyRows.rows) {
            const k = String(r.key || "");
            const v = String(r.value || "");
            if (ALLOWED_SETTING_KEYS.includes(k as any)) {
              try {
                legacySettings[k] = JSON.parse(v);
              } catch {
                legacySettings[k] = v;
              }
            }
          }
        }
      } catch {
        // Ignore if legacy table doesn't exist
      }

      const defaultName =
        (typeof legacySettings.hospital_name === "string" && legacySettings.hospital_name.trim())
          ? legacySettings.hospital_name.trim()
          : DEFAULT_HOSPITAL_NAME;

      const nowIso = new Date().toISOString();
      await db.execute({
        sql: "INSERT INTO centers (id, name, created_at) VALUES (?, ?, ?)",
        args: [DEFAULT_CENTER_ID, defaultName, nowIso],
      });

      const starter = buildStarterSettings(defaultName, false);
      const mergedSettings: Record<string, any> = {
        hospital_name: defaultName,
        inspectors: Array.isArray(legacySettings.inspectors) ? legacySettings.inspectors : starter.inspectors,
        departments: Array.isArray(legacySettings.departments) ? legacySettings.departments : starter.departments,
        categories: Array.isArray(legacySettings.categories) ? legacySettings.categories : starter.categories,
        indicators: Array.isArray(legacySettings.indicators) ? legacySettings.indicators : starter.indicators,
        indicator_targets:
          legacySettings.indicator_targets && typeof legacySettings.indicator_targets === "object"
            ? legacySettings.indicator_targets
            : {},
      };
      await seedCenterSettings(DEFAULT_CENTER_ID, mergedSettings);

      // ربط أي سجلات سابقة في kpis_data بالمركز الافتراضي
      await db.execute({
        sql: "UPDATE kpis_data SET center_id = ? WHERE center_id IS NULL OR TRIM(center_id) = ''",
        args: [DEFAULT_CENTER_ID],
      });

      // إذا كان جدول البيانات فارغاً تماماً (تثبيت جديد)، يتم بذر جلسات أولية للمركز الافتراضي
      const dataCheck = await db.execute("SELECT COUNT(*) as count FROM kpis_data");
      const dataCount = Number(dataCheck.rows[0].count);
      if (dataCount === 0) {
        const timestamp = new Date().toISOString();
        const seedSessions = [
          { date: "2026-10-05", m: 10, y: 2026, sess: 1, insp: "د. محمد", dept: "عناية مركزة", cat: "أطباء", target: "د. كريم أحمد", job: "طبيب مقيم" },
          { date: "2026-10-08", m: 10, y: 2026, sess: 2, insp: "مس سارة", dept: "طوارئ", cat: "تمريض", target: "مريم علي", job: "أخصائية تمريض" },
          { date: "2026-10-12", m: 10, y: 2026, sess: 3, insp: "د. محمد", dept: "عمليات", cat: "أطباء", target: "د. مصطفى خالد", job: "استشاري جراحة" },
          { date: "2026-10-15", m: 10, y: 2026, sess: 4, insp: "مس سارة", dept: "حضانات", cat: "تمريض", target: "فاطمة محمود", job: "فني تمريض" },
          { date: "2026-10-18", m: 10, y: 2026, sess: 5, insp: "د. محمد", dept: "داخلي", cat: "عمال", target: "حسن عبد الله", job: "معاون خدمات" },
          { date: "2026-09-06", m: 9, y: 2026, sess: 1, insp: "د. محمد", dept: "عناية مركزة", cat: "أطباء", target: "د. كريم أحمد", job: "طبيب مقيم" },
          { date: "2026-09-14", m: 9, y: 2026, sess: 2, insp: "مس سارة", dept: "طوارئ", cat: "تمريض", target: "مريم علي", job: "أخصائية تمريض" },
          { date: "2026-09-22", m: 9, y: 2026, sess: 3, insp: "د. محمد", dept: "عمليات", cat: "أطباء", target: "د. مصطفى خالد", job: "استشاري جراحة" },
        ];

        const stmts: any[] = [];
        for (const s of seedSessions) {
          for (const k of DEFAULT_INDICATORS) {
            const isYes = s.sess % 3 !== 0;
            stmts.push({
              sql: `INSERT INTO kpis_data (
                center_id, Date, Month, Year, Inspector, Department, Category,
                Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp,
                Target_Name, Target_Job_ID
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              args: [
                DEFAULT_CENTER_ID,
                s.date,
                s.m,
                s.y,
                s.insp,
                s.dept,
                s.cat,
                s.sess,
                k.indicator,
                k.procedure,
                k.question,
                isYes ? "Yes" : "No",
                isYes ? "" : k.note,
                timestamp,
                s.target,
                s.job,
              ],
            });
          }
        }
        if (stmts.length > 0) {
          await db.batch(stmts, "write");
        }
      }
    } else {
      // ضمان عدم بقاء أي سجلات يتيمة بدون center_id
      const orphanCheck = await db.execute(
        "SELECT COUNT(*) as count FROM kpis_data WHERE center_id IS NULL OR TRIM(center_id) = ''"
      );
      if (Number(orphanCheck.rows[0].count) > 0) {
        const firstCenterRes = await db.execute("SELECT id FROM centers ORDER BY created_at ASC LIMIT 1");
        if (firstCenterRes.rows.length > 0) {
          const fallbackCid = String(firstCenterRes.rows[0].id);
          await db.execute({
            sql: "UPDATE kpis_data SET center_id = ? WHERE center_id IS NULL OR TRIM(center_id) = ''",
            args: [fallbackCid],
          });
        }
      }
    }

    isInitialized = true;
  } catch (err: any) {
    console.error("Database initialization error:", err);
    const errStr = String(err?.message || err);
    if ((errStr.includes("SQLITE_CORRUPT") || errStr.includes("malformed")) && retryCount === 0) {
      console.warn("Detected corrupted SQLite database file. Re-creating kpis.db...");
      resetDb();
      try {
        const dbPath = path.resolve(process.cwd(), "kpis.db");
        if (fs.existsSync(dbPath)) {
          fs.unlinkSync(dbPath);
        }
      } catch (e) {
        console.error("Error unlinking kpis.db:", e);
      }
      return ensureInitialized(1);
    }
    throw err;
  }
}

// قراءة بيانات الطلب (Request Body) بشكل متوافق مع Vercel و Node Middleware
async function getRequestBody(req: any): Promise<any> {
  if (req.body) {
    if (typeof req.body === "string") {
      try {
        return JSON.parse(req.body);
      } catch {
        return {};
      }
    }
    return req.body;
  }
  return new Promise((resolve) => {
    if (req.readableEnded) {
      resolve({});
      return;
    }
    let body = "";
    req.on("data", (chunk: any) => {
      body += chunk;
    });
    req.on("error", () => {
      resolve({});
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
  });
}

// ============================================================================
// نظام التخزين المؤقت في الذاكرة (Per-Center In-Memory Caching)
// ============================================================================
interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

const SETTINGS_CACHE_TTL = 10 * 60 * 1000; // 10 دقائق
const SUMMARY_CACHE_TTL = 2 * 60 * 1000; // دقيقتان
const SESSION_STATUS_TTL = 30 * 1000; // 30 ثانية
const DASHBOARD_CACHE_TTL = 2 * 60 * 1000; // دقيقتان

const settingsCacheByCenter = new Map<string, CacheEntry<any>>();
const procMapCacheByCenter = new Map<string, Record<string, string>>();
export const summaryCache = new Map<string, CacheEntry<any[]>>();
export const sessionStatusCache = new Map<string, CacheEntry<any>>();
export const dashboardCache = new Map<string, CacheEntry<any>>();

export function invalidateKpiDataCaches(centerId: string, indicator?: string) {
  const prefix = `${centerId}___`;
  for (const key of summaryCache.keys()) {
    if (key.startsWith(prefix)) summaryCache.delete(key);
  }
  for (const key of sessionStatusCache.keys()) {
    if (key.startsWith(prefix)) sessionStatusCache.delete(key);
  }
  for (const key of dashboardCache.keys()) {
    if (indicator) {
      if (key.startsWith(`${centerId}___${indicator}___`)) dashboardCache.delete(key);
    } else if (key.startsWith(prefix)) {
      dashboardCache.delete(key);
    }
  }
}

export function invalidateCenterAllCaches(centerId: string) {
  settingsCacheByCenter.delete(centerId);
  procMapCacheByCenter.delete(centerId);
  invalidateKpiDataCaches(centerId);
}

export function updateCachedSettingsInMemory(centerId: string, newSettings: any) {
  const prev = settingsCacheByCenter.get(centerId)?.data || {};
  settingsCacheByCenter.set(centerId, {
    data: { ...prev, ...newSettings },
    timestamp: Date.now(),
  });
  procMapCacheByCenter.delete(centerId);
}

// التحقق من وجود المركز وإرجاع بياناته
async function requireValidCenter(centerIdRaw: any): Promise<{ id: string; name: string }> {
  const cid = String(centerIdRaw || "").trim();
  if (!cid) {
    throw new Error("يرجى اختيار المركز وتسجيل الدخول إليه أولاً.");
  }
  const res = await db.execute({
    sql: "SELECT id, name FROM centers WHERE id = ? LIMIT 1",
    args: [cid],
  });
  if (res.rows.length === 0) {
    throw new Error("المركز المحدد غير موجود أو تم حذفه. يرجى اختيار مركز صالح.");
  }
  return {
    id: String(res.rows[0].id),
    name: String(res.rows[0].name),
  };
}

// جلب إعدادات مركز محدد مع التخزين المؤقت المعزول
async function getCenterSettingsInternal(centerId: string, centerNameFallback?: string, forceRefresh = false) {
  const now = Date.now();
  const cached = settingsCacheByCenter.get(centerId);
  if (!forceRefresh && cached && now - cached.timestamp < SETTINGS_CACHE_TTL) {
    return cached.data;
  }

  const rows = await db.execute({
    sql: "SELECT key, value FROM center_settings WHERE center_id = ? LIMIT 100",
    args: [centerId],
  });

  const settings: any = {};
  for (const r of rows.rows) {
    const key = String(r.key || "");
    const val = String(r.value || "");
    try {
      settings[key] = JSON.parse(val);
    } catch {
      settings[key] = val;
    }
  }

  if (!settings.hospital_name) {
    settings.hospital_name = centerNameFallback || DEFAULT_HOSPITAL_NAME;
  }
  if (typeof settings.logo_right_url !== "string") settings.logo_right_url = "";
  if (typeof settings.logo_left_url !== "string") settings.logo_left_url = "";
  if (!Array.isArray(settings.inspectors)) settings.inspectors = [];
  if (!Array.isArray(settings.departments)) settings.departments = [];
  if (!Array.isArray(settings.categories)) settings.categories = [];
  if (!Array.isArray(settings.indicators)) settings.indicators = [];
  if (!settings.indicator_targets || typeof settings.indicator_targets !== "object") {
    settings.indicator_targets = {};
  }

  settingsCacheByCenter.set(centerId, { data: settings, timestamp: now });
  procMapCacheByCenter.delete(centerId);
  return settings;
}

// بناء خريطة ربط السؤال بالإجراء في الذاكرة الخاصة بكل مركز
async function getQuestionToProcedureMap(centerId: string): Promise<Record<string, string>> {
  const cached = procMapCacheByCenter.get(centerId);
  if (cached) return cached;

  const settings = await getCenterSettingsInternal(centerId);
  const map: Record<string, string> = {};
  const inds = settings.indicators || [];
  for (const item of inds) {
    if (item && item.indicator && item.question) {
      const ind = String(item.indicator).trim();
      const q = String(item.question).trim();
      const proc = String(item.procedure || "عام").trim();
      map[`${ind}___${q}`] = proc;
    }
  }
  procMapCacheByCenter.set(centerId, map);
  return map;
}

// مزامنة سؤال جديد مع الجلسات المسجلة لنفس المركز فقط
async function syncQuestionToExistingSessions(
  centerId: string,
  indicator: string,
  procedure: string,
  question: string
): Promise<number> {
  const indTrim = String(indicator || "").trim();
  const procTrim = String(procedure || "عام").trim();
  const qTrim = String(question || "").trim();
  if (!indTrim || !qTrim) return 0;

  const timestamp = new Date().toISOString();
  let addedCount = 0;

  try {
    const batchRes = await db.execute({
      sql: `INSERT INTO kpis_data (
              center_id, Date, Month, Year, Inspector, Department, Category,
              Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp, Target_Name, Target_Job_ID
            )
            SELECT
              ?,
              COALESCE(s.Date, s.Year || '-' || substr('0' || s.Month, -2) || '-01'),
              s.Month, s.Year,
              COALESCE(s.Inspector, 'مسؤول التقييم'),
              COALESCE(s.Department, ''),
              COALESCE(s.Category, ''),
              COALESCE(s.Session_Number, 1),
              ?, ?, ?, '3', '', ?,
              COALESCE(s.Target_Name, ''),
              COALESCE(s.Target_Job_ID, '')
            FROM (
              SELECT Month, Year, COALESCE(Session_Number, 1) as Session_Number,
                     MAX(Date) as Date, MAX(Inspector) as Inspector,
                     MAX(Department) as Department, MAX(Category) as Category,
                     MAX(Target_Name) as Target_Name, MAX(Target_Job_ID) as Target_Job_ID
              FROM kpis_data
              WHERE center_id = ? AND (TRIM(Indicator) = ? OR Indicator = ?)
              GROUP BY Month, Year, COALESCE(Session_Number, 1)
            ) s
            WHERE NOT EXISTS (
              SELECT 1 FROM kpis_data ex
              WHERE ex.center_id = ?
                AND ex.Month = s.Month
                AND ex.Year = s.Year
                AND COALESCE(ex.Session_Number, 1) = s.Session_Number
                AND (TRIM(ex.Indicator) = ? OR ex.Indicator = ?)
                AND (TRIM(ex.Question) = ? OR ex.Question = ?)
            )`,
      args: [
        centerId,
        indTrim,
        procTrim,
        qTrim,
        timestamp,
        centerId,
        indTrim,
        indicator,
        centerId,
        indTrim,
        indicator,
        qTrim,
        question,
      ],
    });

    addedCount = batchRes.rowsAffected || 0;

    if (addedCount === 0) {
      const fallbackCheck = await db.execute({
        sql: "SELECT COUNT(*) as count FROM kpis_data WHERE center_id = ? AND (TRIM(Indicator) = ? OR Indicator = ?)",
        args: [centerId, indTrim, indicator],
      });

      if (Number(fallbackCheck.rows[0].count) === 0) {
        const otherRes = await db.execute({
          sql: `INSERT INTO kpis_data (
                  center_id, Date, Month, Year, Inspector, Department, Category,
                  Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp, Target_Name, Target_Job_ID
                )
                SELECT
                  ?,
                  COALESCE(s.Date, s.Year || '-' || substr('0' || s.Month, -2) || '-01'),
                  s.Month, s.Year,
                  COALESCE(s.Inspector, 'مسؤول التقييم'),
                  COALESCE(s.Department, ''),
                  COALESCE(s.Category, ''),
                  COALESCE(s.Session_Number, 1),
                  ?, ?, ?, '3', '', ?,
                  '', ''
                FROM (
                  SELECT Month, Year, 1 as Session_Number,
                         MAX(Date) as Date, MAX(Inspector) as Inspector,
                         MAX(Department) as Department, MAX(Category) as Category
                  FROM kpis_data
                  WHERE center_id = ?
                  GROUP BY Month, Year
                ) s
                WHERE NOT EXISTS (
                  SELECT 1 FROM kpis_data ex
                  WHERE ex.center_id = ?
                    AND ex.Month = s.Month
                    AND ex.Year = s.Year
                    AND (TRIM(ex.Indicator) = ? OR ex.Indicator = ?)
                    AND (TRIM(ex.Question) = ? OR ex.Question = ?)
                )`,
          args: [
            centerId,
            indTrim,
            procTrim,
            qTrim,
            timestamp,
            centerId,
            centerId,
            indTrim,
            indicator,
            qTrim,
            question,
          ],
        });
        addedCount = otherRes.rowsAffected || 0;
      }
    }

    await db.execute({
      sql: `UPDATE kpis_data SET Procedure = ?
            WHERE center_id = ?
              AND (TRIM(Indicator) = ? OR Indicator = ?)
              AND (TRIM(Question) = ? OR Question = ?)
              AND (Procedure IS NULL OR TRIM(Procedure) = '' OR TRIM(Procedure) = 'عام')`,
      args: [procTrim, centerId, indTrim, indicator, qTrim, question],
    });
  } catch (err) {
    console.error("Error in syncQuestionToExistingSessions:", err);
  }

  return addedCount;
}

// حذف سؤال نهائياً من نتائج المركز المحدد فقط
async function removeQuestionFromExistingSessions(
  centerId: string,
  indicator: string,
  question: string
): Promise<number> {
  const indTrim = String(indicator || "").trim();
  const qTrim = String(question || "").trim();
  if (!indTrim || !qTrim) return 0;
  const qClean = qTrim.replace(/[\?\؟\r\n\t]/g, "").trim();

  const delRes = await db.execute({
    sql: `DELETE FROM kpis_data
          WHERE center_id = ?
            AND (TRIM(Indicator) = ? OR Indicator = ?)
            AND (
              TRIM(Question) = ?
              OR Question = ?
              OR TRIM(REPLACE(REPLACE(Question, CHAR(13), ''), CHAR(10), '')) = ?
              OR REPLACE(TRIM(Question), '  ', ' ') = ?
              OR TRIM(REPLACE(REPLACE(REPLACE(REPLACE(Question, '؟', ''), '?', ''), CHAR(13), ''), CHAR(10), '')) = ?
            )`,
    args: [
      centerId,
      indicator,
      indTrim,
      question,
      qTrim,
      qTrim,
      qTrim.replace(/\s+/g, " "),
      qClean,
    ],
  });
  return delRes.rowsAffected || 0;
}

// Helper: قائمة المراكز مع الإحصائيات السريعة
async function listCentersWithStats() {
  const centersRes = await db.execute(
    "SELECT id, name, created_at FROM centers ORDER BY created_at ASC LIMIT 200"
  );
  const statsRes = await db.execute(`
    SELECT
      center_id,
      COUNT(*) as recordsCount,
      COUNT(DISTINCT Year || '-' || Month || '-' || Indicator || '-' || COALESCE(Session_Number, 1)) as sessionsCount,
      COUNT(DISTINCT Indicator) as indicatorsCount
    FROM kpis_data
    WHERE center_id IS NOT NULL
    GROUP BY center_id
    LIMIT 200
  `);

  const statsMap = new Map<string, { recordsCount: number; sessionsCount: number; indicatorsCount: number }>();
  for (const r of statsRes.rows) {
    statsMap.set(String(r.center_id), {
      recordsCount: Number(r.recordsCount) || 0,
      sessionsCount: Number(r.sessionsCount) || 0,
      indicatorsCount: Number(r.indicatorsCount) || 0,
    });
  }

  return centersRes.rows.map((c) => {
    const cid = String(c.id);
    const st = statsMap.get(cid) || { recordsCount: 0, sessionsCount: 0, indicatorsCount: 0 };
    return {
      id: cid,
      name: String(c.name),
      createdAt: String(c.created_at || ""),
      recordsCount: st.recordsCount,
      sessionsCount: st.sessionsCount,
      indicatorsCount: st.indicatorsCount,
    };
  });
}

// Helper: إنشاء مركز جديد
async function createCenterInternal(
  nameRaw: string,
  options?: { templateMode?: "starter" | "empty" | "copy"; copyFromCenterId?: string }
) {
  const name = String(nameRaw || "").trim();
  if (!name) {
    throw new Error("يرجى إدخال اسم المركز.");
  }
  if (name.length > 140) {
    throw new Error("اسم المركز طويل جداً (الحد الأقصى 140 حرفاً).");
  }

  // التحقق من عدم تكرار الاسم
  const existing = await db.execute({
    sql: "SELECT id FROM centers WHERE LOWER(TRIM(name)) = LOWER(?) LIMIT 1",
    args: [name],
  });
  if (existing.rows.length > 0) {
    throw new Error(`يوجد مركز مسجل بالفعل باسم "${name}". يرجى اختيار اسم مختلف أو الدخول إليه مباشرة.`);
  }

  const newId = `ctr_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`;
  const nowIso = new Date().toISOString();

  await db.execute({
    sql: "INSERT INTO centers (id, name, created_at) VALUES (?, ?, ?)",
    args: [newId, name, nowIso],
  });

  const mode = options?.templateMode || "starter";
  let settingsToSeed: Record<string, any>;

  if (mode === "copy" && options?.copyFromCenterId) {
    const srcCenter = await requireValidCenter(options.copyFromCenterId);
    const srcSettings = await getCenterSettingsInternal(srcCenter.id, srcCenter.name, true);
    settingsToSeed = {
      hospital_name: name,
      logo_right_url: "",
      logo_left_url: "",
      inspectors: [...(srcSettings.inspectors || [])],
      departments: [...(srcSettings.departments || [])],
      categories: [...(srcSettings.categories || [])],
      indicators: JSON.parse(JSON.stringify(srcSettings.indicators || [])),
      indicator_targets: JSON.parse(JSON.stringify(srcSettings.indicator_targets || {})),
    };
  } else if (mode === "empty") {
    settingsToSeed = buildStarterSettings(name, true);
  } else {
    settingsToSeed = buildStarterSettings(name, false);
  }

  await seedCenterSettings(newId, settingsToSeed);
  invalidateCenterAllCaches(newId);

  return {
    id: newId,
    name,
    createdAt: nowIso,
    recordsCount: 0,
    sessionsCount: 0,
    indicatorsCount: 0,
  };
}

// Helper: فحص قاعدة بيانات Turso سابقة
async function inspectLegacyTursoInternal(sourceUrlRaw: string, sourceAuthTokenRaw?: string) {
  const url = validateTursoUrl(sourceUrlRaw);
  const authToken = String(sourceAuthTokenRaw || "").trim() || undefined;

  let sourceClient: Client | null = null;
  try {
    sourceClient = createClient({ url, authToken });

    // التحقق من الجداول الموجودة في القاعدة السابقة
    const tablesRes = await sourceClient.execute(
      "SELECT name FROM sqlite_master WHERE type='table' LIMIT 100"
    );
    const tableNames = new Set(tablesRes.rows.map((r) => String(r.name || "")));

    const hasKpisData = tableNames.has("kpis_data");
    const hasLegacySettings = tableNames.has("kpis_settings");
    const hasCenters = tableNames.has("centers");
    const hasCenterSettings = tableNames.has("center_settings");

    if (!hasKpisData && !hasLegacySettings && !hasCenterSettings) {
      throw new Error("قاعدة البيانات المحددة لا تحتوي على جداول نظام مؤشرات الأداء (kpis_data / kpis_settings).");
    }

    let schemaType: "legacy" | "multi_center" = "legacy";
    let hospitalName = "";
    let totalRecords = 0;
    let monthsCount = 0;
    let indicators: string[] = [];
    let sourceCenters: Array<{ id: string; name: string; recordsCount: number }> = [];

    if (hasCenters) {
      const cRows = await sourceClient.execute("SELECT id, name FROM centers ORDER BY created_at ASC LIMIT 200");
      if (cRows.rows.length > 0) {
        schemaType = "multi_center";
        const countMap = new Map<string, number>();
        if (hasKpisData) {
          try {
            const cStats = await sourceClient.execute(
              "SELECT center_id, COUNT(*) as cnt FROM kpis_data GROUP BY center_id LIMIT 200"
            );
            for (const row of cStats.rows) {
              countMap.set(String(row.center_id || ""), Number(row.cnt) || 0);
            }
          } catch {
            // kpis_data might not have center_id
          }
        }
        sourceCenters = cRows.rows.map((r) => ({
          id: String(r.id),
          name: String(r.name),
          recordsCount: countMap.get(String(r.id)) || 0,
        }));
        hospitalName = sourceCenters[0].name;
      }
    }

    if (schemaType === "legacy" && hasLegacySettings) {
      const hRes = await sourceClient.execute({
        sql: "SELECT value FROM kpis_settings WHERE key = ? LIMIT 1",
        args: ["hospital_name"],
      });
      if (hRes.rows.length > 0) {
        const rawVal = String(hRes.rows[0].value || "");
        try {
          const parsed = JSON.parse(rawVal);
          hospitalName = typeof parsed === "string" ? parsed : rawVal;
        } catch {
          hospitalName = rawVal;
        }
      }
    }

    if (hasKpisData) {
      const cntRes = await sourceClient.execute("SELECT COUNT(*) as total FROM kpis_data");
      totalRecords = Number(cntRes.rows[0].total) || 0;

      const mRes = await sourceClient.execute(
        "SELECT COUNT(*) as mCount FROM (SELECT DISTINCT Year, Month FROM kpis_data WHERE Year IS NOT NULL AND Month IS NOT NULL)"
      );
      monthsCount = Number(mRes.rows[0].mCount) || 0;

      const indRes = await sourceClient.execute(
        "SELECT DISTINCT Indicator FROM kpis_data WHERE Indicator IS NOT NULL AND TRIM(Indicator) != '' LIMIT 200"
      );
      indicators = indRes.rows.map((r) => String(r.Indicator).trim()).filter(Boolean);
    }

    return {
      success: true,
      schemaType,
      hospitalName: hospitalName.trim(),
      totalRecords,
      monthsCount,
      indicatorsCount: indicators.length,
      indicators: indicators.slice(0, 25),
      hasSettings: hasLegacySettings || hasCenterSettings,
      sourceCenters,
    };
  } catch (err: any) {
    const msg = String(err?.message || err || "");
    if (msg.includes("401") || msg.includes("403") || msg.toLowerCase().includes("unauthorized")) {
      throw new Error("فشل المصادقة مع قاعدة بيانات Turso السابقة. يرجى التحقق من صحة Auth Token.");
    }
    throw new Error(msg || "تعذر الاتصال بقاعدة بيانات Turso السابقة.");
  } finally {
    if (sourceClient) {
      try {
        sourceClient.close();
      } catch {
        // ignore close errors
      }
    }
  }
}

// Helper: استيراد بيانات وسجلات من قاعدة بيانات Turso سابقة إلى مركز محدد (أو جديد) في القاعدة الحالية
async function importFromLegacyTursoInternal(params: {
  sourceUrl: string;
  sourceAuthToken?: string;
  targetCenterId?: string;
  newCenterName?: string;
  sourceCenterId?: string;
  importSettings?: boolean;
  importData?: boolean;
  replaceExisting?: boolean;
}) {
  const url = validateTursoUrl(params.sourceUrl);
  const authToken = String(params.sourceAuthToken || "").trim() || undefined;
  const doImportSettings = params.importSettings !== false;
  const doImportData = params.importData !== false;
  const replaceExisting = params.replaceExisting === true;

  let sourceClient: Client | null = null;
  try {
    sourceClient = createClient({ url, authToken });

    // 1. فحص الجداول في القاعدة السابقة
    const tablesRes = await sourceClient.execute(
      "SELECT name FROM sqlite_master WHERE type='table' LIMIT 100"
    );
    const tableNames = new Set(tablesRes.rows.map((r) => String(r.name || "")));
    const hasKpisData = tableNames.has("kpis_data");
    const hasLegacySettings = tableNames.has("kpis_settings");
    const hasCenterSettings = tableNames.has("center_settings");

    if (!hasKpisData && !hasLegacySettings && !hasCenterSettings) {
      throw new Error("قاعدة البيانات السابقة لا تحتوي على جداول صالحة للاستيراد.");
    }

    // 2. قراءة إعدادات المصدر
    const sourceSettings: Record<string, any> = {};
    let settingsReadCount = 0;
    const sourceCenterIdFilter = String(params.sourceCenterId || "").trim();

    if (doImportSettings) {
      if (hasCenterSettings && sourceCenterIdFilter) {
        const sRows = await sourceClient.execute({
          sql: "SELECT key, value FROM center_settings WHERE center_id = ? LIMIT 100",
          args: [sourceCenterIdFilter],
        });
        for (const r of sRows.rows) {
          const k = String(r.key || "");
          if (!ALLOWED_SETTING_KEYS.includes(k as any)) continue;
          const rawV = String(r.value || "");
          try {
            sourceSettings[k] = JSON.parse(rawV);
          } catch {
            sourceSettings[k] = rawV;
          }
          settingsReadCount++;
        }
      } else if (hasLegacySettings) {
        const sRows = await sourceClient.execute("SELECT key, value FROM kpis_settings LIMIT 100");
        for (const r of sRows.rows) {
          const k = String(r.key || "");
          if (!ALLOWED_SETTING_KEYS.includes(k as any)) continue;
          const rawV = String(r.value || "");
          try {
            sourceSettings[k] = JSON.parse(rawV);
          } catch {
            sourceSettings[k] = rawV;
          }
          settingsReadCount++;
        }
      }
    }

    // 3. تحديد أو إنشاء المركز الوجهة في القاعدة الحالية
    let targetCenter: { id: string; name: string };
    let createdNewCenter = false;

    if (params.newCenterName && String(params.newCenterName).trim()) {
      const created = await createCenterInternal(String(params.newCenterName).trim(), {
        templateMode: "empty",
      });
      targetCenter = { id: created.id, name: created.name };
      createdNewCenter = true;
    } else if (params.targetCenterId) {
      targetCenter = await requireValidCenter(params.targetCenterId);
    } else {
      throw new Error("يرجى تحديد المركز الوجهة أو إدخال اسم مركز جديد لاستيراد البيانات إليه.");
    }

    // 4. استيراد الإعدادات (مع الدمج الذكي أو الاستبدال، بدون كلمات مرور)
    let indicatorsImportedCount = 0;
    if (doImportSettings && settingsReadCount > 0) {
      const currentSettings = await getCenterSettingsInternal(targetCenter.id, targetCenter.name, true);
      const useReplaceSettings = createdNewCenter || replaceExisting;

      const mergeUniqueStrings = (base: any, incoming: any): string[] => {
        const a = Array.isArray(base) ? base.map((x) => String(x || "").trim()).filter(Boolean) : [];
        const b = Array.isArray(incoming) ? incoming.map((x) => String(x || "").trim()).filter(Boolean) : [];
        return Array.from(new Set(useReplaceSettings ? b : [...a, ...b]));
      };

      const mergeIndicators = (base: any, incoming: any): any[] => {
        const b = Array.isArray(incoming) ? incoming : [];
        indicatorsImportedCount = b.length;
        if (useReplaceSettings) return b;
        const a = Array.isArray(base) ? base : [];
        const seen = new Set(
          a.map(
            (i: any) =>
              `${String(i.indicator || "").trim()}___${String(i.procedure || "عام").trim()}___${String(i.question || "").trim()}`
          )
        );
        const merged = [...a];
        for (const item of b) {
          const sig = `${String(item.indicator || "").trim()}___${String(item.procedure || "عام").trim()}___${String(item.question || "").trim()}`;
          if (!seen.has(sig)) {
            seen.add(sig);
            merged.push(item);
          }
        }
        return merged;
      };

      const mergedTargets = useReplaceSettings
        ? sourceSettings.indicator_targets || {}
        : { ...(currentSettings.indicator_targets || {}), ...(sourceSettings.indicator_targets || {}) };

      const finalSettings = {
        hospital_name: targetCenter.name,
        inspectors: mergeUniqueStrings(currentSettings.inspectors, sourceSettings.inspectors),
        departments: mergeUniqueStrings(currentSettings.departments, sourceSettings.departments),
        categories: mergeUniqueStrings(currentSettings.categories, sourceSettings.categories),
        indicators: mergeIndicators(currentSettings.indicators, sourceSettings.indicators),
        indicator_targets: mergedTargets,
      };

      await seedCenterSettings(targetCenter.id, finalSettings);
    }

    // 5. استيراد سجلات التقييم kpis_data على دفعات (Batched Pagination + Duplicate Prevention)
    let importedRecords = 0;
    let skippedDuplicates = 0;

    if (doImportData && hasKpisData) {
      // فحص أعمدة الجدول في المصدر لضمان التوافق مع كافة الإصدارات السابقة
      const colInfo = await sourceClient.execute("PRAGMA table_info(kpis_data)");
      const availableCols = new Set(colInfo.rows.map((r) => String(r.name || "")));

      const KNOWN_COLS = [
        "Date",
        "Month",
        "Year",
        "Inspector",
        "Department",
        "Category",
        "Session_Number",
        "Indicator",
        "Procedure",
        "Question",
        "Answer",
        "Note",
        "Timestamp",
        "Target_Name",
        "Target_Job_ID",
        "Recommendations",
        "Reevaluation_Date",
      ] as const;

      const selectedCols = KNOWN_COLS.filter((c) => availableCols.has(c));
      if (selectedCols.length === 0) {
        throw new Error("جدول kpis_data في القاعدة السابقة لا يحتوي على الأعمدة المتوقعة.");
      }

      const hasSourceCenterIdCol = availableCols.has("center_id");

      if (replaceExisting) {
        await db.execute({
          sql: "DELETE FROM kpis_data WHERE center_id = ?",
          args: [targetCenter.id],
        });
      }

      // تحميل بصمات السجلات الحالية للمركز الوجهة لمنع التكرار عند الدمج
      const existingSignatures = new Set<string>();
      if (!replaceExisting && !createdNewCenter) {
        const existingRows = await db.execute({
          sql: `SELECT Date, Month, Year, Department, Category, Session_Number, Indicator, Question, Answer, Target_Name
                FROM kpis_data WHERE center_id = ? LIMIT 50000`,
          args: [targetCenter.id],
        });
        for (const r of existingRows.rows) {
          const sig = [
            String(r.Date || ""),
            String(r.Month || ""),
            String(r.Year || ""),
            String(r.Department || ""),
            String(r.Category || ""),
            String(r.Session_Number ?? 1),
            String(r.Indicator || "").trim(),
            String(r.Question || "").trim(),
            String(r.Answer || ""),
            String(r.Target_Name || "").trim(),
          ].join("||");
          existingSignatures.add(sig);
        }
      }

      const procMap = await getQuestionToProcedureMap(targetCenter.id);
      const PAGE_SIZE = 500;
      const WRITE_CHUNK = 80;
      let offset = 0;

      while (true) {
        let selectSql = `SELECT ${selectedCols.join(", ")} FROM kpis_data`;
        const selectArgs: any[] = [];
        if (hasSourceCenterIdCol && sourceCenterIdFilter) {
          selectSql += " WHERE center_id = ?";
          selectArgs.push(sourceCenterIdFilter);
        }
        selectSql += " LIMIT ? OFFSET ?";
        selectArgs.push(PAGE_SIZE, offset);

        const pageRes = await sourceClient.execute({ sql: selectSql, args: selectArgs });
        if (!pageRes.rows || pageRes.rows.length === 0) break;

        const batchStmts: any[] = [];
        for (const r of pageRes.rows) {
          const dateVal = String(r.Date || "");
          const monthVal = Number(r.Month) || 1;
          const yearVal = Number(r.Year) || new Date().getFullYear();
          const inspVal = String(r.Inspector || "مسؤول التقييم");
          const deptVal = String(r.Department || "");
          const catVal = String(r.Category || "");
          const sessVal = r.Session_Number !== null && r.Session_Number !== undefined ? Number(r.Session_Number) : 1;
          const indVal = String(r.Indicator || "").trim();
          const qVal = String(r.Question || "").trim();
          const procVal = String(r.Procedure || "").trim() || procMap[`${indVal}___${qVal}`] || "عام";
          const ansVal = String(r.Answer || "Yes");
          const noteVal = String(r.Note || "");
          const tsVal = String(r.Timestamp || new Date().toISOString());
          const targetNameVal = String(r.Target_Name || "");
          const targetJobVal = String(r.Target_Job_ID || "");
          const recommendationsVal = String(r.Recommendations || "");
          const reevalDateVal = String(r.Reevaluation_Date || "");

          if (!replaceExisting && !createdNewCenter) {
            const sig = [
              dateVal,
              String(monthVal),
              String(yearVal),
              deptVal,
              catVal,
              String(sessVal),
              indVal,
              qVal,
              ansVal,
              targetNameVal.trim(),
            ].join("||");
            if (existingSignatures.has(sig)) {
              skippedDuplicates++;
              continue;
            }
            existingSignatures.add(sig);
          }

          batchStmts.push({
            sql: `INSERT INTO kpis_data (
              center_id, Date, Month, Year, Inspector, Department, Category,
              Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp,
              Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            args: [
              targetCenter.id,
              dateVal,
              monthVal,
              yearVal,
              inspVal,
              deptVal,
              catVal,
              sessVal,
              indVal,
              procVal,
              qVal,
              ansVal,
              noteVal,
              tsVal,
              targetNameVal,
              targetJobVal,
              recommendationsVal,
              reevalDateVal,
            ],
          });

          if (batchStmts.length >= WRITE_CHUNK) {
            await db.batch(batchStmts, "write");
            importedRecords += batchStmts.length;
            batchStmts.length = 0;
          }
        }

        if (batchStmts.length > 0) {
          await db.batch(batchStmts, "write");
          importedRecords += batchStmts.length;
        }

        if (pageRes.rows.length < PAGE_SIZE) break;
        offset += PAGE_SIZE;
      }
    }

    invalidateCenterAllCaches(targetCenter.id);

    return {
      success: true,
      center: targetCenter,
      createdNewCenter,
      importedRecords,
      skippedDuplicates,
      settingsImported: doImportSettings && settingsReadCount > 0,
      indicatorsImported: indicatorsImportedCount,
    };
  } catch (err: any) {
    const msg = String(err?.message || err || "");
    if (msg.includes("401") || msg.includes("403") || msg.toLowerCase().includes("unauthorized")) {
      throw new Error("فشل المصادقة مع قاعدة بيانات Turso السابقة. يرجى التحقق من صحة Auth Token.");
    }
    throw new Error(msg || "حدث خطأ أثناء استيراد البيانات من Turso.");
  } finally {
    if (sourceClient) {
      try {
        sourceClient.close();
      } catch {
        // ignore close errors
      }
    }
  }
}

// ============================================================================
// دالة المعالجة الرئيسية للـ API
// ============================================================================
export default async function handler(req: any, res: any) {
  if (res.setHeader) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  try {
    await ensureInitialized();

    const body = await getRequestBody(req);
    const action = body.action;
    const args = Array.isArray(body.args) ? body.args : [];
    const reqCenterId = body.centerId;

    let result: any = null;

    switch (action) {
      // ------------------------------------------------------------------
      // إدارة المراكز واستيراد Turso (لا تتطلب مركزاً نشطاً مسبقاً)
      // ------------------------------------------------------------------
      case "listCenters": {
        result = await listCentersWithStats();
        break;
      }

      case "createCenter": {
        const [name, options] = args;
        const center = await createCenterInternal(name, options);
        result = { success: true, center };
        break;
      }

      case "renameCenter": {
        const [targetId, newNameRaw] = args;
        const center = await requireValidCenter(targetId);
        const newName = String(newNameRaw || "").trim();
        if (!newName) {
          throw new Error("يرجى إدخال اسم المركز الجديد.");
        }
        const dup = await db.execute({
          sql: "SELECT id FROM centers WHERE LOWER(TRIM(name)) = LOWER(?) AND id != ? LIMIT 1",
          args: [newName, center.id],
        });
        if (dup.rows.length > 0) {
          throw new Error(`يوجد مركز آخر مسجل بالفعل باسم "${newName}".`);
        }

        await db.batch(
          [
            { sql: "UPDATE centers SET name = ? WHERE id = ?", args: [newName, center.id] },
            {
              sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
              args: [center.id, "hospital_name", newName],
            },
          ],
          "write"
        );
        updateCachedSettingsInMemory(center.id, { hospital_name: newName });
        result = { success: true, center: { id: center.id, name: newName } };
        break;
      }

      case "deleteCenter": {
        const [targetId] = args;
        const center = await requireValidCenter(targetId);

        const delDataRes = await db.execute({
          sql: "DELETE FROM kpis_data WHERE center_id = ?",
          args: [center.id],
        });
        const delSettingsRes = await db.execute({
          sql: "DELETE FROM center_settings WHERE center_id = ?",
          args: [center.id],
        });
        await db.execute({
          sql: "DELETE FROM centers WHERE id = ?",
          args: [center.id],
        });

        invalidateCenterAllCaches(center.id);

        result = {
          success: true,
          deletedCenterId: center.id,
          deletedCenterName: center.name,
          deletedRecords: delDataRes.rowsAffected || 0,
          deletedSettings: delSettingsRes.rowsAffected || 0,
        };
        break;
      }

      case "inspectLegacyTurso": {
        const [payload] = args;
        result = await inspectLegacyTursoInternal(payload?.sourceUrl, payload?.sourceAuthToken);
        break;
      }

      case "importFromLegacyTurso": {
        const [payload] = args;
        result = await importFromLegacyTursoInternal(payload || {});
        break;
      }

      // ------------------------------------------------------------------
      // إجراءات المركز المعزولة (تتطلب centerId صالح وموثق)
      // ------------------------------------------------------------------
      case "getAppSettings": {
        const center = await requireValidCenter(reqCenterId);
        result = await getCenterSettingsInternal(center.id, center.name);
        break;
      }

      case "saveAppSettings": {
        const center = await requireValidCenter(reqCenterId);
        const newSettings = args[0] || {};
        const oldSettings = await getCenterSettingsInternal(center.id, center.name);
        const oldIndicators = oldSettings.indicators || [];
        const newIndicators = newSettings.indicators || [];

        const newHospitalName = String(newSettings.hospital_name || center.name).trim() || center.name;
        const sanitizedLogoRight =
          newSettings.logo_right_url !== undefined ? sanitizeLogoUrl(newSettings.logo_right_url) : undefined;
        const sanitizedLogoLeft =
          newSettings.logo_left_url !== undefined ? sanitizeLogoUrl(newSettings.logo_left_url) : undefined;

        // إذا تغير اسم المنشأة/المركز في الإعدادات نزامنه مع جدول المراكز (مع التحقق من عدم التكرار)
        if (newHospitalName !== center.name) {
          const dupCheck = await db.execute({
            sql: "SELECT id FROM centers WHERE LOWER(TRIM(name)) = LOWER(?) AND id != ? LIMIT 1",
            args: [newHospitalName, center.id],
          });
          if (dupCheck.rows.length > 0) {
            throw new Error(`اسم المركز "${newHospitalName}" مستخدم بالفعل لمركز آخر. يرجى اختيار اسم مختلف.`);
          }
          await db.execute({
            sql: "UPDATE centers SET name = ? WHERE id = ?",
            args: [newHospitalName, center.id],
          });
        }

        const stmts: any[] = [];
        for (const k of ALLOWED_SETTING_KEYS) {
          let val: any;
          if (k === "hospital_name") val = newHospitalName;
          else if (k === "logo_right_url") val = sanitizedLogoRight;
          else if (k === "logo_left_url") val = sanitizedLogoLeft;
          else val = newSettings[k];

          if (val === undefined) continue;
          if (typeof val !== "string") {
            val = JSON.stringify(val);
          }
          stmts.push({
            sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
            args: [center.id, k, val],
          });
        }
        if (stmts.length > 0) {
          await db.batch(stmts, "write");
        }

        // المزامنة التلقائية مع نتائج نفس المركز فقط
        if (Array.isArray(newIndicators)) {
          if (Array.isArray(oldIndicators)) {
            for (const oldItem of oldIndicators) {
              const oldInd = String(oldItem.indicator || "").trim();
              const oldQ = String(oldItem.question || "").trim();
              if (!oldInd || !oldQ) continue;
              const stillExists = newIndicators.some(
                (newItem: any) =>
                  String(newItem.indicator || "").trim() === oldInd &&
                  String(newItem.question || "").trim() === oldQ
              );
              if (!stillExists) {
                await removeQuestionFromExistingSessions(center.id, oldInd, oldQ);
              }
            }
          }

          for (const newItem of newIndicators) {
            const newInd = String(newItem.indicator || "").trim();
            const newProc = String(newItem.procedure || "عام").trim();
            const newQ = String(newItem.question || "").trim();
            if (!newInd || !newQ) continue;
            await syncQuestionToExistingSessions(center.id, newInd, newProc, newQ);
          }
        }

        updateCachedSettingsInMemory(center.id, {
          ...newSettings,
          hospital_name: newHospitalName,
          ...(sanitizedLogoRight !== undefined ? { logo_right_url: sanitizedLogoRight } : {}),
          ...(sanitizedLogoLeft !== undefined ? { logo_left_url: sanitizedLogoLeft } : {}),
        });
        invalidateKpiDataCaches(center.id);

        result = true;
        break;
      }

      case "getSessionStatus": {
        const center = await requireValidCenter(reqCenterId);
        const [_inspector, _dept, _category, indicator, dateStr] = args;
        const dateObj = new Date(dateStr);
        const m = dateObj.getMonth() + 1;
        const y = dateObj.getFullYear();
        const cacheKey = `${center.id}___${y}-${m}___${indicator}`;
        const now = Date.now();

        const cached = sessionStatusCache.get(cacheKey);
        if (cached && now - cached.timestamp < SESSION_STATUS_TTL) {
          result = cached.data;
          break;
        }

        const query = await db.execute({
          sql: "SELECT Session_Number, Answer FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ? LIMIT 2500",
          args: [center.id, m, y, indicator],
        });

        const sessionsMap: Record<number, { earned: number; max: number }> = {};
        let totalPreviousEarned = 0;
        let totalPreviousMax = 0;
        for (const row of query.rows) {
          const sNum = Number(row.Session_Number);
          if (!sessionsMap[sNum]) sessionsMap[sNum] = { earned: 0, max: 0 };
          const parsed = parseAnswerPoints(row.Answer);
          if (parsed.max > 0) {
            sessionsMap[sNum].max += parsed.max;
            sessionsMap[sNum].earned += parsed.earned;
            totalPreviousMax += parsed.max;
            totalPreviousEarned += parsed.earned;
          }
        }

        const sessionNums = Object.keys(sessionsMap);
        let previousScoresSum = 0;
        let validSessionCount = 0;

        for (const sNumStr of sessionNums) {
          const s = sessionsMap[Number(sNumStr)];
          if (s.max > 0) {
            previousScoresSum += (s.earned / s.max) * 100;
            validSessionCount++;
          }
        }

        const count = sessionNums.length;
        const previousAverage = validSessionCount > 0 ? Math.round(previousScoresSum / validSessionCount) : null;

        result = {
          nextSession: count + 1,
          currentCount: count,
          previousAverage,
          previousScoresSum: Math.round(previousScoresSum),
          previousYesCount: totalPreviousEarned,
          previousTotalCount: totalPreviousMax,
          remaining: 999999,
          isFull: false,
        };

        sessionStatusCache.set(cacheKey, { data: result, timestamp: now });
        break;
      }

      case "submitKpiForm": {
        const center = await requireValidCenter(reqCenterId);
        const form = args[0] || {};
        const targetName = String(form.targetName || "").trim();
        const targetJobId = String(form.targetJobId || "").trim();
        if (!targetName || !targetJobId) {
          throw new Error("يرجى إدخال الاسم والوظيفة (حقول إجبارية).");
        }
        const recommendations = String(form.recommendations || "").trim();
        const reevaluationDate = String(form.reevaluationDate || "").trim();

        const dateObj = new Date(form.date);
        const month = dateObj.getMonth() + 1;
        const year = dateObj.getFullYear();
        const timestampStr = new Date().toISOString();
        const dateStr = dateObj.toISOString().slice(0, 10);
        const procMap = await getQuestionToProcedureMap(center.id);

        const stmts = (form.answers || []).map((ans: any) => {
          const proc = ans.procedure || procMap[`${form.indicator}___${ans.question}`] || "عام";
          return {
            sql: `INSERT INTO kpis_data (
              center_id, Date, Month, Year, Inspector, Department, Category,
              Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp,
              Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            args: [
              center.id,
              dateStr,
              month,
              year,
              form.inspector,
              "",
              "",
              form.sessionNum,
              form.indicator,
              proc,
              ans.question,
              ans.answer,
              ans.note || "",
              timestampStr,
              targetName,
              targetJobId,
              recommendations,
              reevaluationDate,
            ],
          };
        });

        if (stmts.length > 0) {
          await db.batch(stmts, "write");
        }

        invalidateKpiDataCaches(center.id, form.indicator);
        result = { success: true, session: form.sessionNum };
        break;
      }

      case "fetchKpiReport": {
        const center = await requireValidCenter(reqCenterId);
        const monthStr = args[0];
        const indicatorFilter = args[1];
        if (!monthStr) {
          result = [];
          break;
        }
        const [y, m] = monthStr.split("-").map(Number);
        const procMap = await getQuestionToProcedureMap(center.id);

        let sql =
          "SELECT id, Month, Year, Date, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ?";
        const sqlArgs: any[] = [center.id, m, y];
        if (indicatorFilter) {
          sql += " AND Indicator = ?";
          sqlArgs.push(indicatorFilter);
        }
        sql += " ORDER BY Session_Number ASC, id ASC LIMIT 2500";

        const query = await db.execute({ sql, args: sqlArgs });

        result = query.rows.map((r) => {
          const ind = String(r.Indicator || "").trim();
          const q = String(r.Question || "").trim();
          return {
            id: r.id,
            month: `${r.Year}-${("0" + r.Month).slice(-2)}`,
            date: r.Date,
            department: r.Department,
            category: r.Category,
            sessionNumber: r.Session_Number,
            indicator: r.Indicator,
            procedure: r.Procedure || procMap[`${ind}___${q}`] || "عام",
            question: r.Question,
            answer: r.Answer,
            note: r.Note,
          };
        });
        break;
      }

      case "fetchReportsSummary": {
        const center = await requireValidCenter(reqCenterId);
        const monthFilter = args[0];
        const cacheKey = `${center.id}___${monthFilter || "all"}`;
        const now = Date.now();

        const cached = summaryCache.get(cacheKey);
        if (cached && now - cached.timestamp < SUMMARY_CACHE_TTL) {
          result = cached.data;
          break;
        }

        let sql = `
          SELECT
            Month, Year, Indicator,
            COUNT(*) as totalRecords,
            COUNT(DISTINCT Session_Number) as sessionsCount,
            SUM(CASE WHEN Answer = 'Yes' THEN 1 ELSE 0 END) as totalYes,
            SUM(CASE WHEN Answer IN ('Yes', 'No') THEN 1 ELSE 0 END) as totalValid
          FROM kpis_data
          WHERE center_id = ?
        `;
        const sqlArgs: any[] = [center.id];
        if (monthFilter && monthFilter !== "all") {
          const [y, m] = monthFilter.split("-").map(Number);
          sql += " AND Month = ? AND Year = ?";
          sqlArgs.push(m, y);
        }
        sql += " GROUP BY Year, Month, Indicator ORDER BY Year DESC, Month DESC, Indicator ASC LIMIT 500";

        const query = await db.execute({ sql, args: sqlArgs });
        const summary = query.rows.map((r) => {
          const m = Number(r.Month);
          const y = Number(r.Year);
          const totalValid = Number(r.totalValid) || 0;
          const totalYes = Number(r.totalYes) || 0;
          const score = totalValid > 0 ? Math.round((totalYes / totalValid) * 100) : 0;
          return {
            month: `${y}-${("0" + m).slice(-2)}`,
            year: y,
            monthNum: m,
            indicator: String(r.Indicator || "غير محدد").trim(),
            score,
            totalYes,
            totalValid,
            sessionsCount: Number(r.sessionsCount) || 1,
            totalRecords: Number(r.totalRecords) || 0,
          };
        });

        summaryCache.set(cacheKey, { data: summary, timestamp: now });
        result = summary;
        break;
      }

      case "fetchSelectedReports": {
        const center = await requireValidCenter(reqCenterId);
        const items = args[0];
        const procMap = await getQuestionToProcedureMap(center.id);
        const allResults: any[] = [];

        if (items === "all" || !Array.isArray(items) || items.length === 0) {
          const query = await db.execute({
            sql: "SELECT id, Month, Year, Date, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note FROM kpis_data WHERE center_id = ? ORDER BY Year DESC, Month DESC, Indicator ASC, id ASC LIMIT 5000",
            args: [center.id],
          });
          for (const r of query.rows) {
            const ind = String(r.Indicator || "").trim();
            const q = String(r.Question || "").trim();
            const m = Number(r.Month);
            const y = Number(r.Year);
            allResults.push({
              id: r.id,
              month: `${y}-${("0" + m).slice(-2)}`,
              date: r.Date,
              department: r.Department,
              category: r.Category,
              sessionNumber: r.Session_Number,
              indicator: r.Indicator,
              procedure: r.Procedure || procMap[`${ind}___${q}`] || "عام",
              question: r.Question,
              answer: r.Answer,
              note: r.Note,
            });
          }
        } else {
          for (const item of items) {
            if (!item.month || !item.indicator) continue;
            const [y, m] = item.month.split("-").map(Number);
            const query = await db.execute({
              sql: "SELECT id, Month, Year, Date, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ? ORDER BY id ASC LIMIT 2000",
              args: [center.id, m, y, item.indicator],
            });
            for (const r of query.rows) {
              const ind = String(r.Indicator || "").trim();
              const q = String(r.Question || "").trim();
              allResults.push({
                id: r.id,
                month: item.month,
                date: r.Date,
                department: r.Department,
                category: r.Category,
                sessionNumber: r.Session_Number,
                indicator: r.Indicator,
                procedure: r.Procedure || procMap[`${ind}___${q}`] || "عام",
                question: r.Question,
                answer: r.Answer,
                note: r.Note,
              });
            }
          }
        }
        result = allResults;
        break;
      }

      case "fetchAllResultsForExcel": {
        const center = await requireValidCenter(reqCenterId);
        const procMap = await getQuestionToProcedureMap(center.id);
        const query = await db.execute({
          sql: "SELECT id, Month, Year, Date, Inspector, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date FROM kpis_data WHERE center_id = ? ORDER BY Year DESC, Month DESC, Indicator ASC, COALESCE(Session_Number, 1) ASC, id ASC LIMIT 15000",
          args: [center.id],
        });
        result = query.rows.map((r) => {
          const ind = String(r.Indicator || "").trim();
          const q = String(r.Question || "").trim();
          const m = Number(r.Month);
          const y = Number(r.Year);
          return {
            id: r.id,
            month: `${y}-${("0" + m).slice(-2)}`,
            date: r.Date || `${y}-${("0" + m).slice(-2)}-01`,
            inspector: r.Inspector || "مسؤول التقييم",
            department: r.Department || "",
            category: r.Category || "",
            sessionNumber: r.Session_Number !== null && r.Session_Number !== undefined ? Number(r.Session_Number) : 1,
            indicator: r.Indicator,
            procedure: r.Procedure || procMap[`${ind}___${q}`] || "عام",
            question: r.Question,
            answer: r.Answer,
            note: r.Note || "",
            targetName: r.Target_Name || "",
            targetJobId: r.Target_Job_ID || "",
            recommendations: r.Recommendations || "",
            reevaluationDate: r.Reevaluation_Date || "",
          };
        });
        break;
      }

      case "fetchIndicatorRecordsForEdit": {
        const center = await requireValidCenter(reqCenterId);
        const [monthStr, indicator] = args;
        if (!monthStr || !indicator) {
          result = [];
          break;
        }
        const [y, m] = monthStr.split("-").map(Number);
        const procMap = await getQuestionToProcedureMap(center.id);
        const query = await db.execute({
          sql: "SELECT id, Date, Month, Year, Inspector, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ? ORDER BY Session_Number ASC, id ASC LIMIT 2000",
          args: [center.id, m, y, indicator],
        });
        result = query.rows.map((r) => {
          const ind = String(r.Indicator || "").trim();
          const q = String(r.Question || "").trim();
          return {
            id: r.id,
            date: r.Date,
            month: r.Month,
            year: r.Year,
            inspector: r.Inspector,
            department: r.Department,
            category: r.Category,
            sessionNumber: r.Session_Number,
            indicator: r.Indicator,
            procedure: r.Procedure || procMap[`${ind}___${q}`] || "عام",
            question: r.Question,
            answer: r.Answer,
            note: r.Note,
            targetName: r.Target_Name,
          };
        });
        break;
      }

      case "updateKpiRecords": {
        const center = await requireValidCenter(reqCenterId);
        const recordsToUpdate = args[0];
        if (Array.isArray(recordsToUpdate)) {
          const stmts = recordsToUpdate
            .filter((rec: any) => rec && rec.id)
            .map((rec: any) => ({
              sql: "UPDATE kpis_data SET Answer = ?, Note = ?, Department = ?, Category = ? WHERE id = ? AND center_id = ?",
              args: [rec.answer, rec.note || "", rec.department || "", rec.category || "", rec.id, center.id],
            }));
          if (stmts.length > 0) {
            await db.batch(stmts, "write");
          }
        }
        invalidateKpiDataCaches(center.id);
        result = { success: true };
        break;
      }

      case "deleteKpiReport": {
        const center = await requireValidCenter(reqCenterId);
        const [monthStr, indicator] = args;
        if (!monthStr || !indicator) {
          result = { success: false, error: "بيانات غير مكتملة" };
          break;
        }
        const [y, m] = monthStr.split("-").map(Number);
        await db.execute({
          sql: "DELETE FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ?",
          args: [center.id, m, y, indicator],
        });
        invalidateKpiDataCaches(center.id, indicator);
        result = { success: true };
        break;
      }

      case "cloneKpiReport": {
        const center = await requireValidCenter(reqCenterId);
        const [targetMonth, targetDate, targetIndicator, records] = args;
        if (!targetMonth || !targetIndicator || !Array.isArray(records) || records.length === 0) {
          result = { success: false, error: "بيانات غير مكتملة للنسخ" };
          break;
        }
        const [y, m] = targetMonth.split("-").map(Number);
        const timestamp = new Date().toISOString();
        const finalDate = targetDate || `${y}-${("0" + m).slice(-2)}-01`;
        const procMap = await getQuestionToProcedureMap(center.id);

        const stmts = records.map((r: any) => {
          const proc = r.procedure || procMap[`${targetIndicator}___${r.question}`] || "عام";
          return {
            sql: `INSERT INTO kpis_data (
              center_id, Date, Month, Year, Inspector, Department, Category, Session_Number,
              Indicator, Procedure, Question, Answer, Note, Timestamp, Target_Name, Target_Job_ID
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            args: [
              center.id,
              finalDate,
              m,
              y,
              r.inspector || "مسؤول التقييم",
              r.department || "",
              r.category || "",
              r.sessionNumber || 1,
              targetIndicator,
              proc,
              r.question || "",
              r.answer || "Yes",
              r.note || "",
              timestamp,
              r.targetName || "",
              r.targetJobId || "",
            ],
          };
        });

        for (let i = 0; i < stmts.length; i += 80) {
          await db.batch(stmts.slice(i, i + 80), "write");
        }

        invalidateKpiDataCaches(center.id, targetIndicator);
        result = { success: true, count: records.length };
        break;
      }

      case "multiplyKpiSessions": {
        const center = await requireValidCenter(reqCenterId);
        const [monthStr, indicator, multiplierRaw, optionsRaw] = args;
        const multiplier = Math.max(2, Math.min(25, parseInt(multiplierRaw, 10) || 2));
        const options = optionsRaw || {};

        if (!monthStr || !indicator) {
          result = { success: false, error: "بيانات غير مكتملة لمضاعفة الجلسات" };
          break;
        }

        const [y, m] = monthStr.split("-").map(Number);
        const query = await db.execute({
          sql: "SELECT id, Date, Month, Year, Inspector, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date FROM kpis_data WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ? ORDER BY Session_Number ASC, id ASC LIMIT 3000",
          args: [center.id, m, y, indicator],
        });

        const rows = query.rows;
        if (!rows || rows.length === 0) {
          result = { success: false, error: "لا توجد جلسات أو سجلات مسجلة لهذا المؤشر في هذا الشهر للمضاعفة" };
          break;
        }

        const sessionsMap: Record<number, any[]> = {};
        for (const r of rows) {
          const sNum = Number(r.Session_Number !== undefined ? r.Session_Number : r.session_number) || 1;
          if (!sessionsMap[sNum]) sessionsMap[sNum] = [];
          sessionsMap[sNum].push(r);
        }

        const existingSessionNumbers = Object.keys(sessionsMap)
          .map(Number)
          .sort((a, b) => a - b);
        const currentSessionsCount = existingSessionNumbers.length;
        const maxExistingSession = existingSessionNumbers.length > 0 ? Math.max(...existingSessionNumbers) : 0;

        const timestamp = new Date().toISOString();
        const procMap = await getQuestionToProcedureMap(center.id);
        let addedRecordsCount = 0;
        let addedSessionsCount = 0;

        const cycles = multiplier - 1;
        const batchStmts: any[] = [];

        for (let cycle = 1; cycle <= cycles; cycle++) {
          for (let i = 0; i < existingSessionNumbers.length; i++) {
            const origSessionNum = existingSessionNumbers[i];
            const recordsInSession = sessionsMap[origSessionNum] || [];

            addedSessionsCount++;
            const newSessionNumber = maxExistingSession + addedSessionsCount;

            let sessionDate: string;
            if (options.dateMode === "custom" && options.customDate) {
              sessionDate = options.customDate;
            } else if (options.dateMode === "today") {
              sessionDate = new Date().toISOString().slice(0, 10);
            } else {
              sessionDate =
                recordsInSession[0]?.Date ||
                recordsInSession[0]?.date ||
                `${y}-${("0" + m).slice(-2)}-01`;
            }

            for (const r of recordsInSession) {
              const ind = String(r.Indicator || r.indicator || indicator).trim();
              const q = String(r.Question || r.question || "").trim();
              const proc = r.Procedure || r.procedure || procMap[`${ind}___${q}`] || "عام";

              let answer = String(r.Answer ?? r.answer ?? "3").trim();
              let note = String(r.Note || r.note || "");

              if (options.slightVariation && Math.random() < 0.05) {
                if (answer === "3") {
                  answer = "1";
                  note = "تراجع بسيط في الدرجة بالجلسة الإضافية";
                } else if (answer === "Yes") {
                  answer = "No";
                  note = "عدم التزام تم رصده في الجلسة الإضافية";
                }
              }

              batchStmts.push({
                sql: `INSERT INTO kpis_data (
                  center_id, Date, Month, Year, Inspector, Department, Category, Session_Number,
                  Indicator, Procedure, Question, Answer, Note, Timestamp, Target_Name, Target_Job_ID,
                  Recommendations, Reevaluation_Date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                args: [
                  center.id,
                  sessionDate,
                  m,
                  y,
                  r.Inspector || r.inspector || "مسؤول التقييم",
                  r.Department || r.department || "",
                  r.Category || r.category || "",
                  newSessionNumber,
                  indicator,
                  proc,
                  q,
                  answer,
                  note,
                  timestamp,
                  r.Target_Name || r.target_name || "",
                  r.Target_Job_ID || r.target_job_id || "",
                  r.Recommendations || r.recommendations || "",
                  r.Reevaluation_Date || r.reevaluation_date || "",
                ],
              });
              addedRecordsCount++;
            }
          }
        }

        for (let i = 0; i < batchStmts.length; i += 80) {
          await db.batch(batchStmts.slice(i, i + 80), "write");
        }

        invalidateKpiDataCaches(center.id, indicator);

        result = {
          success: true,
          addedSessionsCount,
          totalSessionsCount: currentSessionsCount + addedSessionsCount,
          addedRecordsCount,
          multiplier,
          month: monthStr,
          indicator,
        };
        break;
      }

      case "deleteProcedureFromIndicator": {
        const center = await requireValidCenter(reqCenterId);
        const [indicatorRaw, procedureRaw] = args;
        const indicator = String(indicatorRaw || "").trim();
        const procedure = String(procedureRaw || "").trim();

        if (!indicator || !procedure) {
          result = { success: false, error: "المؤشر أو الإجراء غير محدد" };
          break;
        }

        const settings = await getCenterSettingsInternal(center.id, center.name);
        const rawIndicators = settings.indicators || [];
        const questionsToDelete: string[] = [];
        const remainingIndicators: any[] = [];

        for (const item of rawIndicators) {
          const itemInd = String(item.indicator || "").trim();
          const itemProc = String(item.procedure || "عام").trim();
          if (itemInd === indicator && itemProc === procedure) {
            if (item.question) questionsToDelete.push(String(item.question).trim());
          } else {
            remainingIndicators.push(item);
          }
        }

        await db.execute({
          sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
          args: [center.id, "indicators", JSON.stringify(remainingIndicators)],
        });

        let deletedRowsCount = 0;
        if (questionsToDelete.length > 0) {
          const placeholders = questionsToDelete.map(() => "?").join(",");
          const delRes = await db.execute({
            sql: `DELETE FROM kpis_data WHERE center_id = ? AND Indicator = ? AND (TRIM(Procedure) = ? OR TRIM(Procedure) IS NULL OR Procedure = '' OR Question IN (${placeholders}))`,
            args: [center.id, indicator, procedure, ...questionsToDelete],
          });
          deletedRowsCount = delRes.rowsAffected || 0;
        } else {
          const delRes = await db.execute({
            sql: "DELETE FROM kpis_data WHERE center_id = ? AND Indicator = ? AND (TRIM(Procedure) = ? OR Procedure = ?)",
            args: [center.id, indicator, procedure, procedure],
          });
          deletedRowsCount = delRes.rowsAffected || 0;
        }

        updateCachedSettingsInMemory(center.id, { indicators: remainingIndicators });
        invalidateKpiDataCaches(center.id, indicator);

        result = {
          success: true,
          indicator,
          procedure,
          deletedFromReports: deletedRowsCount,
          questionsDeleted: questionsToDelete.length,
        };
        break;
      }

      case "renameProcedure": {
        const center = await requireValidCenter(reqCenterId);
        const [indicatorRaw, oldProcRaw, newProcRaw, updateHistorical] = args;
        const indicator = String(indicatorRaw || "").trim();
        const oldProc = String(oldProcRaw || "").trim();
        const newProc = String(newProcRaw || "").trim();

        if (!indicator || !oldProc || !newProc) {
          result = { success: false, error: "المؤشر أو اسم الإجراء غير صالح" };
          break;
        }

        const settings = await getCenterSettingsInternal(center.id, center.name);
        let indicators = settings.indicators || [];
        let modified = false;

        indicators = indicators.map((item: any) => {
          if (
            item &&
            String(item.indicator || "").trim() === indicator &&
            String(item.procedure || "عام").trim() === oldProc
          ) {
            modified = true;
            return { ...item, procedure: newProc };
          }
          return item;
        });

        if (modified) {
          await db.execute({
            sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
            args: [center.id, "indicators", JSON.stringify(indicators)],
          });
        }

        let updatedHistoricalCount = 0;
        if (updateHistorical !== false) {
          const updRes = await db.execute({
            sql: "UPDATE kpis_data SET Procedure = ? WHERE center_id = ? AND Indicator = ? AND (TRIM(Procedure) = ? OR Procedure = ?)",
            args: [newProc, center.id, indicator, oldProc, oldProc],
          });
          updatedHistoricalCount = updRes.rowsAffected || 0;
        }

        updateCachedSettingsInMemory(center.id, { indicators });
        invalidateKpiDataCaches(center.id, indicator);

        result = { success: true, updatedHistoricalCount };
        break;
      }

      case "addProcedureToIndicator":
      case "addProcedureItemToReports": {
        const center = await requireValidCenter(reqCenterId);
        const [newItemOrInd, secondArg, thirdArg, fourthArg, fifthArg] = args;
        let indicator = "";
        let procedure = "";
        let question = "";
        let note = "";
        let addToExistingReports = true;

        if (typeof newItemOrInd === "object" && newItemOrInd !== null) {
          indicator = String(newItemOrInd.indicator || "").trim();
          procedure = String(newItemOrInd.procedure || "عام").trim();
          question = String(newItemOrInd.question || "").trim();
          note = String(newItemOrInd.note || "").trim();
          addToExistingReports = secondArg !== false;
        } else {
          indicator = String(newItemOrInd || "").trim();
          procedure = String(secondArg || "عام").trim();
          question = String(thirdArg || "").trim();
          note = String(fourthArg || "").trim();
          addToExistingReports = fifthArg !== false;
        }

        if (!indicator || !question) {
          result = { success: false, error: "المؤشر والسؤال مطلوبان" };
          break;
        }

        if (!procedure) procedure = "عام";

        const settings = await getCenterSettingsInternal(center.id, center.name);
        const indicators = [...(settings.indicators || [])];
        const exists = indicators.some(
          (i: any) =>
            String(i.indicator || "").trim() === indicator &&
            String(i.procedure || "عام").trim() === procedure &&
            String(i.question || "").trim() === question
        );

        if (!exists) {
          indicators.push({
            indicator,
            procedure,
            question,
            note,
            cats: [],
            depts: [],
          });
          await db.execute({
            sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
            args: [center.id, "indicators", JSON.stringify(indicators)],
          });
        }

        let addedToSessionsCount = 0;
        if (addToExistingReports !== false) {
          addedToSessionsCount = await syncQuestionToExistingSessions(center.id, indicator, procedure, question);
        }

        updateCachedSettingsInMemory(center.id, { indicators });
        invalidateKpiDataCaches(center.id, indicator);

        result = { success: true, addedToSessionsCount, indicator, procedure, question };
        break;
      }

      case "deleteQuestionFromIndicator": {
        const center = await requireValidCenter(reqCenterId);
        const [indicatorRaw, questionRaw] = args;
        const indicator = String(indicatorRaw || "").trim();
        const question = String(questionRaw || "").trim();

        if (!indicator || !question) {
          result = { success: false, error: "المؤشر أو السؤال غير محدد" };
          break;
        }

        const cleanStr = (s: string) => String(s || "").replace(/[\r\n\t]/g, "").trim();
        const targetInd = cleanStr(indicator);
        const targetQ = cleanStr(question);

        const settings = await getCenterSettingsInternal(center.id, center.name);
        const indicators = (settings.indicators || []).filter((i: any) => {
          const itemInd = cleanStr(i.indicator);
          const itemQ = cleanStr(i.question);
          return !(itemInd === targetInd && itemQ === targetQ);
        });
        await db.execute({
          sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
          args: [center.id, "indicators", JSON.stringify(indicators)],
        });

        const deletedRows = await removeQuestionFromExistingSessions(center.id, indicator, question);

        updateCachedSettingsInMemory(center.id, { indicators });
        invalidateKpiDataCaches(center.id, indicator);

        result = {
          success: true,
          indicator,
          question,
          deletedFromReports: deletedRows,
        };
        break;
      }

      case "renameIndicator": {
        const center = await requireValidCenter(reqCenterId);
        const [oldNameRaw, newNameRaw, updateHistorical] = args;
        const oldName = String(oldNameRaw || "").trim();
        const newName = String(newNameRaw || "").trim();

        if (!oldName || !newName) {
          result = { success: false, error: "اسم المؤشر غير صالح" };
          break;
        }

        const settings = await getCenterSettingsInternal(center.id, center.name);
        let indicators = settings.indicators || [];
        let modified = false;

        indicators = indicators.map((item: any) => {
          if (item && String(item.indicator || "").trim() === oldName) {
            modified = true;
            return { ...item, indicator: newName };
          }
          return item;
        });

        const targets = { ...(settings.indicator_targets || {}) };
        if (targets[oldName] !== undefined) {
          targets[newName] = targets[oldName];
          delete targets[oldName];
        }

        await db.batch(
          [
            {
              sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
              args: [center.id, "indicators", JSON.stringify(indicators)],
            },
            {
              sql: "INSERT OR REPLACE INTO center_settings (center_id, key, value) VALUES (?, ?, ?)",
              args: [center.id, "indicator_targets", JSON.stringify(targets)],
            },
          ],
          "write"
        );

        let updatedRecordsCount = 0;
        if (updateHistorical !== false) {
          const updateRes = await db.execute({
            sql: "UPDATE kpis_data SET Indicator = ? WHERE center_id = ? AND Indicator = ?",
            args: [newName, center.id, oldName],
          });
          updatedRecordsCount = updateRes.rowsAffected || 0;
        }

        updateCachedSettingsInMemory(center.id, { indicators, indicator_targets: targets });
        invalidateKpiDataCaches(center.id);

        result = { success: true, oldName, newName, updatedRecordsCount, settingsUpdated: modified };
        break;
      }

      case "fetchIndividualAssessments": {
        const center = await requireValidCenter(reqCenterId);
        const query = await db.execute({
          sql: `SELECT id, Date, Month, Year, Inspector, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
                FROM kpis_data
                WHERE center_id = ?
                  AND ((Target_Name IS NOT NULL AND TRIM(Target_Name) != '') OR (Target_Job_ID IS NOT NULL AND TRIM(Target_Job_ID) != ''))
                ORDER BY Year DESC, Month DESC, id DESC
                LIMIT 3000`,
          args: [center.id],
        });
        const data = query.rows;

        const sessions: Record<string, any> = {};

        for (const r of data) {
          const name = r.Target_Name ? String(r.Target_Name).trim() : "";
          const jobId = r.Target_Job_ID ? String(r.Target_Job_ID).trim() : "";

          if (!name && !jobId) continue;

          const groupingKey = `${r.Date}_${r.Inspector}_${r.Session_Number}_${r.Indicator}_${name}_${jobId}`;

          if (!sessions[groupingKey]) {
            sessions[groupingKey] = {
              sessionKey: groupingKey,
              recordIds: [] as number[],
              date: r.Date,
              month: r.Month,
              year: r.Year,
              inspector: r.Inspector ? String(r.Inspector).trim() : "",
              sessionNumber: Number(r.Session_Number || 1),
              indicator: r.Indicator,
              name,
              jobId,
              totalQuestions: 0,
              yesCount: 0,
              notes: [],
              recommendations: r.Recommendations ? String(r.Recommendations).trim() : "",
              reevaluationDate: r.Reevaluation_Date ? String(r.Reevaluation_Date).trim() : "",
            };
          } else {
            if (!sessions[groupingKey].recommendations && r.Recommendations) {
              sessions[groupingKey].recommendations = String(r.Recommendations).trim();
            }
            if (!sessions[groupingKey].reevaluationDate && r.Reevaluation_Date) {
              sessions[groupingKey].reevaluationDate = String(r.Reevaluation_Date).trim();
            }
          }

          if (r.id !== undefined && r.id !== null) {
            sessions[groupingKey].recordIds.push(Number(r.id));
          }

          const qText = r.Question;
          const parsed = parseAnswerPoints(r.Answer);
          if (parsed.max > 0) {
            sessions[groupingKey].totalQuestions += parsed.max;
            sessions[groupingKey].yesCount += parsed.earned;
          }

          const note = r.Note ? String(r.Note).trim() : "";
          if (parsed.isLow) {
            if (parsed.numericVal !== null) {
              sessions[groupingKey].notes.push(`${qText} (الدرجة: ${parsed.numericVal}/3${note ? " - " + note : ""})`);
            } else {
              sessions[groupingKey].notes.push(qText + (note ? " (" + note + ")" : ""));
            }
          }
        }

        result = Object.values(sessions).map((s) => {
          const score = s.totalQuestions > 0 ? Math.round((s.yesCount / s.totalQuestions) * 100) : 0;
          const formattedMonth = ("0" + s.month).slice(-2);
          s.recordIds.sort((a: number, b: number) => a - b);
          return {
            sessionKey: s.sessionKey,
            recordIds: s.recordIds,
            date: s.date,
            month: formattedMonth,
            year: s.year,
            inspector: s.inspector,
            sessionNumber: s.sessionNumber,
            indicator: s.indicator,
            name: s.name,
            jobId: s.jobId,
            yesCount: s.yesCount,
            totalQuestions: s.totalQuestions,
            earnedPoints: s.yesCount,
            maxPoints: s.totalQuestions,
            score,
            notes: s.notes.join("<br>"),
            recommendations: s.recommendations || "",
            reevaluationDate: s.reevaluationDate || "",
          };
        });
        break;
      }

      case "fetchIndividualAssessmentDetails": {
        const center = await requireValidCenter(reqCenterId);
        const rawIds = Array.isArray(args[0]) ? args[0] : [];
        const recordIds: number[] = Array.from(
          new Set<number>(rawIds.map((x: any) => Number(x)).filter((n: number) => Number.isInteger(n) && n > 0))
        ).slice(0, 500);
        if (recordIds.length === 0) {
          throw new Error("لم يتم تحديد سجل صالح للعرض.");
        }

        const placeholders = recordIds.map(() => "?").join(",");
        const procMap = await getQuestionToProcedureMap(center.id);
        const query = await db.execute({
          sql: `SELECT id, Date, Month, Year, Inspector, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
                FROM kpis_data
                WHERE center_id = ? AND id IN (${placeholders})
                ORDER BY id ASC`,
          args: [center.id, ...recordIds],
        });

        if (query.rows.length === 0) {
          throw new Error("لم يتم العثور على التقييم المحدد في هذا المركز.");
        }

        const first = query.rows[0];
        let recommendations = "";
        let reevaluationDate = "";
        let earnedPoints = 0;
        let maxPoints = 0;

        const items = query.rows.map((r) => {
          const ind = String(r.Indicator || "").trim();
          const q = String(r.Question || "").trim();
          if (!recommendations && r.Recommendations) recommendations = String(r.Recommendations).trim();
          if (!reevaluationDate && r.Reevaluation_Date) reevaluationDate = String(r.Reevaluation_Date).trim();
          const parsed = parseAnswerPoints(r.Answer);
          if (parsed.max > 0) {
            earnedPoints += parsed.earned;
            maxPoints += parsed.max;
          }
          return {
            id: Number(r.id),
            procedure: r.Procedure ? String(r.Procedure).trim() : (procMap[`${ind}___${q}`] || "عام"),
            question: q,
            answer: r.Answer !== null && r.Answer !== undefined ? String(r.Answer) : "0",
            note: r.Note ? String(r.Note) : "",
          };
        });

        result = {
          recordIds: items.map((it) => it.id),
          date: String(first.Date || "").slice(0, 10),
          month: ("0" + first.Month).slice(-2),
          year: Number(first.Year),
          inspector: first.Inspector ? String(first.Inspector).trim() : "",
          sessionNumber: Number(first.Session_Number || 1),
          indicator: first.Indicator ? String(first.Indicator).trim() : "",
          name: first.Target_Name ? String(first.Target_Name).trim() : "",
          jobId: first.Target_Job_ID ? String(first.Target_Job_ID).trim() : "",
          recommendations,
          reevaluationDate,
          earnedPoints,
          maxPoints,
          score: maxPoints > 0 ? Math.round((earnedPoints / maxPoints) * 100) : 0,
          items,
        };
        break;
      }

      case "fetchMultipleIndividualAssessments": {
        const center = await requireValidCenter(reqCenterId);
        const sessionsIdsList = Array.isArray(args[0]) ? args[0] : [];
        const normalizedGroups: number[][] = sessionsIdsList
          .map((grp: any) =>
            Array.isArray(grp)
              ? Array.from(new Set<number>(grp.map((x: any) => Number(x)).filter((n: number) => Number.isInteger(n) && n > 0)))
              : []
          )
          .filter((grp: number[]) => grp.length > 0)
          .slice(0, 100);

        if (normalizedGroups.length === 0) {
          throw new Error("يرجى تحديد تقييم واحد على الأقل للطباعة.");
        }

        const allIds: number[] = Array.from(new Set<number>(normalizedGroups.flat())).slice(0, 4000);
        const placeholders = allIds.map(() => "?").join(",");
        const procMap = await getQuestionToProcedureMap(center.id);
        const query = await db.execute({
          sql: `SELECT id, Date, Month, Year, Inspector, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
                FROM kpis_data
                WHERE center_id = ? AND id IN (${placeholders})
                ORDER BY id ASC`,
          args: [center.id, ...allIds],
        });

        const rowById = new Map<number, any>();
        for (const r of query.rows) {
          rowById.set(Number(r.id), r);
        }

        const assessments: any[] = [];
        for (const grp of normalizedGroups) {
          const rows = grp.map((id) => rowById.get(id)).filter(Boolean);
          if (rows.length === 0) continue;
          const first = rows[0];
          let recommendations = "";
          let reevaluationDate = "";
          let earnedPoints = 0;
          let maxPoints = 0;

          const items = rows.map((r: any) => {
            const ind = String(r.Indicator || "").trim();
            const q = String(r.Question || "").trim();
            if (!recommendations && r.Recommendations) recommendations = String(r.Recommendations).trim();
            if (!reevaluationDate && r.Reevaluation_Date) reevaluationDate = String(r.Reevaluation_Date).trim();
            const parsed = parseAnswerPoints(r.Answer);
            if (parsed.max > 0) {
              earnedPoints += parsed.earned;
              maxPoints += parsed.max;
            }
            return {
              id: Number(r.id),
              procedure: r.Procedure ? String(r.Procedure).trim() : (procMap[`${ind}___${q}`] || "عام"),
              question: q,
              answer: r.Answer !== null && r.Answer !== undefined ? String(r.Answer) : "0",
              note: r.Note ? String(r.Note) : "",
            };
          });

          assessments.push({
            recordIds: items.map((it: any) => it.id),
            date: String(first.Date || "").slice(0, 10),
            month: ("0" + first.Month).slice(-2),
            year: Number(first.Year),
            inspector: first.Inspector ? String(first.Inspector).trim() : "",
            sessionNumber: Number(first.Session_Number || 1),
            indicator: first.Indicator ? String(first.Indicator).trim() : "",
            name: first.Target_Name ? String(first.Target_Name).trim() : "",
            jobId: first.Target_Job_ID ? String(first.Target_Job_ID).trim() : "",
            recommendations,
            reevaluationDate,
            earnedPoints,
            maxPoints,
            score: maxPoints > 0 ? Math.round((earnedPoints / maxPoints) * 100) : 0,
            items,
          });
        }

        result = assessments;
        break;
      }

      case "updateIndividualAssessment": {
        const center = await requireValidCenter(reqCenterId);
        const payload = args[0] || {};
        const rawIds = Array.isArray(payload.recordIds) ? payload.recordIds : [];
        const allowedIdSet = new Set(
          rawIds.map((x: any) => Number(x)).filter((n: number) => Number.isInteger(n) && n > 0)
        );
        if (allowedIdSet.size === 0) {
          throw new Error("معرفات التقييم غير صالحة.");
        }

        const targetName = String(payload.name || "").trim();
        const targetJobId = String(payload.jobId || "").trim();
        if (!targetName || !targetJobId) {
          throw new Error("يرجى إدخال الاسم والوظيفة (حقول إجبارية).");
        }

        const rawDate = String(payload.date || "").trim();
        const dateObj = new Date(rawDate);
        if (!rawDate || isNaN(dateObj.getTime())) {
          throw new Error("يرجى إدخال تاريخ صالح.");
        }
        const dateStr = dateObj.toISOString().slice(0, 10);
        const month = dateObj.getMonth() + 1;
        const year = dateObj.getFullYear();

        const inspector = String(payload.inspector || "").trim();
        const recommendations = String(payload.recommendations || "").trim();
        const reevaluationDate = String(payload.reevaluationDate || "").trim();
        const items = Array.isArray(payload.items) ? payload.items : [];

        const stmts: Array<{ sql: string; args: any[] }> = [];
        for (const item of items) {
          const itemId = Number(item && item.id);
          if (!Number.isInteger(itemId) || !allowedIdSet.has(itemId)) continue;
          const answerStr = item.answer !== undefined && item.answer !== null ? String(item.answer).trim() : "0";
          const noteStr = item.note ? String(item.note).trim() : "";
          stmts.push({
            sql: `UPDATE kpis_data
                  SET Date = ?, Month = ?, Year = ?, Inspector = ?, Target_Name = ?, Target_Job_ID = ?,
                      Recommendations = ?, Reevaluation_Date = ?, Answer = ?, Note = ?
                  WHERE id = ? AND center_id = ?`,
            args: [
              dateStr,
              month,
              year,
              inspector,
              targetName,
              targetJobId,
              recommendations,
              reevaluationDate,
              answerStr,
              noteStr,
              itemId,
              center.id,
            ],
          });
        }

        if (stmts.length === 0) {
          throw new Error("لا توجد بنود صالحة للتحديث.");
        }

        await db.batch(stmts, "write");
        invalidateKpiDataCaches(center.id);
        result = { success: true, updatedCount: stmts.length };
        break;
      }

      case "duplicateIndividualAssessment": {
        const center = await requireValidCenter(reqCenterId);
        const payload = args[0] || {};
        const rawIds = Array.isArray(payload.recordIds) ? payload.recordIds : [];
        const recordIds: number[] = Array.from(
          new Set<number>(rawIds.map((x: any) => Number(x)).filter((n: number) => Number.isInteger(n) && n > 0))
        ).slice(0, 500);
        if (recordIds.length === 0) {
          throw new Error("لم يتم تحديد سجل صالح للنسخ.");
        }

        const placeholders = recordIds.map(() => "?").join(",");
        const sourceQuery = await db.execute({
          sql: `SELECT id, Date, Month, Year, Inspector, Department, Category, Session_Number, Indicator, Procedure, Question, Answer, Note, Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
                FROM kpis_data
                WHERE center_id = ? AND id IN (${placeholders})
                ORDER BY id ASC`,
          args: [center.id, ...recordIds],
        });

        if (sourceQuery.rows.length === 0) {
          throw new Error("لم يتم العثور على التقييم المصدر في هذا المركز.");
        }

        const first = sourceQuery.rows[0];
        const targetName = String(payload.name !== undefined ? payload.name : first.Target_Name || "").trim();
        const targetJobId = String(payload.jobId !== undefined ? payload.jobId : first.Target_Job_ID || "").trim();
        if (!targetName || !targetJobId) {
          throw new Error("يرجى إدخال الاسم والوظيفة (حقول إجبارية).");
        }

        const rawDate = String(payload.date || first.Date || "").trim();
        const dateObj = new Date(rawDate);
        if (!rawDate || isNaN(dateObj.getTime())) {
          throw new Error("يرجى إدخال تاريخ صالح.");
        }
        const dateStr = dateObj.toISOString().slice(0, 10);
        const month = dateObj.getMonth() + 1;
        const year = dateObj.getFullYear();

        const inspector = String(payload.inspector !== undefined ? payload.inspector : first.Inspector || "").trim();
        const recommendations = String(
          payload.recommendations !== undefined ? payload.recommendations : first.Recommendations || ""
        ).trim();
        const reevaluationDate = String(
          payload.reevaluationDate !== undefined ? payload.reevaluationDate : first.Reevaluation_Date || ""
        ).trim();
        const indicatorName = String(first.Indicator || "").trim();

        const maxSessRes = await db.execute({
          sql: `SELECT COALESCE(MAX(Session_Number), 0) AS maxSession
                FROM kpis_data
                WHERE center_id = ? AND Month = ? AND Year = ? AND Indicator = ?`,
          args: [center.id, month, year, indicatorName],
        });
        const nextSessionNumber = Number(maxSessRes.rows[0]?.maxSession || 0) + 1;
        const timestampStr = new Date().toISOString();

        const stmts = sourceQuery.rows.map((r) => ({
          sql: `INSERT INTO kpis_data (
            center_id, Date, Month, Year, Inspector, Department, Category,
            Session_Number, Indicator, Procedure, Question, Answer, Note, Timestamp,
            Target_Name, Target_Job_ID, Recommendations, Reevaluation_Date
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [
            center.id,
            dateStr,
            month,
            year,
            inspector,
            "",
            "",
            nextSessionNumber,
            indicatorName,
            r.Procedure || "عام",
            r.Question || "",
            r.Answer !== null && r.Answer !== undefined ? String(r.Answer) : "0",
            r.Note || "",
            timestampStr,
            targetName,
            targetJobId,
            recommendations,
            reevaluationDate,
          ],
        }));

        await db.batch(stmts, "write");
        invalidateKpiDataCaches(center.id, indicatorName);
        result = { success: true, count: stmts.length, sessionNumber: nextSessionNumber };
        break;
      }

      case "deleteIndividualAssessment": {
        const center = await requireValidCenter(reqCenterId);
        const rawIds = Array.isArray(args[0]) ? args[0] : [];
        const recordIds: number[] = Array.from(
          new Set<number>(rawIds.map((x: any) => Number(x)).filter((n: number) => Number.isInteger(n) && n > 0))
        ).slice(0, 500);
        if (recordIds.length === 0) {
          throw new Error("لم يتم تحديد سجل صالح للحذف.");
        }

        const placeholders = recordIds.map(() => "?").join(",");
        const delRes = await db.execute({
          sql: `DELETE FROM kpis_data WHERE center_id = ? AND id IN (${placeholders})`,
          args: [center.id, ...recordIds],
        });

        invalidateKpiDataCaches(center.id);
        result = { success: true, deletedCount: delRes.rowsAffected || 0 };
        break;
      }

      case "getDashboardData": {
        const center = await requireValidCenter(reqCenterId);
        const [indicator, monthStr] = args;
        if (!monthStr || !indicator) {
          result = {
            monthlyCat: { labels: [], data: [] },
            monthlyDept: { labels: [], data: [] },
            annual: { labels: [], data: [] },
            totalInspections: 0,
            overallCompliance: 0,
          };
          break;
        }

        const cacheKey = `${center.id}___${indicator}___${monthStr}`;
        const now = Date.now();

        const cached = dashboardCache.get(cacheKey);
        if (cached && now - cached.timestamp < DASHBOARD_CACHE_TTL) {
          result = cached.data;
          break;
        }

        const [targetYear, targetMonth] = monthStr.split("-").map(Number);

        const query = await db.execute({
          sql: "SELECT Month, Department, Category, Answer FROM kpis_data WHERE center_id = ? AND Indicator = ? AND Year = ? LIMIT 10000",
          args: [center.id, indicator, targetYear],
        });
        const data = query.rows;

        const catStats: Record<string, { total: number; yes: number }> = {};
        const deptStats: Record<string, { total: number; yes: number }> = {};
        const annualStats: Record<number, { total: number; yes: number }> = {};

        for (let i = 1; i <= 12; i++) {
          annualStats[i] = { total: 0, yes: 0 };
        }

        let globalTotal = 0;
        let globalYes = 0;

        for (const row of data) {
          const rMonth = Number(row.Month);
          const rDept = row.Department ? String(row.Department) : "";
          const rCategory = row.Category ? String(row.Category) : "";
          const rAnswer = row.Answer ? String(row.Answer) : "";

          if (rAnswer === "NA") continue;

          if (!annualStats[rMonth]) annualStats[rMonth] = { total: 0, yes: 0 };
          annualStats[rMonth].total++;
          if (rAnswer === "Yes") annualStats[rMonth].yes++;

          if (rMonth === targetMonth) {
            if (rCategory && rCategory.trim()) {
              if (!catStats[rCategory]) catStats[rCategory] = { total: 0, yes: 0 };
              catStats[rCategory].total++;
              if (rAnswer === "Yes") catStats[rCategory].yes++;
            }

            if (rDept && rDept.trim()) {
              if (!deptStats[rDept]) deptStats[rDept] = { total: 0, yes: 0 };
              deptStats[rDept].total++;
              if (rAnswer === "Yes") deptStats[rDept].yes++;
            }

            globalTotal++;
            if (rAnswer === "Yes") globalYes++;
          }
        }

        const getChartData = (statsObj: Record<string, { total: number; yes: number }>) => {
          const labels = Object.keys(statsObj);
          const values = labels.map((key) => {
            const s = statsObj[key];
            return s.total ? Math.round((s.yes / s.total) * 100) : 0;
          });
          return { labels, data: values };
        };

        const annualLabels = [
          "يناير",
          "فبراير",
          "مارس",
          "أبريل",
          "مايو",
          "يونيو",
          "يوليو",
          "أغسطس",
          "سبتمبر",
          "أكتوبر",
          "نوفمبر",
          "ديسمبر",
        ];
        const annualData: number[] = [];
        for (let i = 1; i <= 12; i++) {
          const s = annualStats[i];
          annualData.push(s.total ? Math.round((s.yes / s.total) * 100) : 0);
        }

        result = {
          monthlyCat: getChartData(catStats),
          monthlyDept: getChartData(deptStats),
          annual: { labels: annualLabels, data: annualData },
          totalInspections: globalTotal,
          overallCompliance: globalTotal ? Math.round((globalYes / globalTotal) * 100) : 0,
        };

        dashboardCache.set(cacheKey, { data: result, timestamp: now });
        break;
      }

      default:
        throw new Error("Action غير معروف: " + action);
    }

    if (res.writeHead) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, data: result }));
    } else {
      res.json?.({ success: true, data: result }) || res.send?.({ success: true, data: result });
    }
  } catch (error: any) {
    console.error("API handler error:", error);
    if (res.writeHead) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: error.message || error.toString() }));
    } else {
      res.status?.(500).json?.({ success: false, error: error.message }) ||
        res.send?.({ success: false, error: error.toString() });
    }
  }
}
