/**
 * 62vail.com — centralized form submission endpoint.
 *
 * Vercel auto-detects this file in the `/api/` directory and serves it as
 * a serverless function on the static-site Vercel project (no Node.js
 * config needed).
 *
 * Flow (2026-05-11, parity with thesixtytwovail.com):
 *
 *   client form → POST /api/submit-form (this fn)
 *                  ↓
 *           honeypot check (early exit, no network)
 *                  ↓
 *           forward → form-notify  (authoritative reCAPTCHA + spam gate)
 *                  ↓
 *           { success: true, accepted: true|false, reason? }
 *                  ↓
 *      accepted=true   →   upsert HubSpot
 *      accepted=false  →   append row to SPAM tab in 62vail's master Sheet
 *      network fail    →   skip both, log to console
 *
 * Always returns 200 to avoid leaking the spam-detection signal to bots.
 *
 * Why we don't verify reCAPTCHA in this route too: v3 tokens are
 * SINGLE-USE — Google's siteverify rejects the second verify of the same
 * token. form-notify is the authoritative gate; we read its `accepted`
 * flag and act accordingly. See FORMS-HUBSPOT-INTEGRATION.md §2.
 *
 * Required Vercel env vars (sensitive, production+preview):
 *   - HUBSPOT_SERVICE_KEY              for the HubSpot Contacts API upsert
 *   - GOOGLE_SERVICE_ACCOUNT_EMAIL     `claude@gen-lang-client-...iam.gserviceaccount.com`
 *   - GOOGLE_SERVICE_ACCOUNT_KEY       the BEGIN/END PRIVATE KEY block,
 *                                       with literal \n escape sequences
 *                                       (unescape happens in code below)
 *
 * The service account uses domain-wide delegation impersonating
 * justin@webeducationservices.com to access the 62vail sheet — same
 * pattern myaieditor's form-notify uses to create the sheet.
 */

const crypto = require("crypto");

const FORM_NOTIFY_URL = "https://myaieditor.com/api/form-notify";
const HUBSPOT_API = "https://api.hubapi.com";

// 62vail's master submissions sheet (from Supabase sites table —
// google_sheet_id for slug=62vail). Owned by justin@webeducationservices.com
// via domain-wide delegation; we impersonate justin@ to write.
const SPAM_SHEET_ID = "1sZRmEc-UAxzt46VANFI7EA0MHwqGCXHnL421hsxzucM";
const SPAM_TAB_RANGE = "SPAM!A:Z";
const IMPERSONATE_USER = "justin@webeducationservices.com";

// ── Google Sheets append helper (impersonation via JWT bearer) ──────

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function getGoogleAccessToken() {
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!email || !rawKey) {
    return { ok: false, reason: "GOOGLE_SERVICE_ACCOUNT_* env vars not set" };
  }
  const privateKey = rawKey.replace(/\\n/g, "\n");

  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64url(
    JSON.stringify({
      iss: email,
      sub: IMPERSONATE_USER,
      scope: "https://www.googleapis.com/auth/spreadsheets",
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    }),
  );
  const unsigned = `${header}.${claim}`;
  const signature = b64url(
    crypto.sign("RSA-SHA256", Buffer.from(unsigned), privateKey),
  );
  const jwt = `${unsigned}.${signature}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }).toString(),
  });
  const data = await res.json().catch(() => ({}));
  if (!data.access_token) {
    return { ok: false, reason: `oauth: ${data.error || JSON.stringify(data).slice(0, 200)}` };
  }
  return { ok: true, token: data.access_token };
}

async function appendSpamRow(payload, req, reason) {
  // Column order matches the SPAM tab header in the 62vail sheet:
  // timestamp | site_slug | form_type | first_name | last_name | email |
  // phone | reason | score | honeypot | ip | user_agent | referrer |
  // analytics_source
  const s = (v) => (typeof v === "string" ? v : "");
  const row = [
    new Date().toISOString(),
    s(payload.site_slug),
    s(payload.form_type),
    s(payload.first_name),
    s(payload.last_name),
    s(payload.email),
    s(payload.phone),
    reason,
    "",
    s(payload._honey),
    (req.headers && (req.headers["x-forwarded-for"] || req.headers["x-real-ip"])) || "",
    (req.headers && req.headers["user-agent"]) || "",
    s(payload.first_referrer),
    s(payload.analytics_source),
  ];

  try {
    const auth = await getGoogleAccessToken();
    if (!auth.ok) {
      console.error("[submit-form] SPAM auth failed:", auth.reason);
      return;
    }
    const url =
      `https://sheets.googleapis.com/v4/spreadsheets/${SPAM_SHEET_ID}` +
      `/values/${encodeURIComponent(SPAM_TAB_RANGE)}:append` +
      `?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ values: [row] }),
    });
    if (!res.ok) {
      const text = await res.text();
      console.error("[submit-form] SPAM append failed:", res.status, text.slice(0, 200));
    }
  } catch (err) {
    console.error("[submit-form] SPAM append threw:", err && err.message);
  }
}

// ── HubSpot upsert (preserved from previous version) ─────────────────

async function upsertHubspotContact(payload) {
  const token = process.env.HUBSPOT_SERVICE_KEY;
  if (!token) return { ok: false, reason: "HUBSPOT_SERVICE_KEY not set" };

  const email = payload.email;
  if (!email || !email.includes("@")) {
    return { ok: false, reason: "valid email required" };
  }

  const extras = [];
  if (payload.message) extras.push(`Message: ${payload.message}`);
  if (payload.company) extras.push(`Company: ${payload.company}`);
  if (payload.partner_type) extras.push(`Partner type: ${payload.partner_type}`);
  if (payload.position) extras.push(`Position: ${payload.position}`);
  if (payload.experience) extras.push(`Experience: ${payload.experience}`);
  if (payload.sms_consent) extras.push("SMS consent: yes");

  const properties = {
    email,
    lifecyclestage: "lead",
    // Mark as Marketing Contact + record explicit Opt_In. Both take the
    // literal string "true" — HubSpot's enumerations don't accept booleans.
    // hs_marketable_status is marked readOnlyValue=true in the schema, so
    // the Properties API blocks direct edits; the Contacts upsert path has
    // special handling. If it still gets rejected, the retry-on-readonly
    // logic below strips it and the contact lands with opt_in alone.
    hs_marketable_status: "true",
    opt_in: "true",
  };
  if (payload.first_name) properties.firstname = String(payload.first_name);
  if (payload.last_name) properties.lastname = String(payload.last_name);
  if (payload.phone) properties.phone = String(payload.phone);
  if (extras.length) properties.message = extras.join("\n");
  if (payload.form_type) properties.form_type = String(payload.form_type);
  properties.source_site = String(payload.site_slug || "62vail");

  if (payload.analytics_source) properties.hs_analytics_source = String(payload.analytics_source);
  if (payload.analytics_source_data_1) properties.hs_analytics_source_data_1 = String(payload.analytics_source_data_1);
  if (payload.analytics_source_data_2) properties.hs_analytics_source_data_2 = String(payload.analytics_source_data_2);
  if (payload.first_referrer) properties.hs_analytics_first_referrer = String(payload.first_referrer);
  if (payload.first_url) properties.hs_analytics_first_url = String(payload.first_url);

  try {
    let attempt = await postUpsertOnce(token, email, properties);
    if (!attempt.ok && attempt.unknownProps && attempt.unknownProps.length) {
      const trimmed = Object.assign({}, properties);
      for (const p of attempt.unknownProps) delete trimmed[p];
      console.warn("[hubspot] Stripping unknown custom props and retrying:", attempt.unknownProps.join(", "));
      attempt = await postUpsertOnce(token, email, trimmed);
    }
    return attempt;
  } catch (err) {
    return { ok: false, reason: err.message || "fetch failed" };
  }
}

async function postUpsertOnce(token, email, properties) {
  const res = await fetch(`${HUBSPOT_API}/crm/v3/objects/contacts/batch/upsert`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      inputs: [{ idProperty: "email", id: email, properties }],
    }),
  });
  const data = await res.json();
  if (res.ok && data.status === "COMPLETE" && data.results && data.results[0]) {
    const r = data.results[0];
    const created = new Date(r.createdAt).getTime();
    const updated = new Date(r.updatedAt).getTime();
    const status = Math.abs(updated - created) < 2000 ? "created" : "updated";
    return { ok: true, id: r.id, status };
  }
  const unknown = [];
  for (const e of data.errors || []) {
    if ((e.code === "PROPERTY_DOESNT_EXIST" || e.code === "READ_ONLY_VALUE") && e.context && e.context.propertyName) {
      for (const n of e.context.propertyName) unknown.push(n);
    }
  }
  return {
    ok: false,
    reason: data.message || `HTTP ${res.status}`,
    unknownProps: unknown.length ? unknown : undefined,
  };
}

// ── Main handler ─────────────────────────────────────────────────────

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const payload = typeof req.body === "object" && req.body !== null ? req.body : {};

  // 1. Honeypot trip → silent SPAM log + return 200 (no form-notify round-trip)
  if (typeof payload._honey === "string" && payload._honey.trim() !== "") {
    await appendSpamRow(payload, req, "honeypot filled");
    res.status(200).json({ success: true });
    return;
  }

  // 2. Forward to form-notify (authoritative gate). Parse the new `accepted`
  //    + `reason` fields so we can branch on its verdict instead of guessing
  //    from res.ok (which is true even for silent-dropped spam).
  let accepted = false;
  let reason = "form_notify_unreachable";
  let networkOk = false;
  try {
    const r = await fetch(FORM_NOTIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    networkOk = r.ok;
    if (r.ok) {
      const body = await r.json().catch(() => ({}));
      // Default-accept on missing `accepted` field so rolling form-notify
      // deploys don't drop real submissions.
      accepted = body.accepted !== false;
      if (typeof body.reason === "string") reason = body.reason;
    } else {
      reason = `form_notify_http_${r.status}`;
    }
  } catch (err) {
    console.error("[submit-form] form-notify forward failed:", err.message);
  }

  // 3a. Rejected by form-notify → SPAM log, skip HubSpot
  if (networkOk && !accepted) {
    await appendSpamRow(payload, req, reason);
    res.status(200).json({ success: true });
    return;
  }

  // 3b. Network failure → log to console, skip everything else.
  if (!networkOk) {
    console.error("[submit-form] form-notify network failure:", reason);
    res.status(200).json({ success: true });
    return;
  }

  // 4. Accepted → HubSpot upsert
  if (payload.email) {
    const result = await upsertHubspotContact(payload);
    if (!result.ok) {
      console.error("[submit-form] HubSpot upsert failed:", result.reason);
    } else {
      console.log(`[submit-form] HubSpot ${result.status}: id=${result.id}`);
    }
  }

  res.status(200).json({ success: true });
};
