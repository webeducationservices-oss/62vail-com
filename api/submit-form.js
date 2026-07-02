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
const HUBSPOT_FORMS_API = "https://api.hsforms.com";
const HUBSPOT_PORTAL_ID = "48481800";
// "Website Lead (API Bridge)" — shared with thesixtytwovail (same portal).
// Server-side Forms API submissions stitch the visitor's hubspotutk cookie
// to the contact (Website activity panel), record a form-submission
// timeline event, and create the contact as a Marketing contact. Form
// GUIDs aren't secrets (visible in any embedded form's HTML).
const HUBSPOT_BRIDGE_FORM_GUID = "2214d219-b416-4b52-9d07-600dd0b2e49d";

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

// ── HubSpot Forms API bridge (identity stitching) ────────────────────
//
// Mirrors thesixtytwovail's src/lib/hubspot.ts submitToHubspotForm().
// Unlike the Contacts upsert, this path stitches the hubspotutk cookie to
// the contact (Website activity panel populates), records a form-submission
// timeline event, creates the contact as a Marketing contact, and lets
// HubSpot compute Original Source natively from the web session. Runs ONLY
// after form-notify accepts, so bots never reach it. No auth needed.

function isValidHutk(hutk) {
  return typeof hutk === "string" && /^[0-9a-f]{32}$/i.test(hutk);
}

async function submitToHubspotForm(payload) {
  const email = payload.email;
  if (!email || !email.includes("@")) {
    return { ok: false, reason: "valid email required" };
  }

  const fields = [{ objectTypeId: "0-1", name: "email", value: email }];
  if (payload.first_name) fields.push({ objectTypeId: "0-1", name: "firstname", value: String(payload.first_name) });
  if (payload.last_name) fields.push({ objectTypeId: "0-1", name: "lastname", value: String(payload.last_name) });
  if (payload.phone) fields.push({ objectTypeId: "0-1", name: "phone", value: String(payload.phone) });

  const context = {
    pageUri: (typeof payload.first_url === "string" && payload.first_url) || "https://62vail.com/",
    pageName: (typeof payload.form_type === "string" && payload.form_type) || "website_form",
  };
  if (isValidHutk(payload.hutk)) context.hutk = payload.hutk.toLowerCase();

  const url = `${HUBSPOT_FORMS_API}/submissions/v3/integration/submit/${HUBSPOT_PORTAL_ID}/${HUBSPOT_BRIDGE_FORM_GUID}`;

  try {
    let res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fields, context }),
    });
    if (res.ok) return { ok: true, hutk: !!context.hutk };

    // Field-validation failure (e.g. exotic phone format) — retry with the
    // minimum viable submission so identity stitching still happens.
    const firstBody = await res.text();
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fields: [{ objectTypeId: "0-1", name: "email", value: email }],
        context,
      }),
    });
    if (res.ok) return { ok: true, hutk: !!context.hutk };
    return { ok: false, reason: `HTTP ${res.status}: ${firstBody.slice(0, 200)}` };
  } catch (err) {
    return { ok: false, reason: (err && err.message) || "fetch failed" };
  }
}

// ── HubSpot upsert (preserved from previous version) ─────────────────

async function upsertHubspotContact(payload, skipAnalyticsProps) {
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

  // When the Forms bridge stitched a valid hutk, HubSpot computes Original
  // Source natively from the actual web session — don't fight it with our
  // client-side classification. Classified values remain the fallback for
  // cookie-less submissions.
  if (!skipAnalyticsProps) {
    if (payload.analytics_source) properties.hs_analytics_source = String(payload.analytics_source);
    if (payload.analytics_source_data_1) properties.hs_analytics_source_data_1 = String(payload.analytics_source_data_1);
    if (payload.analytics_source_data_2) properties.hs_analytics_source_data_2 = String(payload.analytics_source_data_2);
    if (payload.first_referrer) properties.hs_analytics_first_referrer = String(payload.first_referrer);
    if (payload.first_url) properties.hs_analytics_first_url = String(payload.first_url);
  }

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

  // 4. Accepted → HubSpot, two complementary calls
  if (payload.email) {
    // 4a. Forms API bridge — cookie → contact stitch (Website activity),
    //     form-submission timeline event, Marketing-contact status, native
    //     Original Source. Failure is non-fatal; the upsert still records.
    const formResult = await submitToHubspotForm(payload);
    if (!formResult.ok) {
      console.error("[submit-form] HubSpot Forms bridge failed:", formResult.reason);
    } else {
      console.log(`[submit-form] HubSpot Forms bridge ok (hutk=${formResult.hutk ? "yes" : "no"})`);
    }

    // 4b. Contacts upsert — custom props (form_type, source_site, opt_in,
    //     message digest). Skip classified analytics props when the bridge
    //     stitched natively.
    const result = await upsertHubspotContact(payload, formResult.ok && formResult.hutk);
    if (!result.ok) {
      console.error("[submit-form] HubSpot upsert failed:", result.reason);
    } else {
      console.log(`[submit-form] HubSpot ${result.status}: id=${result.id}`);
    }
  }

  // Accepted path only: `tracked` green-lights the client's HubSpot
  // identify call (stitches the hubspotutk cookie to the contact so
  // Website activity shows on the record). Spam/failure paths above
  // return plain { success: true } so bots see an identical success.
  res.status(200).json({ success: true, tracked: true });
};
