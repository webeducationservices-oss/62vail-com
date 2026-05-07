/**
 * 62vail.com — centralized form submission endpoint.
 *
 * Vercel auto-detects this file in the `/api/` directory and serves it as
 * a serverless function on the static-site Vercel project (no Node.js
 * config needed).
 *
 * Mirrors the pattern on thesixtytwovail.com's Next.js /api/submit-form
 * route. Same env var (HUBSPOT_SERVICE_KEY), same flow:
 *
 *   client form → POST /api/submit-form (this fn)
 *                  ↓
 *                forward → myaieditor.com/api/form-notify
 *                  (handles reCAPTCHA + Sheet + email notifications)
 *                  ↓ if accepted
 *                upsert → HubSpot Contacts API (server-only token)
 *                  ↓
 *                respond { success: true }
 *
 * Always returns 200 to avoid leaking spam-detection signal to bots.
 *
 * HUBSPOT_SERVICE_KEY must be set in the Vercel project env (production +
 * preview targets, type: sensitive). Never expose to client code.
 */

const FORM_NOTIFY_URL = "https://myaieditor.com/api/form-notify";
const HUBSPOT_API = "https://api.hubapi.com";

async function upsertHubspotContact(payload) {
  const token = process.env.HUBSPOT_SERVICE_KEY;
  if (!token) return { ok: false, reason: "HUBSPOT_SERVICE_KEY not set" };

  const email = payload.email;
  if (!email || !email.includes("@")) {
    return { ok: false, reason: "valid email required" };
  }

  // Build a "message" capturing form-specific extras so nothing's lost
  // even without custom HubSpot properties for them.
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
  };
  if (payload.first_name) properties.firstname = String(payload.first_name);
  if (payload.last_name) properties.lastname = String(payload.last_name);
  if (payload.phone) properties.phone = String(payload.phone);
  if (extras.length) properties.message = extras.join("\n");
  if (payload.form_type) properties.form_type = String(payload.form_type);
  properties.source_site = String(payload.site_slug || "62vail");

  // Browser-side traffic-source attribution → standard HubSpot
  // hs_analytics_* properties. Without these, contacts created via the
  // Contacts API default to "Offline sources" in HubSpot's analytics.
  if (payload.analytics_source) properties.hs_analytics_source = String(payload.analytics_source);
  if (payload.analytics_source_data_1) properties.hs_analytics_source_data_1 = String(payload.analytics_source_data_1);
  if (payload.analytics_source_data_2) properties.hs_analytics_source_data_2 = String(payload.analytics_source_data_2);
  if (payload.first_referrer) properties.hs_analytics_first_referrer = String(payload.first_referrer);
  if (payload.first_url) properties.hs_analytics_first_url = String(payload.first_url);

  // Try with all properties; if HubSpot rejects unknown custom properties
  // (form_type / source_site / message), strip them and retry once.
  // Lets the integration ship today AND auto-upgrade once the portal has
  // those custom properties defined — no code change.
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
  // Strip names rejected as either PROPERTY_DOESNT_EXIST or READ_ONLY_VALUE.
  // The latter covers HubSpot's portal-managed analytics fields like
  // hs_analytics_source_data_1 / first_url that can only be written by
  // HubSpot's own tracking script, not via API.
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

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const payload = typeof req.body === "object" && req.body !== null ? req.body : {};

  // Step 1: forward to form-notify (reCAPTCHA + sheet + email)
  let formNotifyOk = false;
  try {
    const r = await fetch(FORM_NOTIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    formNotifyOk = r.ok;
  } catch (err) {
    console.error("[submit-form] form-notify forward failed:", err.message);
  }

  // Step 2: upsert HubSpot contact if form-notify accepted
  if (formNotifyOk && payload.email) {
    const result = await upsertHubspotContact(payload);
    if (!result.ok) {
      console.error("[submit-form] HubSpot upsert failed:", result.reason);
    } else {
      console.log(`[submit-form] HubSpot ${result.status}: id=${result.id}`);
    }
  }

  // Always success to client — avoid leaking spam-detection signal
  res.status(200).json({ success: true });
};
