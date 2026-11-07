// Lémou et Touty : paiement de l'abonnement des groupes avec SasPay
// Fonction serveur Vercel. Les clés secrètes viennent des variables d'environnement.
const crypto = require("crypto");

const SB_URL = process.env.SUPABASE_URL;
const SB_PUB = process.env.SUPABASE_PUBLISHABLE_KEY;
const SB_SECRET = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SP_KEY = process.env.SASPAY_API_KEY;
const SP_URL = process.env.SASPAY_BASE_URL || "https://api.saspay.me/api/v1";

function sbHeaders(extra) {
  const h = { apikey: SB_SECRET, "Content-Type": "application/json" };
  if (SB_SECRET && SB_SECRET.startsWith("eyJ")) h.Authorization = "Bearer " + SB_SECRET;
  return Object.assign(h, extra || {});
}
async function rest(path, opts) {
  opts = opts || {};
  const r = await fetch(SB_URL + "/rest/v1/" + path, { method: opts.method || "GET", headers: sbHeaders(opts.headers), body: opts.body });
  const t = await r.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch (e) {}
  return { ok: r.ok, data };
}
async function sp(path, opts) {
  opts = opts || {};
  const r = await fetch(SP_URL + path, {
    method: opts.method || "GET",
    headers: { Authorization: "Bearer " + SP_KEY, "Content-Type": "application/json" },
    body: opts.body,
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, data: (j && j.data) || j || {}, raw: j };
}
async function userFromReq(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const r = await fetch(SB_URL + "/auth/v1/user", { headers: { apikey: SB_PUB, Authorization: "Bearer " + token } });
  return r.ok ? r.json() : null;
}
async function isManager(uid, gid) {
  const m = await rest("memberships?group_id=eq." + gid + "&user_id=eq." + uid + "&role=eq.responsable&status=eq.active&select=id");
  return !!(m.ok && m.data && m.data.length);
}

// Vérifie auprès de SasPay si la session a été payée, puis active le groupe.
async function reconcile(row) {
  if (!row || row.status !== "pending" || !/^saspay:.+/.test(row.reference || "")) return false;
  const s = await sp("/checkout-sessions/" + encodeURIComponent(row.reference.slice(7)) + "/status/");
  if (!s.ok) return false;
  const d = s.data;
  if (d.status === "PAID" && (!d.transaction_status || d.transaction_status === "SUCCESS")) {
    const c = await rest("rpc/confirm_subscription_auto", { method: "POST", body: JSON.stringify({ pid: row.id }) });
    return c.ok;
  }
  return false;
}
async function reconcileRecent(gid) {
  const since = new Date(Date.now() - 3 * 86400000).toISOString();
  let q = "subscription_payments?status=eq.pending&reference=like.saspay:*&created_at=gte." + encodeURIComponent(since) + "&select=id,reference,status&limit=20";
  if (gid) q += "&group_id=eq." + gid;
  const r = await rest(q);
  let n = 0;
  for (const row of r.data || []) if (await reconcile(row)) n++;
  return n;
}

function readRaw(req) {
  return new Promise((ok, ko) => {
    const c = [];
    req.on("data", (d) => c.push(d));
    req.on("end", () => ok(Buffer.concat(c).toString("utf8")));
    req.on("error", ko);
  });
}
function validSig(raw, sig, ts, secret) {
  if (!secret || !sig || !ts) return false;
  if (!(Math.abs(Date.now() / 1000 - Number(ts)) <= 300)) return false;
  const exp = crypto.createHmac("sha256", secret).update(ts + "." + raw).digest("hex");
  const a = Buffer.from(exp), b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  let raw;
  try { raw = await readRaw(req); } catch (e) { return res.status(400).end(); }

  // 1) Webhook envoyé par SasPay : sert seulement de signal, la vérification se fait auprès de SasPay.
  if (req.headers["x-webhook-signature"]) {
    if (!validSig(raw, String(req.headers["x-webhook-signature"]), String(req.headers["x-webhook-timestamp"] || ""), process.env.SASPAY_WEBHOOK_SECRET)) {
      return res.status(403).end();
    }
    if (String(req.headers["x-webhook-event"] || "").indexOf("transaction.") !== 0) return res.status(200).json({ ok: true });
    try { await reconcileRecent(null); return res.status(200).json({ ok: true }); } catch (e) { return res.status(500).end(); }
  }

  // 2) Appels de l'application (le responsable du groupe doit être connecté)
  try {
    const user = await userFromReq(req);
    if (!user) return res.status(401).json({ error: "Connexion requise" });
    let body = {};
    try { body = JSON.parse(raw || "{}"); } catch (e) {}
    const gid = String(body.group_id || "");
    if (!/^[0-9a-f-]{36}$/i.test(gid)) return res.status(400).json({ error: "Groupe invalide" });
    if (!(await isManager(user.id, gid))) return res.status(403).json({ error: "Réservé au responsable du groupe" });

    if (body.action === "check") {
      const n = await reconcileRecent(gid);
      return res.status(200).json({ confirmed: n });
    }

    if (body.action === "create") {
      const origin = String(req.headers.origin || "");
      if (!/^https:\/\//.test(origin)) return res.status(400).json({ error: "Origine invalide" });
      const f = await rest("platform_settings?key=eq.fee_per_group&select=value");
      const fee = parseInt((f.data && f.data[0] && f.data[0].value) || "2000", 10) || 2000;
      const p = await rest("profiles?id=eq." + user.id + "&select=full_name");
      const name = (p.data && p.data[0] && p.data[0].full_name) || "Responsable";
      const ins = await rest("subscription_payments", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ group_id: gid, user_id: user.id, months: 1, amount: fee, method: "saspay", reference: "saspay:" }),
      });
      if (!ins.ok || !ins.data || !ins.data[0]) return res.status(500).json({ error: "Impossible d’enregistrer le paiement" });
      const rid = ins.data[0].id;
      const payload = {
        amount: fee + ".00",
        currency: "XOF",
        description: "Abonnement Lémou et Touty (1 mois)",
        customer_email: user.email,
        customer_name: name,
        return_url: origin + "/?paye=1",
        metadata: { sub_payment_id: rid, group_id: gid },
      };
      if (process.env.SASPAY_FEE_MODE === "ADD_ON" || process.env.SASPAY_FEE_MODE === "DEDUCTED") payload.fee_charge_mode = process.env.SASPAY_FEE_MODE;
      const s = await sp("/checkout-sessions/", { method: "POST", body: JSON.stringify(payload) });
      const d = s.data || {};
      if (!s.ok || !d.id || !d.checkout_url) {
        await rest("subscription_payments?id=eq." + rid, { method: "DELETE" });
        const msg = s.raw && (s.raw.message || s.raw.detail);
        return res.status(502).json({ error: typeof msg === "string" ? msg : "Le paiement n’a pas pu être créé" });
      }
      await rest("subscription_payments?id=eq." + rid, { method: "PATCH", body: JSON.stringify({ reference: "saspay:" + d.id }) });
      return res.status(200).json({ url: d.checkout_url });
    }

    return res.status(400).json({ error: "Action inconnue" });
  } catch (e) {
    return res.status(500).json({ error: "Erreur serveur" });
  }
};
module.exports.config = { api: { bodyParser: false } };
