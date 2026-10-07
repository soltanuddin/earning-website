import { hashPassword, verifyPassword } from "./auth.js";

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...extraHeaders
    }
  });
}

function generateReferralCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));

  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join("");
}

function generateSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function sessionCookie(token) {
  return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}

function clearSessionCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

function getSessionToken(request) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);

  return match ? match[1] : null;
}

async function getLoggedInUser(request, env) {
  const token = getSessionToken(request);

  if (!token) {
    return null;
  }

  const session = await env.DB
    .prepare(`
      SELECT
        sessions.user_id,
        sessions.expires_at,
        users.id,
        users.name,
        users.email,
        users.balance,
        users.referral_code
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.token = ?
      LIMIT 1
    `)
    .bind(token)
    .first();

  if (!session) {
    return null;
  }

  const expiresAt = new Date(session.expires_at).getTime();

  if (Number.isNaN(expiresAt) || expiresAt <= Date.now()) {
    await env.DB
      .prepare("DELETE FROM sessions WHERE token = ?")
      .bind(token)
      .run();

    return null;
  }

  return {
    id: session.id,
    name: session.name,
    email: session.email,
    balance: session.balance,
    referral_code: session.referral_code
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // REGISTER
    // =========================
    if (
      url.pathname === "/api/register" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const name = String(body.name || "").trim();
        const email = String(body.email || "")
          .trim()
          .toLowerCase();
        const password = String(body.password || "");

        if (!name || !email || !password) {
          return json({
            success: false,
            message: "Name, email and password are required."
          }, 400);
        }

        if (password.length < 6) {
          return json({
            success: false,
            message: "Password must be at least 6 characters."
          }, 400);
        }

        const existing = await env.DB
          .prepare("SELECT id FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (existing) {
          return json({
            success: false,
            message: "Email already registered."
          }, 409);
        }

        const passwordData = await hashPassword(password);

        const passwordHash =
          `${passwordData.salt}:${passwordData.hash}`;

        let referralCode = null;

        for (let i = 0; i < 5;