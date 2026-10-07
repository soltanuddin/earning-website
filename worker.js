import { hashPassword, verifyPassword } from "./auth.js";

function json(data, status = 200) {
  return Response.json(data, { status });
}

function generateReferralCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));

  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join("");
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
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!name || !email || !password) {
          return json(
            {
              success: false,
              message: "Name, email and password are required."
            },
            400
          );
        }

        if (password.length < 6) {
          return json(
            {
              success: false,
              message: "Password must be at least 6 characters."
            },
            400
          );
        }

        // Check existing email
        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE email = ?"
          )
          .bind(email)
          .first();

        if (existing) {
          return json(
            {
              success: false,
              message: "Email already registered."
            },
            409
          );
        }

        // Hash password
        const passwordData = await hashPassword(password);

        const passwordHash =
          `${passwordData.salt}:${passwordData.hash}`;

        // Generate referral code
        let referralCode;

        for (let i = 0; i < 5; i++) {
          const code = generateReferralCode();

          const found = await env.DB
            .prepare(
              "SELECT id FROM users WHERE referral_code = ?"
            )
            .bind(code)
            .first();

          if (!found) {
            referralCode = code;
            break;
          }
        }

        if (!referralCode) {
          return json(
            {
              success: false,
              message: "Could not create referral code."
            },
            500
          );
        }

        // Create user
        const result = await env.DB
          .prepare(`
            INSERT INTO users
            (
              name,
              email,
              password_hash,
              balance,
              referral_code
            )
            VALUES (?, ?, ?, 0, ?)
          `)
          .bind(
            name,
            email,
            passwordHash,
            referralCode
          )
          .run();

        return json({
          success: true,
          message: "Registration successful.",
          user: {
            id: result.meta.last_row_id,
            name,
            email,
            balance: 0,
            referral_code: referralCode
          }
        });

      } catch (error) {
        return json(
          {
            success: false,
            message: "Registration failed.",
            error: error.message
          },
          500
        );
      }
    }

    // =========================
    // TEST DATABASE
    // =========================
    if (url.pathname === "/api/test-db") {
      try {
        const result = await env.DB
          .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
          )
          .all();

        return json({
          success: true,
          tables: result.results
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =========================
    // WEBSITE
    // =========================
    if (
      url.pathname === "/" ||
      url.pathname === "/index.html"
    ) {
      return env.ASSETS.fetch(
        new Request(
          new URL("/index.html", request.url),
          request
        )
      );
    }

    return env.ASSETS.fetch(request);
  }
};