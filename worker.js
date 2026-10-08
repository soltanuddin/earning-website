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
          .prepare(
            "SELECT id FROM users WHERE email = ?"
          )
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

        for (let i = 0; i < 10; i++) {
          const candidate = generateReferralCode();

          const exists = await env.DB
            .prepare(
              "SELECT id FROM users WHERE referral_code = ?"
            )
            .bind(candidate)
            .first();

          if (!exists) {
            referralCode = candidate;
            break;
          }
        }

        if (!referralCode) {
          return json({
            success: false,
            message: "Could not create referral code."
          }, 500);
        }

        const result = await env.DB
          .prepare(`
            INSERT INTO users
            (name, email, password_hash, balance, referral_code)
            VALUES (?, ?, ?, 0, ?)
          `)
          .bind(
            name,
            email,
            passwordHash,
            referralCode
          )
          .run();

        if (!result.success) {
          return json({
            success: false,
            message: "Account creation failed."
          }, 500);
        }

        return json({
          success: true,
          message: "Account created successfully.",
          user: {
            name,
            email,
            balance: 0,
            referral_code: referralCode
          }
        }, 201);

      } catch (error) {
        return json({
          success: false,
          message: "Server error during registration."
        }, 500);
      }
    }

    // =========================
    // LOGIN
    // =========================
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const email = String(body.email || "")
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        if (!email || !password) {
          return json({
            success: false,
            message: "Email and password are required."
          }, 400);
        }

        const user = await env.DB
          .prepare(`
            SELECT
              id,
              name,
              email,
              password_hash,
              balance,
              referral_code
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        if (!user) {
          return json({
            success: false,
            message: "Invalid email or password."
          }, 401);
        }

        const parts = String(user.password_hash).split(":");

        if (parts.length !== 2) {
          return json({
            success: false,
            message: "Invalid account password data."
          }, 500);
        }

        const valid = await verifyPassword(
          password,
          parts[1],
          parts[0]
        );

        if (!valid) {
          return json({
            success: false,
            message: "Invalid email or password."
          }, 401);
        }

        const token = generateSessionToken();

        const expiresAt = new Date(
          Date.now() +
          7 * 24 * 60 * 60 * 1000
        ).toISOString();

        await env.DB
          .prepare(`
            INSERT INTO sessions
            (token, user_id, expires_at)
            VALUES (?, ?, ?)
          `)
          .bind(
            token,
            user.id,
            expiresAt
          )
          .run();

        return json({
          success: true,
          message: "Login successful.",
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            balance: user.balance,
            referral_code: user.referral_code
          }
        }, 200, {
          "Set-Cookie": sessionCookie(token)
        });

      } catch (error) {
        return json({
          success: false,
          message: "Server error during login."
        }, 500);
      }
    }

    // =========================
    // CURRENT USER
    // =========================
    if (
      url.pathname === "/api/me" &&
      request.method === "GET"
    ) {
      try {
        const user = await getLoggedInUser(
          request,
          env
        );

        if (!user) {
          return json({
            success: false,
            message: "Not logged in."
          }, 401);
        }

        return json({
          success: true,
          user
        });

      } catch (error) {
        return json({
          success: false,
          message: "Could not load account."
        }, 500);
      }
    }

    // =========================
    // TASK LIST
    // =========================
    if (
      url.pathname === "/api/tasks" &&
      request.method === "GET"
    ) {
      try {
        const user = await getLoggedInUser(
          request,
          env
        );

        if (!user) {
          return json({
            success: false,
            message: "Please login first."
          }, 401);
        }

        const result = await env.DB
          .prepare(`
            SELECT
              tasks.id,
              tasks.title,
              tasks.description,
              tasks.reward,
              tasks.task_type,
              tasks.task_url
            FROM tasks
            WHERE tasks.status = 'active'
            AND NOT EXISTS (
              SELECT 1
              FROM task_completions
              WHERE task_completions.user_id = ?
              AND task_completions.task_id = tasks.id
            )
            ORDER BY
              CASE
                WHEN tasks.task_type = 'telegram' THEN 1
                WHEN tasks.task_type = 'video' THEN 2
                WHEN tasks.task_type = 'tiktok' THEN 3
                ELSE 4
              END,
              tasks.id ASC
            LIMIT 3
          `)
          .bind(user.id)
          .all();

        return json({
          success: true,
          tasks: result.results || []
        });

      } catch (error) {
        return json({
          success: false,
          message: "Could not load tasks."
        }, 500);
      }
    }

    // =========================
    // COMPLETE TASK
    // =========================
    if (
      url.pathname.match(
        /^\/api\/tasks\/\d+\/complete$/
      ) &&
      request.method === "POST"
    ) {
      try {
        const user = await getLoggedInUser(
          request,
          env
        );

        if (!user) {
          return json({
            success: false,
            message: "Please login first."
          }, 401);
        }

        const taskId = Number(
          url.pathname.split("/")[3]
        );

        if (
          !Number.isInteger(taskId) ||
          taskId <= 0
        ) {
          return json({
            success: false,
            message: "Invalid task."
          }, 400);
        }

        const task = await env.DB
          .prepare(`
            SELECT
              id,
              title,
              reward,
              task_type,
              task_url,
              status
            FROM tasks
            WHERE id = ?
            LIMIT 1
          `)
          .bind(taskId)
          .first();

        if (!task) {
          return json({
            success: false,
            message: "Task not found."
          }, 404);
        }

        if (task.status !== "active") {
          return json({
            success: false,
            message: "This task is no longer active."
          }, 400);
        }

        if (
          !Number.isFinite(Number(task.reward)) ||
          Number(task.reward) <= 0
        ) {
          return json({
            success: false,
            message: "Invalid task reward."
          }, 400);
        }

        const alreadyCompleted = await env.DB
          .prepare(`
            SELECT id
            FROM task_completions
            WHERE user_id = ?
            AND task_id = ?
            LIMIT 1
          `)
          .bind(
            user.id,
            task.id
          )
          .first();

        if (alreadyCompleted) {
          return json({
            success: false,
            message: "You have already completed this task."
          }, 409);
        }

        const reward = Number(task.reward);

        await env.DB.batch([
          env.DB
            .prepare(`
              INSERT INTO task_completions
              (user_id, task_id, reward)
              VALUES (?, ?, ?)
            `)
            .bind(
              user.id,
              task.id,
              reward
            ),

          env.DB
            .prepare(`
              UPDATE users
              SET balance = balance + ?
              WHERE id = ?
            `)
            .bind(
              reward,
              user.id
            ),

          env.DB
            .prepare(`
              INSERT INTO transactions
              (user_id, type, amount, description)
              VALUES (?, ?, ?, ?)
            `)
            .bind(
              user.id,
              "task",
              reward,
              `Task Reward: ${task.title}`
            )
        ]);

        const updatedUser = await env.DB
          .prepare(`
            SELECT
              id,
              name,
              email,
              balance,
              referral_code
            FROM users
            WHERE id = ?
            LIMIT 1
          `)
          .bind(user.id)
          .first();

        return json({
          success: true,
          message: "Task completed successfully.",
          reward,
          user: updatedUser
        });

      } catch (