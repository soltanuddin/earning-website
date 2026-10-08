import { hashPassword, verifyPassword } from "./auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function makeToken(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function makeReferralCode() {
  return "EX" + makeToken(4).toUpperCase();
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const parts = cookie.split(";");

  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function sessionCookie(token) {
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}

function clearSessionCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  const result = await env.DB.prepare(
    `SELECT
      users.id,
      users.name,
      users.email,
      users.balance,
      users.referral_code,
      users.referred_by,
      users.created_at
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = ?
       AND sessions.expires_at > datetime('now')`
  )
    .bind(token)
    .first();

  return result || null;
}

async function createSession(userId, env) {
  const token = makeToken(32);

  await env.DB.prepare(
    `INSERT INTO sessions
      (token, user_id, expires_at)
     VALUES
      (?, ?, datetime('now', '+7 days'))`
  )
    .bind(token, userId)
    .run();

  return token;
}

async function register(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({ success: false, message: "Invalid request." }, 400);
  }

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

  const existing = await env.DB.prepare(
    `SELECT id FROM users WHERE email = ?`
  )
    .bind(email)
    .first();

  if (existing) {
    return json(
      {
        success: false,
        message: "This email is already registered."
      },
      409
    );
  }

  const passwordData = await hashPassword(password);
  const referralCode = makeReferralCode();

  const result = await env.DB.prepare(
    `INSERT INTO users
      (name, email, password_hash, balance, referral_code, referred_by)
     VALUES
      (?, ?, ?, 0, ?, ?)`
  )
    .bind(
      name,
      email,
      `${passwordData.salt}:${passwordData.hash}`,
      referralCode,
      body.referred_by ? String(body.referred_by).trim() : null
    )
    .run();

  const userId = result.meta.last_row_id;

  const token = await createSession(userId, env);

  const response = json({
    success: true,
    message: "Registration successful.",
    user: {
      id: userId,
      name,
      email,
      balance: 0,
      referral_code: referralCode
    }
  });

  response.headers.set("Set-Cookie", sessionCookie(token));

  return response;
}

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({ success: false, message: "Invalid request." }, 400);
  }

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!email || !password) {
    return json(
      {
        success: false,
        message: "Email and password are required."
      },
      400
    );
  }

  const user = await env.DB.prepare(
    `SELECT
      id,
      name,
      email,
      password_hash,
      balance,
      referral_code,
      referred_by
     FROM users
     WHERE email = ?`
  )
    .bind(email)
    .first();

  if (!user) {
    return json(
      {
        success: false,
        message: "Invalid email or password."
      },
      401
    );
  }

  const stored = String(user.password_hash || "");
  const separator = stored.indexOf(":");

  if (separator === -1) {
    return json(
      {
        success: false,
        message: "Account password data is invalid."
      },
      500
    );
  }

  const salt = stored.slice(0, separator);
  const hash = stored.slice(separator + 1);

  const valid = await verifyPassword(password, hash, salt);

  if (!valid) {
    return json(
      {
        success: false,
        message: "Invalid email or password."
      },
      401
    );
  }

  const token = await createSession(user.id, env);

  const response = json({
    success: true,
    message: "Login successful.",
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      balance: Number(user.balance || 0),
      referral_code: user.referral_code,
      referred_by: user.referred_by
    }
  });

  response.headers.set("Set-Cookie", sessionCookie(token));

  return response;
}

async function me(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json(
      {
        success: false,
        logged_in: false
      },
      401
    );
  }

  const referralCount = await env.DB.prepare(
    `SELECT COUNT(*) AS count
     FROM users
     WHERE referred_by = ?`
  )
    .bind(user.referral_code)
    .first();

  const earned = await env.DB.prepare(
    `SELECT COALESCE(SUM(amount), 0) AS total
     FROM transactions
     WHERE user_id = ?
       AND amount > 0`
  )
    .bind(user.id)
    .first();

  return json({
    success: true,
    logged_in: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      balance: Number(user.balance || 0),
      referral_code: user.referral_code,
      referred_by: user.referred_by,
      total_earned: Number(earned?.total || 0),
      referrals: Number(referralCount?.count || 0),
      created_at: user.created_at
    }
  });
}

async function getTasks(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json(
      {
        success: false,
        message: "Please login first."
      },
      401
    );
  }

  const result = await env.DB.prepare(
    `SELECT
      tasks.id,
      tasks.title,
      tasks.description,
      tasks.reward,
      tasks.task_type,
      tasks.task_url
     FROM tasks
     LEFT JOIN task_completions
       ON task_completions.task_id = tasks.id
      AND task_completions.user_id = ?
     WHERE tasks.status = 'active'
       AND task_completions.id IS NULL
     ORDER BY
       CASE
         WHEN tasks.task_type = 'telegram' THEN 1
         WHEN tasks.task_type = 'video' THEN 2
         WHEN tasks.task_type = 'tiktok' THEN 3
         ELSE 4
       END,
       tasks.id ASC
     LIMIT 3`
  )
    .bind(user.id)
    .all();

  return json({
    success: true,
    tasks: result.results || []
  });
}

async function completeTask(request, env, taskId) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json(
      {
        success: false,
        message: "Please login first."
      },
      401
    );
  }

  const id = Number(taskId);

  if (!Number.isInteger(id) || id <= 0) {
    return json(
      {
        success: false,
        message: "Invalid task ID."
      },
      400
    );
  }

  const task = await env.DB.prepare(
    `SELECT
      id,
      title,
      reward,
      status,
      task_type,
      task_url
     FROM tasks
     WHERE id = ?`
  )
    .bind(id)
    .first();

  if (!task) {
    return json(
      {
        success: false,
        message: "Task not found."
      },
      404
    );
  }

  if (task.status !== "active") {
    return json(
      {
        success: false,
        message: "This task is not active."
      },
      400
    );
  }

  const alreadyCompleted = await env.DB.prepare(
    `SELECT id
     FROM task_completions
     WHERE user_id = ?
       AND task_id = ?`
  )
    .bind(user.id, id)
    .first();

  if (alreadyCompleted) {
    return json(
      {
        success: false,
        message: "You already completed this task."
      },
      409
    );
  }

  const reward = Number(task.reward || 0);

  if (reward <= 0) {
    return json(
      {
        success: false,
        message: "Invalid task reward."
      },
      400
    );
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO task_completions
          (user_id, task_id, reward)
         VALUES
          (?, ?, ?)`
      ).bind(user.id, id, reward),

      env.DB.prepare(
        `UPDATE users
         SET balance = balance + ?
         WHERE id = ?`
      ).bind(reward, user.id),

      env.DB.prepare(
        `INSERT INTO transactions
          (user_id, type, amount, description)
         VALUES
          (?, 'task', ?, ?)`
      ).bind(
        user.id,
        reward,
        `Completed task: ${task.title}`
      )
    ]);
  } catch (error) {
    const message = String(error?.message || "");

    if (
      message.toLowerCase().includes("unique") ||
      message.toLowerCase().includes("constraint")
    ) {
      return json(
        {
          success: false,
          message: "You already completed this task."
        },
        409
      );
    }

    throw error;
  }

  const updatedUser = await env.DB.prepare(
    `SELECT balance
     FROM users
     WHERE id = ?`
  )
    .bind(user.id)
    .first();

  return json({
    success: true,
    message: `Task completed. You earned $${reward.toFixed(2)}.`,
    reward,
    balance: Number(updatedUser?.balance || 0)
  });
}

async function dailyBonus(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json(
      {
        success: false,
        message: "Please login first."
      },
      401
    );
  }

  const today = new Date().toISOString().slice(0, 10);
  const bonusAmount = 1;

  const claimed = await env.DB.prepare(
    `SELECT id
     FROM daily_bonus
     WHERE user_id = ?
       AND claim_date = ?`
  )
    .bind(user.id, today)
    .first();

  if (claimed) {
    return json(
      {
        success: false,
        message: "Today's bonus has already been claimed."
      },
      409
    );
  }

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO daily_bonus
          (user_id, bonus_amount, claim_date)
         VALUES
          (?, ?, ?)`
      ).bind(user.id, bonusAmount, today),

      env.DB.prepare(
        `UPDATE users
         SET balance = balance + ?
         WHERE id = ?`
      ).bind(bonusAmount, user.id),

      env.DB.prepare(
        `INSERT INTO transactions
          (user_id, type, amount, description)
         VALUES
          (?, 'daily_bonus', ?, ?)`
      ).bind(
        user.id,
        bonusAmount,
        "Daily bonus"
      )
    ]);
  } catch (error) {
    const message = String(error?.message || "");

    if (
      message.toLowerCase().includes("unique") ||
      message.toLowerCase().includes("constraint")
    ) {
      return json(
        {
          success: false,
          message: "Today's bonus has already been claimed."
        },
        409
      );
    }

    throw error;
  }

  const updatedUser = await env.DB.prepare(
    `SELECT balance
     FROM users
     WHERE id = ?`
  )
    .bind(user.id)
    .first();

  return json({
    success: true,
    message: "Daily bonus claimed successfully.",
    bonus: bonusAmount,
    balance: Number(updatedUser?.balance || 0)
  });
}

async function transactions(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json(
      {
        success: false,
        message: "Please login first."
      },
      401
    );
  }

  const result = await env.DB.prepare(
    `SELECT
      id,
      type,
      amount,
      description,
      created_at
     FROM transactions
     WHERE user_id = ?
     ORDER BY id DESC
     LIMIT 100`
  )
    .bind(user.id)
    .all();

  return json({
    success: true,
    transactions: result.results || []
  });
}

async function logout(request, env) {
  const token = getCookie(request, "session");

  if (token) {
    await env.DB.prepare(
      `DELETE FROM sessions WHERE token = ?`
    )
      .bind(token)
      .run();
  }

  const response = json({
    success: true,
    message: "Logged out successfully."
  });

  response.headers.set("Set-Cookie", clearSessionCookie());

  return response;
}

async function testDatabase(env) {
  try {
    const result = await env.DB.prepare(
      `SELECT
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM tasks) AS tasks,
        (SELECT COUNT(*) FROM task_completions) AS completions,
        (SELECT COUNT(*) FROM transactions) AS transactions`
    ).first();

    return json({
      success: true,
      database: "connected",
      counts: {
        users: Number(result?.users || 0),
        tasks: Number(result?.tasks || 0),
        completions: Number(result?.completions || 0),
        transactions: Number(result?.transactions || 0)
      }
    });
  } catch (error) {
    return json(
      {
        success: false,
        database: "error",
        message: String(error?.message || error)
      },
      500
    );
  }
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (path === "/api/register" && method === "POST") {
        return await register(request, env);
      }

      if (path === "/api/login" && method === "POST") {
        return await login(request, env);
      }

      if (path === "/api/me" && method === "GET") {
        return await me(request, env);
      }

      if (path === "/api/tasks" && method === "GET") {
        return await getTasks(request, env);
      }

      if (
        path.startsWith("/api/tasks/") &&
        path.endsWith("/complete") &&
        method === "POST"
      ) {
        const parts = path.split("/");
        const taskId = parts[3];

        return await completeTask(request, env, taskId);
      }

      if (path === "/api/daily-bonus" && method === "POST") {
        return await dailyBonus(request, env);
      }

      if (path === "/api/transactions" && method === "GET") {
        return await transactions(request, env);
      }

      if (path === "/api/logout" && method === "POST") {
        return await logout(request, env);
      }

      if (path === "/api/test-db" && method === "GET") {
        return await testDatabase(env);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      return json(
        {
          success: false,
          message: "Server error.",
          error: String(error?.message || error)
        },
        500
      );
    }
  }
}; 