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

function generateToken() {
  return crypto.randomUUID() + "-" + crypto.randomUUID();
}

function generateReferralCode() {
  return "EX" + Math.random().toString(36).substring(2, 9).toUpperCase();
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const parts = cookie.split(";");

  for (const part of parts) {
    const [key, ...value] = part.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

function sessionCookie(token) {
  return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}

function clearSessionCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

function adminSessionCookie(token) {
  return `admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}

function clearAdminSessionCookie() {
  return "admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}


/* =========================
   USER SESSION
========================= */

async function getCurrentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  const result = await env.DB.prepare(`
    SELECT users.*
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ?
      AND sessions.expires_at > datetime('now')
    LIMIT 1
  `)
    .bind(token)
    .first();

  return result || null;
}


/* =========================
   ADMIN TABLE
========================= */

async function ensureAdminTables(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      admin_id INTEGER NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (admin_id) REFERENCES admin_users(id)
    )
  `).run();
}


/* =========================
   ADMIN SETUP
========================= */

async function ensureAdminAccount(env) {
  if (!env.ADMIN_PASSWORD) {
    throw new Error("ADMIN_PASSWORD secret is not configured.");
  }

  const email = "soltanuddin45@gmail.com";

  const existing = await env.DB.prepare(`
    SELECT id
    FROM admin_users
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (existing) {
    return existing;
  }

  const passwordData = await hashPassword(env.ADMIN_PASSWORD);

  const result = await env.DB.prepare(`
    INSERT INTO admin_users (
      email,
      password_hash
    )
    VALUES (?, ?)
  `)
    .bind(
      email,
      `${passwordData.salt}:${passwordData.hash}`
    )
    .run();

  return {
    id: result.meta?.last_row_id,
    email
  };
}


/* =========================
   ADMIN SESSION
========================= */

async function getCurrentAdmin(request, env) {
  const token = getCookie(request, "admin_session");

  if (!token) {
    return null;
  }

  await ensureAdminTables(env);

  const admin = await env.DB.prepare(`
    SELECT
      admin_users.id,
      admin_users.email
    FROM admin_sessions
    JOIN admin_users
      ON admin_users.id = admin_sessions.admin_id
    WHERE admin_sessions.token = ?
      AND admin_sessions.expires_at > datetime('now')
    LIMIT 1
  `)
    .bind(token)
    .first();

  return admin || null;
}

async function requireAdmin(request, env) {
  const admin = await getCurrentAdmin(request, env);

  if (!admin) {
    return null;
  }

  return admin;
}


/* =========================
   REGISTER
========================= */

async function register(request, env) {
  try {
    const body = await request.json();

    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "").trim();
    const referralCode = String(body.referralCode || "").trim();

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

    const existing = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE email = ?
    `)
      .bind(email)
      .first();

    if (existing) {
      return json({
        success: false,
        message: "Email already registered."
      }, 409);
    }

    let referredBy = null;

    if (referralCode) {
      const referrer = await env.DB.prepare(`
        SELECT id, referral_code
        FROM users
        WHERE referral_code = ?
      `)
        .bind(referralCode)
        .first();

      if (referrer) {
        referredBy = referrer.referral_code;
      }
    }

    const passwordData = await hashPassword(password);

    let newReferralCode = generateReferralCode();

    let codeExists = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE referral_code = ?
    `)
      .bind(newReferralCode)
      .first();

    while (codeExists) {
      newReferralCode = generateReferralCode();

      codeExists = await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE referral_code = ?
      `)
        .bind(newReferralCode)
        .first();
    }

    await env.DB.prepare(`
      INSERT INTO users (
        name,
        email,
        password_hash,
        balance,
        referral_code,
        referred_by
      )
      VALUES (?, ?, ?, 0, ?, ?)
    `)
      .bind(
        name,
        email,
        `${passwordData.salt}:${passwordData.hash}`,
        newReferralCode,
        referredBy
      )
      .run();

    return json({
      success: true,
      message: "Registration successful."
    });

  } catch (error) {
    return json({
      success: false,
      message: "Registration failed.",
      error: error.message
    }, 500);
  }
}


/* =========================
   USER LOGIN
========================= */

async function login(request, env) {
  try {
    const body = await request.json();

    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!email || !password) {
      return json({
        success: false,
        message: "Email and password are required."
      }, 400);
    }

    const user = await env.DB.prepare(`
      SELECT *
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

    const stored = String(user.password_hash || "");
    const [salt, storedHash] = stored.split(":");

    if (!salt || !storedHash) {
      return json({
        success: false,
        message: "Invalid account password data."
      }, 500);
    }

    const valid = await verifyPassword(
      password,
      storedHash,
      salt
    );

    if (!valid) {
      return json({
        success: false,
        message: "Invalid email or password."
      }, 401);
    }

    const token = generateToken();

    await env.DB.prepare(`
      INSERT INTO sessions (
        token,
        user_id,
        expires_at
      )
      VALUES (
        ?,
        ?,
        datetime('now', '+7 days')
      )
    `)
      .bind(token, user.id)
      .run();

    return json({
      success: true,
      message: "Login successful.",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    }, 200, {
      "Set-Cookie": sessionCookie(token)
    });

  } catch (error) {
    return json({
      success: false,
      message: "Login failed.",
      error: error.message
    }, 500);
  }
}


/* =========================
   ADMIN LOGIN
========================= */

async function adminLogin(request, env) {
  try {
    const body = await request.json();

    const email = String(body.email || "")
      .trim()
      .toLowerCase();

    const password = String(body.password || "");

    if (!email || !password) {
      return json({
        success: false,
        message: "Admin email and password are required."
      }, 400);
    }

    if (email !== "soltanuddin45@gmail.com") {
      return json({
        success: false,
        message: "Invalid admin credentials."
      }, 401);
    }

    await ensureAdminTables(env);

    const admin = await ensureAdminAccount(env);

    const storedAdmin = await env.DB.prepare(`
      SELECT *
      FROM admin_users
      WHERE email = ?
      LIMIT 1
    `)
      .bind(email)
      .first();

    if (!storedAdmin) {
      return json({
        success: false,
        message: "Admin account not found."
      }, 401);
    }

    const stored = String(storedAdmin.password_hash || "");
    const [salt, storedHash] = stored.split(":");

    if (!salt || !storedHash) {
      return json({
        success: false,
        message: "Invalid admin password data."
      }, 500);
    }

    const valid = await verifyPassword(
      password,
      storedHash,
      salt
    );

    if (!valid) {
      return json({
        success: false,
        message: "Invalid admin credentials."
      }, 401);
    }

    const token = generateToken();

    await env.DB.prepare(`
      INSERT INTO admin_sessions (
        token,
        admin_id,
        expires_at
      )
      VALUES (
        ?,
        ?,
        datetime('now', '+1 day')
      )
    `)
      .bind(token, storedAdmin.id)
      .run();

    return json({
      success: true,
      message: "Admin login successful.",
      admin: {
        id: storedAdmin.id,
        email: storedAdmin.email
      }
    }, 200, {
      "Set-Cookie": adminSessionCookie(token)
    });

  } catch (error) {
    return json({
      success: false,
      message: "Admin login failed.",
      error: error.message
    }, 500);
  }
}


/* =========================
   ADMIN ME
========================= */

async function adminMe(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      loggedIn: false
    }, 401);
  }

  return json({
    success: true,
    loggedIn: true,
    admin
  });
}


/* =========================
   ADMIN LOGOUT
========================= */

async function adminLogout(request, env) {
  const token = getCookie(request, "admin_session");

  if (token) {
    await ensureAdminTables(env);

    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }

  return json({
    success: true,
    message: "Admin logged out."
  }, 200, {
    "Set-Cookie": clearAdminSessionCookie()
  });
}


/* =========================
   ME / DASHBOARD
========================= */

async function me(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      loggedIn: false
    }, 401);
  }

  const referralResult = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM users
    WHERE referred_by = ?
  `)
    .bind(user.referral_code)
    .first();

  const earnedResult = await env.DB.prepare(`
    SELECT COALESCE(SUM(amount), 0) AS total
    FROM transactions
    WHERE user_id = ?
      AND amount > 0
  `)
    .bind(user.id)
    .first();

  return json({
    success: true,
    loggedIn: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      balance: Number(user.balance || 0),
      referral_code: user.referral_code,
      referrals: Number(referralResult?.count || 0),
      total_earned: Number(earnedResult?.total || 0),
      status: "Active"
    }
  });
}


/* =========================
   TASKS
========================= */

async function tasks(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      tasks.id,
      tasks.title,
      tasks.description,
      tasks.reward,
      tasks.task_type,
      tasks.task_url
    FROM tasks
    WHERE tasks.status = 'active'
      AND tasks.id NOT IN (
        SELECT task_id
        FROM task_completions
        WHERE user_id = ?
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
}


/* =========================
   COMPLETE TASK
========================= */

async function completeTask(request, env, taskId) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  const task = await env.DB.prepare(`
    SELECT *
    FROM tasks
    WHERE id = ?
      AND status = 'active'
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

  const alreadyCompleted = await env.DB.prepare(`
    SELECT id
    FROM task_completions
    WHERE user_id = ?
      AND task_id = ?
    LIMIT 1
  `)
    .bind(user.id, taskId)
    .first();

  if (alreadyCompleted) {
    return json({
      success: false,
      message: "Task already completed."
    }, 400);
  }

  const reward = Number(task.reward || 0);

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO task_completions (
        user_id,
        task_id,
        reward
      )
      VALUES (?, ?, ?)
    `).bind(user.id, taskId, reward),

    env.DB.prepare(`
      UPDATE users
      SET balance = balance + ?
      WHERE id = ?
    `).bind(reward, user.id),

    env.DB.prepare(`
      INSERT INTO transactions (
        user_id,
        type,
        amount,
        description
      )
      VALUES (?, 'task', ?, ?)
    `).bind(
      user.id,
      reward,
      task.title
    )
  ]);

  return json({
    success: true,
    message: "Task completed successfully.",
    reward
  });
}


/* =========================
   DAILY BONUS
========================= */

async function dailyBonus(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  const today = new Date()
    .toISOString()
    .slice(0, 10);

  const existing = await env.DB.prepare(`
    SELECT id
    FROM daily_bonus
    WHERE user_id = ?
      AND claim_date = ?
    LIMIT 1
  `)
    .bind(user.id, today)
    .first();

  if (existing) {
    return json({
      success: false,
      message: "Daily bonus already claimed today."
    }, 400);
  }

  const bonus = 1;

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO daily_bonus (
        user_id,
        bonus_amount,
        claim_date
      )
      VALUES (?, ?, ?)
    `).bind(user.id, bonus, today),

    env.DB.prepare(`
      UPDATE users
      SET balance = balance + ?
      WHERE id = ?
    `).bind(bonus, user.id),

    env.DB.prepare(`
      INSERT INTO transactions (
        user_id,
        type,
        amount,
        description
      )
      VALUES (?, 'daily_bonus', ?, 'Daily Bonus')
    `).bind(user.id, bonus)
  ]);

  return json({
    success: true,
    message: "Daily bonus claimed.",
    bonus
  });
}


/* =========================
   TRANSACTIONS
========================= */

async function transactions(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      type,
      amount,
      description,
      created_at
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `)
    .bind(user.id)
    .all();

  return json({
    success: true,
    transactions: result.results || []
  });
}


/* =========================
   WITHDRAW
========================= */

async function withdraw(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  try {
    const body = await request.json();

    const method = String(body.method || "")
      .trim()
      .toLowerCase();

    const account = String(body.account || "")
      .trim();

    const amount = Number(body.amount);

    if (!method || !account || !Number.isFinite(amount)) {
      return json({
        success: false,
        message: "Method, account and amount are required."
      }, 400);
    }

    if (!["bkash", "nagad", "usdt"].includes(method)) {
      return json({
        success: false,
        message: "Invalid withdrawal method."
      }, 400);
    }

    if (amount <= 0) {
      return json({
        success: false,
        message: "Invalid withdrawal amount."
      }, 400);
    }

    if (amount < 1) {
      return json({
        success: false,
        message: "Minimum withdrawal is $1."
      }, 400);
    }

    const updateResult = await env.DB.prepare(`
      UPDATE users
      SET balance = balance - ?
      WHERE id = ?
        AND balance >= ?
    `)
      .bind(amount, user.id, amount)
      .run();

    if (!updateResult.meta || updateResult.meta.changes !== 1) {
      return json({
        success: false,
        message: "Insufficient balance or balance changed. Please try again."
      }, 400);
    }

    try {
      await env.DB.batch([
        env.DB.prepare(`
          INSERT INTO withdrawals (
            user_id,
            method,
            account,
            amount,
            status
          )
          VALUES (?, ?, ?, ?, 'pending')
        `).bind(
          user.id,
          method,
          account,
          amount
        ),

        env.DB.prepare(`
          INSERT INTO transactions (
            user_id,
            type,
            amount,
            description
          )
          VALUES (?, 'withdrawal', ?, ?)
        `).bind(
          user.id,
          -amount,
          `Withdrawal request - ${method}`
        )
      ]);

    } catch (insertError) {

      await env.DB.prepare(`
        UPDATE users
        SET balance = balance + ?
        WHERE id = ?
      `)
        .bind(amount, user.id)
        .run();

      throw insertError;
    }

    return json({
      success: true,
      message: "Withdrawal request submitted successfully.",
      amount,
      method,
      status: "pending"
    });

  } catch (error) {
    return json({
      success: false,
      message: "Withdrawal request failed.",
      error: error.message
    }, 500);
  }
}


/* =========================
   WITHDRAWAL HISTORY
========================= */

async function getWithdrawals(request, env) {
  const user = await getCurrentUser(request, env);

  if (!user) {
    return json({
      success: false,
      message: "Please login first."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      method,
      account,
      amount,
      status,
      admin_note,
      created_at,
      processed_at
    FROM withdrawals
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `)
    .bind(user.id)
    .all();

  return json({
    success: true,
    withdrawals: result.results || []
  });
}


/* =========================
   ADMIN DASHBOARD
========================= */

async function adminStats(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin authentication required."
    }, 401);
  }

  const users = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM users
  `).first();

  const balances = await env.DB.prepare(`
    SELECT COALESCE(SUM(balance), 0) AS total
    FROM users
  `).first();

  const pending = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM withdrawals
    WHERE status = 'pending'
  `).first();

  const approved = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM withdrawals
    WHERE status = 'approved'
  `).first();

  const rejected = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM withdrawals
    WHERE status = 'rejected'
  `).first();

  return json({
    success: true,
    stats: {
      users: Number(users?.count || 0),
      total_balance: Number(balances?.total || 0),
      pending_withdrawals: Number(pending?.count || 0),
      approved_withdrawals: Number(approved?.count || 0),
      rejected_withdrawals: Number(rejected?.count || 0)
    }
  });
}


/* =========================
   ADMIN USERS
========================= */

async function adminUsers(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin authentication required."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      email,
      balance,
      referral_code,
      referred_by,
      created_at
    FROM users
    ORDER BY id DESC
    LIMIT 500
  `).all();

  return json({
    success: true,
    users: result.results || []
  });
}


/* =========================
   ADMIN WITHDRAWALS
========================= */

async function adminWithdrawals(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin authentication required."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      withdrawals.id,
      withdrawals.user_id,
      users.name,
      users.email,
      withdrawals.method,
      withdrawals.account,
      withdrawals.amount,
      withdrawals.status,
      withdrawals.admin_note,
      withdrawals.created_at,
      withdrawals.processed_at
    FROM withdrawals
    JOIN users
      ON users.id = withdrawals.user_id
    ORDER BY withdrawals.id DESC
    LIMIT 500
  `).all();

  return json({
    success: true,
    withdrawals: result.results || []
  });
}


/* =========================
   ADMIN APPROVE WITHDRAWAL
========================= */

async function approveWithdrawal(request, env, withdrawalId) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin authentication required."
    }, 401);
  }

  const id = Number(withdrawalId);

  if (!Number.isInteger(id)) {
    return json({
      success: false,
      message: "Invalid withdrawal ID."
    }, 400);
  }

  const body = await request.json().catch(() => ({}));

  const note = String(body.note || "").trim();

  const withdrawal = await env.DB.prepare(`
    SELECT *
    FROM withdrawals
    WHERE id = ?
    LIMIT 1
  `)
    .bind(id)
    .first();

  if (!withdrawal) {
    return json({
      success: false,
      message: "Withdrawal not found."
    }, 404);
  }

  if (withdrawal.status !== "pending") {
    return json({
      success: false,
      message: "This withdrawal has already been processed."
    }, 400);
  }

  await env.DB.prepare(`
    UPDATE withdrawals
    SET
      status = 'approved',
      admin_note = ?,
      processed_at = CURRENT_TIMESTAMP
    WHERE id = ?
      AND status = 'pending'
  `)
    .bind(note || "Approved by admin.", id)
    .run();

  return json({
    success: true,
    message: "Withdrawal approved.",
    withdrawal_id: id
  });
}


/* =========================
   ADMIN REJECT WITHDRAWAL
========================= */

async function rejectWithdrawal(request, env, withdrawalId) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin authentication required."
    }, 401);
  }

  const id = Number(withdrawalId);

  if (!Number.isInteger(id)) {
    return json({
      success: false,
      message: "Invalid withdrawal ID."
    }, 400);
  }

  const body = await request.json().catch(() => ({}));

  const note = String(body.note || "").trim();

  const withdrawal = await env.DB.prepare(`
    SELECT *
    FROM withdrawals
    WHERE id = ?
    LIMIT 1
  `)
    .bind(id)
    .first();

  if (!withdrawal) {
    return json({
      success: false,
      message: "Withdrawal not found."
    }, 404);
  }

  if (withdrawal.status !== "pending") {
    return json({
      success: false,
      message: "This withdrawal has already been processed."
    }, 400);
  }

  const amount = Number(withdrawal.amount || 0);
  const userId = Number(withdrawal.user_id);

  try {
    await env.DB.batch([
      env.DB.prepare(`
        UPDATE withdrawals
        SET
          status = 'rejected',
          admin_note = ?,
          processed_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND status = 'pending'
      `).bind(
        note || "Rejected by admin.",
        id
      ),

      env.DB.prepare(`
        UPDATE users
        SET balance = balance + ?
        WHERE id = ?
      `).bind(
        amount,
        userId
      ),

      env.DB.prepare(`
        INSERT INTO transactions (
          user_id,
          type,
          amount,
          description
        )
        VALUES (?, 'withdrawal_refund', ?, ?)
      `).bind(
        userId,
        amount,
        `Withdrawal refund #${id}`
      )
    ]);

  } catch (error) {
    return json({
      success: false,
      message: "Withdrawal rejection failed.",
      error: error.message
    }, 500);
  }

  return json({
    success: true,
    message: "Withdrawal rejected and balance refunded.",
    withdrawal_id: id,
    refunded: amount
  });
}


/* =========================
   LOGOUT
========================= */

async function logout(request, env) {
  const token = getCookie(request, "session");

  if (token) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }

  return json({
    success: true,
    message: "Logged out."
  }, 200, {
    "Set-Cookie": clearSessionCookie()
  });
}


/* =========================
   TEST DB
========================= */

async function testDb(env) {
  const result = await env.DB.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    ORDER BY name
  `).all();

  return json({
    success: true,
    tables: result.results || []
  });
}


/* =========================
   MAIN WORKER
========================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {

      /* USER */

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
        return await tasks(request, env);
      }

      if (
        path.startsWith("/api/tasks/") &&
        path.endsWith("/complete") &&
        method === "POST"
      ) {
        const parts = path.split("/");
        const taskId = Number(parts[3]);

        if (!Number.isInteger(taskId)) {
          return json({
            success: false,
            message: "Invalid task ID."
          }, 400);
        }

        return await completeTask(request, env, taskId);
      }

      if (path === "/api/daily-bonus" && method === "POST") {
        return await dailyBonus(request, env);
      }

      if (path === "/api/transactions" && method === "GET") {
        return await transactions(request, env);
      }

      if (path === "/api/withdraw" && method === "POST") {
        return await withdraw(request, env);
      }

      if (path === "/api/withdrawals" && method === "GET") {
        return await getWithdrawals(request, env);
      }

      if (path === "/api/logout" && method === "POST") {
        return await logout(request, env);
      }


      /* ADMIN */

      if (path === "/api/admin/login" && method === "POST") {
        return await adminLogin(request, env);
      }

      if (path === "/api/admin/me" && method === "GET") {
        return await adminMe(request, env);
      }

      if (path === "/api/admin/logout" && method === "POST") {
        return await adminLogout(request, env);
      }

      if (path === "/api/admin/stats" && method === "GET") {
        return await adminStats(request, env);
      }

      if (path === "/api/admin/users" && method === "GET") {
        return await adminUsers(request, env);
      }

      if (path === "/api/admin/withdrawals" && method === "GET") {
        return await adminWithdrawals(request, env);
      }

      if (
        path.startsWith("/api/admin/withdrawals/") &&
        path.endsWith("/approve") &&
        method === "POST"
      ) {
        const parts = path.split("/");
        const withdrawalId = Number(parts[4]);

        return await approveWithdrawal(
          request,
          env,
          withdrawalId
        );
      }

      if (
        path.startsWith("/api/admin/withdrawals/") &&
        path.endsWith("/reject") &&
        method === "POST"
      ) {
        const parts = path.split("/");
        const withdrawalId = Number(parts[4]);

        return await rejectWithdrawal(
          request,
          env,
          withdrawalId
        );
      }


      /* TEST */

      if (path === "/api/test-db" && method === "GET") {
        return await testDb(env);
      }

      return env.ASSETS.fetch(request);

    } catch (error) {

      return json({
        success: false,
        message: "Server error.",
        error: error.message
      }, 500);
    }
  }
};