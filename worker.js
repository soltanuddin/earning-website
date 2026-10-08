import { hashPassword, verifyPassword } from "./auth.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
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
      SELECT id FROM users WHERE email = ?
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
      SELECT id FROM users WHERE referral_code = ?
    `)
      .bind(newReferralCode)
      .first();

    while (codeExists) {
      newReferralCode = generateReferralCode();

      codeExists = await env.DB.prepare(`
        SELECT id FROM users WHERE referral_code = ?
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
   LOGIN
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

    return new Response(
      JSON.stringify({
        success: true,
        message: "Login successful.",
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": sessionCookie(token)
        }
      }
    );

  } catch (error) {
    return json({
      success: false,
      message: "Login failed.",
      error: error.message
    }, 500);
  }
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

    const freshUser = await env.DB.prepare(`
      SELECT id, balance
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(user.id)
      .first();

    const balance = Number(freshUser?.balance || 0);

    if (balance < amount) {
      return json({
        success: false,
        message: "Insufficient balance."
      }, 400);
    }

    /*
      First reserve/deduct the balance only if enough
      balance is available.
    */

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
        message: "Balance changed. Please try again."
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

      /*
        If creating the withdrawal failed,
        return the reserved balance.
      */

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

  return new Response(
    JSON.stringify({
      success: true,
      message: "Logged out."
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": clearSessionCookie()
      }
    }
  );
}


/* =========================
   TEST DB
========================= */

async function testDb(env) {
  const result = await env.DB.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE