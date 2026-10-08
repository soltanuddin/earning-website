import { hashPassword, verifyPassword } from "./auth.js";

const SESSION_DAYS = 7;
const ADMIN_SESSION_DAYS = 1;
const ADMIN_EMAIL = "soltanuddin45@gmail.com";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const item of header.split(";")) {
    const [key, ...rest] = item.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

function randomToken(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));

  return Array.from(bytes)
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomReferralCode() {
  return randomToken(5).toUpperCase().slice(0, 8);
}

async function getUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT
      sessions.user_id,
      sessions.expires_at,
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
      AND sessions.expires_at > datetime('now')
  `)
    .bind(token)
    .first();
}

async function getAdmin(request, env) {
  const token = getCookie(request, "admin_session");

  if (!token) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT
      admin_sessions.id,
      admin_sessions.admin_id,
      admin_sessions.expires_at,
      admin_users.email
    FROM admin_sessions
    JOIN admin_users
      ON admin_users.id = admin_sessions.admin_id
    WHERE admin_sessions.token = ?
      AND admin_sessions.expires_at > datetime('now')
  `)
    .bind(token)
    .first();
}

async function createUserSession(env, userId) {
  const token = randomToken(32);

  await env.DB.prepare(`
    INSERT INTO sessions
      (token, user_id, expires_at)
    VALUES
      (?, ?, datetime('now', '+7 days'))
  `)
    .bind(token, userId)
    .run();

  return token;
}

async function ensureAdminTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      admin_id INTEGER NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (admin_id)
        REFERENCES admin_users(id)
    )
  `)
    .run();
}

async function createAdminSession(env, adminId) {
  await ensureAdminTable(env);

  const token = randomToken(32);

  await env.DB.prepare(`
    INSERT INTO admin_sessions
      (token, admin_id, expires_at)
    VALUES
      (?, ?, datetime('now', '+1 day'))
  `)
    .bind(token, adminId)
    .run();

  return token;
}

async function ensureAdmin(env) {
  await ensureAdminTable(env);

  const existing = await env.DB.prepare(`
    SELECT id
    FROM admin_users
    WHERE email = ?
  `)
    .bind(ADMIN_EMAIL)
    .first();

  if (existing || !env.ADMIN_PASSWORD) {
    return;
  }

  const result = await hashPassword(
    env.ADMIN_PASSWORD
  );

  await env.DB.prepare(`
    INSERT INTO admin_users
      (email, password_hash, created_at)
    VALUES
      (?, ?, datetime('now'))
  `)
    .bind(
      ADMIN_EMAIL,
      `${result.hash}:${result.salt}`
    )
    .run();
}

function parseStoredPassword(value) {
  const parts = String(value || "").split(":");

  if (parts.length !== 2) {
    return null;
  }

  return {
    hash: parts[0],
    salt: parts[1]
  };
}

async function verifyStoredPassword(password, stored) {
  const parsed = parseStoredPassword(stored);

  if (!parsed) {
    return false;
  }

  return verifyPassword(
    password,
    parsed.hash,
    parsed.salt
  );
}

async function register(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      message: "Invalid request."
    }, 400);
  }

  const name = String(
    body.name || ""
  ).trim();

  const email = String(
    body.email || ""
  ).trim().toLowerCase();

  const password = String(
    body.password || ""
  );

  const referralCode = String(
    body.referralCode ??
    body.referral_code ??
    ""
  ).trim();

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
      SELECT referral_code
      FROM users
      WHERE referral_code = ?
    `)
      .bind(referralCode)
      .first();

    if (!referrer) {
      return json({
        success: false,
        message: "Invalid referral code."
      }, 400);
    }

    referredBy = referrer.referral_code;
  }

  let newReferralCode = null;

  for (let i = 0; i < 10; i++) {
    const candidate = randomReferralCode();

    const exists = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE referral_code = ?
    `)
      .bind(candidate)
      .first();

    if (!exists) {
      newReferralCode = candidate;
      break;
    }
  }

  if (!newReferralCode) {
    return json({
      success: false,
      message: "Could not create referral code."
    }, 500);
  }

  const passwordData = await hashPassword(
    password
  );

  const result = await env.DB.prepare(`
    INSERT INTO users
      (
        name,
        email,
        password_hash,
        balance,
        referral_code,
        referred_by,
        created_at
      )
    VALUES
      (?, ?, ?, 0, ?, ?, datetime('now'))
  `)
    .bind(
      name,
      email,
      `${passwordData.hash}:${passwordData.salt}`,
      newReferralCode,
      referredBy
    )
    .run();

  return json({
    success: true,
    message: "Registration successful.",
    user_id: result.meta.last_row_id
  });
}

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      message: "Invalid request."
    }, 400);
  }

  const email = String(
    body.email || ""
  ).trim().toLowerCase();

  const password = String(
    body.password || ""
  );

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
  `)
    .bind(email)
    .first();

  if (
    !user ||
    !(await verifyStoredPassword(
      password,
      user.password_hash
    ))
  ) {
    return json({
      success: false,
      message: "Invalid email or password."
    }, 401);
  }

  const token = await createUserSession(
    env,
    user.id
  );

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
        "Cache-Control": "no-store",
        "Set-Cookie": cookie(
          "session",
          token,
          SESSION_DAYS * 86400
        )
      }
    }
  );
}

async function logout(request, env) {
  const token = getCookie(
    request,
    "session"
  );

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
        "Set-Cookie": clearCookie("session")
      }
    }
  );
}

async function me(request, env) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Not logged in."
    }, 401);
  }

  const earned = await env.DB.prepare(`
    SELECT COALESCE(
      SUM(
        CASE
          WHEN amount > 0 THEN amount
          ELSE 0
        END
      ),
      0
    ) AS total
    FROM transactions
    WHERE user_id = ?
  `)
    .bind(user.id)
    .first();

  const referrals = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM users
    WHERE referred_by = ?
  `)
    .bind(user.referral_code)
    .first();

  return json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      balance: Number(user.balance || 0),
      total_earned: Number(
        earned?.total || 0
      ),
      referrals: Number(
        referrals?.total || 0
      ),
      referral_code: user.referral_code,
      status: "Active"
    }
  });
}

async function tasks(request, env) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      tasks.*,
      CASE
        WHEN task_completions.id IS NULL
        THEN 0
        ELSE 1
      END AS completed
    FROM tasks
    LEFT JOIN task_completions
      ON task_completions.task_id = tasks.id
      AND task_completions.user_id = ?
    WHERE tasks.status = 'active'
    ORDER BY tasks.id ASC
  `)
    .bind(user.id)
    .all();

  return json({
    success: true,
    tasks: result.results || []
  });
}

async function completeTask(
  request,
  env,
  taskId
) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  const task = await env.DB.prepare(`
    SELECT *
    FROM tasks
    WHERE id = ?
      AND status = 'active'
  `)
    .bind(taskId)
    .first();

  if (!task) {
    return json({
      success: false,
      message: "Task not found."
    }, 404);
  }

  const already = await env.DB.prepare(`
    SELECT id
    FROM task_completions
    WHERE user_id = ?
      AND task_id = ?
  `)
    .bind(
      user.id,
      taskId
    )
    .first();

  if (already) {
    return json({
      success: false,
      message: "You already completed this task."
    }, 400);
  }

  const reward = Number(
    task.reward || 0
  );

  await env.DB.prepare(`
    INSERT INTO task_completions
      (user_id, task_id, reward)
    VALUES
      (?, ?, ?)
  `)
    .bind(
      user.id,
      taskId,
      reward
    )
    .run();

  await env.DB.prepare(`
    UPDATE users
    SET balance = balance + ?
    WHERE id = ?
  `)
    .bind(
      reward,
      user.id
    )
    .run();

  await env.DB.prepare(`
    INSERT INTO transactions
      (user_id, type, amount, description)
    VALUES
      (?, 'task', ?, ?)
  `)
    .bind(
      user.id,
      reward,
      `Task reward: ${task.title}`
    )
    .run();

  return json({
    success: true,
    message: "Task completed.",
    reward
  });
}

async function dailyBonus(
  request,
  env
) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  const today = new Date()
    .toISOString()
    .slice(0, 10);

  const already = await env.DB.prepare(`
    SELECT id
    FROM daily_bonus
    WHERE user_id = ?
      AND claim_date = ?
  `)
    .bind(
      user.id,
      today
    )
    .first();

  if (already) {
    return json({
      success: false,
      message: "Daily bonus already claimed today."
    }, 400);
  }

  const amount = 1;

  await env.DB.prepare(`
    INSERT INTO daily_bonus
      (user_id, bonus_amount, claim_date)
    VALUES
      (?, ?, ?)
  `)
    .bind(
      user.id,
      amount,
      today
    )
    .run();

  await env.DB.prepare(`
    UPDATE users
    SET balance = balance + ?
    WHERE id = ?
  `)
    .bind(
      amount,
      user.id
    )
    .run();

  await env.DB.prepare(`
    INSERT INTO transactions
      (user_id, type, amount, description)
    VALUES
      (?, 'bonus', ?, 'Daily Bonus')
  `)
    .bind(
      user.id,
      amount
    )
    .run();

  return json({
    success: true,
    bonus: amount
  });
}

async function transactions(
  request,
  env
) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT *
    FROM transactions
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 100
  `)
    .bind(user.id)
    .all();

  return json({
    success: true,
    transactions: result.results || []
  });
}

async function withdraw(
  request,
  env
) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      message: "Invalid request."
    }, 400);
  }

  const method = String(
    body.method || ""
  ).trim();

  const account = String(
    body.account || ""
  ).trim();

  const amount = Number(
    body.amount
  );

  if (
    !method ||
    !account ||
    !Number.isFinite(amount)
  ) {
    return json({
      success: false,
      message: "All withdrawal fields are required."
    }, 400);
  }

  if (amount < 1) {
    return json({
      success: false,
      message: "Minimum withdrawal is $1."
    }, 400);
  }

  const result = await env.DB.prepare(`
    UPDATE users
    SET balance = balance - ?
    WHERE id = ?
      AND balance >= ?
  `)
    .bind(
      amount,
      user.id,
      amount
    )
    .run();

  if (
    !result.meta ||
    result.meta.changes !== 1
  ) {
    return json({
      success: false,
      message: "Insufficient balance."
    }, 400);
  }

  await env.DB.prepare(`
    INSERT INTO withdrawals
      (user_id, method, account, amount, status)
    VALUES
      (?, ?, ?, ?, 'pending')
  `)
    .bind(
      user.id,
      method,
      account,
      amount
    )
    .run();

  await env.DB.prepare(`
    INSERT INTO transactions
      (user_id, type, amount, description)
    VALUES
      (?, 'withdrawal', ?, ?)
  `)
    .bind(
      user.id,
      -amount,
      `Withdrawal request - ${method}`
    )
    .run();

  return json({
    success: true,
    message: "Withdrawal request submitted."
  });
}

async function withdrawals(
  request,
  env
) {
  const user = await getUser(
    request,
    env
  );

  if (!user) {
    return json({
      success: false,
      message: "Please login."
    }, 401);
  }

  const result = await env.DB.prepare(`
  SELECT *
  FROM withdrawals
  WHERE user_id = ?
  ORDER BY id DESC
  LIMIT 100
`)
  .bind(user.id)
  .all();

return json({
  success: true,
  withdrawals: result.results || []
});
}

async function adminLogin(request, env) {
  await ensureAdmin(env);

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      message: "Invalid request."
    }, 400);
  }

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

  const admin = await env.DB.prepare(`
    SELECT *
    FROM admin_users
    WHERE email = ?
  `)
    .bind(email)
    .first();

  if (
    !admin ||
    !(await verifyStoredPassword(
      password,
      admin.password_hash
    ))
  ) {
    return json({
      success: false,
      message: "Invalid admin login."
    }, 401);
  }

  const token = await createAdminSession(
    env,
    admin.id
  );

  return new Response(
    JSON.stringify({
      success: true,
      message: "Admin login successful.",
      admin: {
        email: admin.email
      }
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie": cookie(
          "admin_session",
          token,
          ADMIN_SESSION_DAYS * 86400
        )
      }
    }
  );
}

async function adminLogout(request, env) {
  const token = getCookie(
    request,
    "admin_session"
  );

  if (token) {
    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }

  return new Response(
    JSON.stringify({
      success: true,
      message: "Admin logged out."
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": clearCookie("admin_session")
      }
    }
  );
}

async function adminMe(request, env) {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return json({
      success: false,
      message: "Admin not logged in."
    }, 401);
  }

  return json({
    success: true,
    admin: {
      email: admin.email
    }
  });
}