export function getBalance(user) {
  return {
    userId: user.id,
    balance: Number(user.balance || 0)
  };
}

export function changeBalance(admin, user, amount) {
  if (!admin || admin.role !== "admin" || admin.isActive !== true) {
    return {
      ok: false,
      status: 403,
      message: "Admin access required"
    };
  }

  const value = Number(amount);

  if (!Number.isFinite(value) || value === 0) {
    return {
      ok: false,
      status: 400,
      message: "Invalid balance amount"
    };
  }

  const currentBalance = Number(user.balance || 0);
  const newBalance = currentBalance + value;

  if (newBalance < 0) {
    return {
      ok: false,
      status: 400,
      message: "Insufficient balance"
    };
  }

  return {
    ok: true,
    status: 200,
    userId: user.id,
    oldBalance: currentBalance,
    change: value,
    newBalance
  };
}