export function isAdmin(user) {
  return Boolean(
    user &&
    user.role === "admin" &&
    user.isActive === true
  );
}

export function requireAdmin(user) {
  if (!isAdmin(user)) {
    return {
      ok: false,
      status: 403,
      message: "Admin access required"
    };
  }

  return {
    ok: true,
    status: 200
  };
}