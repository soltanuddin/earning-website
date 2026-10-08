export const MIN_DEPOSIT = 50;

export const PAYMENT_METHODS = [
  "bKash",
  "Nagad",
  "Binance UID"
];

export function validateDeposit(amount, method) {
  if (!Number.isFinite(amount) || amount < MIN_DEPOSIT) {
    return {
      ok: false,
      message: `Minimum deposit is ${MIN_DEPOSIT} BDT`
    };
  }

  if (!PAYMENT_METHODS.includes(method)) {
    return {
      ok: false,
      message: "Invalid payment method"
    };
  }

  return {
    ok: true,
    amount,
    method
  };
}