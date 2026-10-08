export const DEFAULT_SETTINGS = {
  minDeposit: 50,
  taxPercent: 0,

  paymentMethods: {
    bKash: {
      enabled: true,
      number: ""
    },

    Nagad: {
      enabled: true,
      number: ""
    },

    Binance: {
      enabled: true,
      uid: ""
    }
  },

  social: {
    youtube: "",
    tiktok: "",
    telegramChannel: "",
    telegramGroup: ""
  }
};

export function updateAdminSettings(current, updates) {
  return {
    ...current,
    ...updates,

    minDeposit:
      Number(updates.minDeposit ?? current.minDeposit) >= 50
        ? Number(updates.minDeposit ?? current.minDeposit)
        : 50,

    taxPercent:
      Number(updates.taxPercent ?? current.taxPercent) >= 0
        ? Number(updates.taxPercent ?? current.taxPercent)
        : 0
  };
}