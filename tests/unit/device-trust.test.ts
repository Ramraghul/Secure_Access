import { isTrustActive, newTrustExpiry, trustView, TRUST_CLEARED } from "../../src/services/device.service";

const inOneMinute = () => new Date(Date.now() + 60_000);
const oneMinuteAgo = () => new Date(Date.now() - 60_000);

describe("device trust", () => {
  it("is active only when set and not yet expired", () => {
    expect(isTrustActive({ isTrusted: true, trustedUntil: inOneMinute() })).toBe(true);
    expect(isTrustActive({ isTrusted: true, trustedUntil: oneMinuteAgo() })).toBe(false);
    expect(isTrustActive({ isTrusted: true, trustedUntil: null })).toBe(false); // legacy trust without expiry
    expect(isTrustActive({ isTrusted: false, trustedUntil: inOneMinute() })).toBe(false);
    expect(isTrustActive(null)).toBe(false);
  });

  it("reports the effective state, hiding expired trust", () => {
    const until = inOneMinute();
    expect(trustView({ isTrusted: true, trustedUntil: until })).toEqual({ isTrusted: true, trustedUntil: until });
    expect(trustView({ isTrusted: true, trustedUntil: oneMinuteAgo() })).toEqual({ isTrusted: false, trustedUntil: null });
    expect(trustView(TRUST_CLEARED)).toEqual({ isTrusted: false, trustedUntil: null });
  });

  it("lasts TRUSTED_DEVICE_DAYS (30 by default)", () => {
    const days = (newTrustExpiry().getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.99);
    expect(days).toBeLessThanOrEqual(30);
  });
});
