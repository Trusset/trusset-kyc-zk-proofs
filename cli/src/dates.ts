// Civil-date conversions. Mirrors prover/src/dates.rs exactly; `epochDays` is
// the tool's time unit everywhere and the two sides must agree to the day.

/** Days since 1970-01-01 for a proleptic Gregorian date, or null. */
export function daysFromCivil(y: number, m: number, d: number): number | null {
  if (!Number.isInteger(y) || !Number.isInteger(m) || !Number.isInteger(d)) return null;
  if (m < 1 || m > 12 || d < 1 || d > 31) return null;
  const yAdj = y - (m <= 2 ? 1 : 0);
  const era = Math.floor((yAdj >= 0 ? yAdj : yAdj - 399) / 400);
  const yoe = yAdj - era * 400;
  const mAdj = m > 2 ? m - 3 : m + 9;
  const doy = Math.floor((153 * mAdj + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const days = era * 146097 + doe - 719468;
  return days < 0 ? null : days;
}

/** `(year, month, day)` from days since 1970-01-01. */
export function civilFromDays(z: number): { year: number; month: number; day: number } {
  const zz = z + 719468;
  const era = Math.floor((zz >= 0 ? zz : zz - 146096) / 146097);
  const doe = zz - era * 146097;
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365,
  );
  const y0 = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp < 10 ? mp + 3 : mp - 9;
  const year = month <= 2 ? y0 + 1 : y0;
  return { year, month, day };
}

/** `epochDays` rendered as `YYYY-MM-DD`. */
export function epochDaysToIsoDate(epochDays: number): string {
  const { year, month, day } = civilFromDays(epochDays);
  const pad = (n: number, w: number) => String(n).padStart(w, '0');
  return `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}`;
}

/**
 * Parse `YYYY-MM-DD` or a raw epoch-day integer. Operators write dates; the
 * tool stores day counts, and every boundary between them goes through here so
 * a malformed date fails once with a clear message rather than silently
 * becoming a wrong number.
 */
export function parseDateToEpochDays(input: string, context: string): number {
  const trimmed = input.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(trimmed);
  if (!m) {
    throw new Error(`${context}: "${input}" is not a date. Use YYYY-MM-DD, or an epoch-day integer.`);
  }
  const days = daysFromCivil(Number(m[1]), Number(m[2]), Number(m[3]));
  if (days === null) {
    throw new Error(
      `${context}: "${input}" is not a real calendar date, or falls before 1970-01-01.`,
    );
  }
  return days;
}

/** Today in `epochDays`, UTC. */
export function todayEpochDays(): number {
  return Math.floor(Date.now() / 86_400_000);
}
