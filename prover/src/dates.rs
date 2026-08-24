//! Civil-date conversions shared by the dispatch, manifest, and CLI paths.
//!
//! `epochDays` is the tool's time unit everywhere: it is what the leaf hash
//! binds, what the age circuit compares against, and what validity intervals
//! and revocations are expressed in. Auditors read dates, so every place a day
//! count reaches a human it is rendered through [`epoch_days_to_iso_date`].
//!
//! Both directions are Howard Hinnant's `days_from_civil` / `civil_from_days`,
//! exact over the proleptic Gregorian calendar with no floating point.

/// Days since 1970-01-01 for a proleptic Gregorian date. `None` for a month
/// outside 1..=12, a day outside 1..=31, or a date before the epoch.
#[must_use]
pub fn days_from_civil(y: i64, m: u32, d: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let d = d as u64;
    let m_adj = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = ((153 * m_adj as u64 + 2) / 5) + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_y0 = (era * 146097) + doe as i64 - 719468;
    if days_since_y0 < 0 {
        None
    } else {
        Some(days_since_y0 as u64)
    }
}

/// Inverse of [`days_from_civil`]: `(year, month, day)` from days since epoch.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// `epochDays` rendered as `YYYY-MM-DD`.
#[must_use]
pub fn epoch_days_to_iso_date(epoch_days: u64) -> String {
    let (y, m, d) = civil_from_days(epoch_days as i64);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// `epochDays` plus a time-of-day of zero, as an ISO 8601 instant.
#[must_use]
pub fn epoch_days_to_iso_instant(epoch_days: u64) -> String {
    format!("{}T00:00:00Z", epoch_days_to_iso_date(epoch_days))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_across_a_wide_range() {
        for days in [0u64, 1, 10957, 20587, 20700, 25000, 100_000] {
            let (y, m, d) = civil_from_days(days as i64);
            assert_eq!(
                days_from_civil(y, m, d),
                Some(days),
                "round trip failed at {}",
                days
            );
        }
    }

    #[test]
    fn known_dates_render_correctly() {
        assert_eq!(epoch_days_to_iso_date(0), "1970-01-01");
        assert_eq!(epoch_days_to_iso_date(10957), "2000-01-01");
        assert_eq!(epoch_days_to_iso_date(20587), "2026-05-14");
    }

    #[test]
    fn leap_day_is_exact() {
        let leap = days_from_civil(2024, 2, 29).unwrap();
        assert_eq!(epoch_days_to_iso_date(leap), "2024-02-29");
        assert_eq!(
            days_from_civil(2024, 3, 1).unwrap() - leap,
            1,
            "the day after 29 Feb 2024 is 1 March"
        );
    }

    #[test]
    fn rejects_impossible_months_and_days() {
        assert_eq!(days_from_civil(2020, 0, 1), None);
        assert_eq!(days_from_civil(2020, 13, 1), None);
        assert_eq!(days_from_civil(2020, 1, 0), None);
        assert_eq!(days_from_civil(2020, 1, 32), None);
    }

    #[test]
    fn rejects_dates_before_the_epoch() {
        assert_eq!(days_from_civil(1969, 12, 31), None);
    }

    #[test]
    fn iso_instant_appends_midnight_utc() {
        assert_eq!(epoch_days_to_iso_instant(20587), "2026-05-14T00:00:00Z");
    }
}
