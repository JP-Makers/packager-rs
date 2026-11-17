//! Deterministic timestamps for reproducible packages.
//!
//! `SOURCE_DATE_EPOCH` is the cross-ecosystem convention: when it is set,
//! every timestamp written into an artifact must come from it instead of the
//! wall clock.

use std::time::{SystemTime, UNIX_EPOCH};

/// Return `SOURCE_DATE_EPOCH` when it is a valid non-negative integer.
pub fn source_date_epoch() -> Option<u64> {
    std::env::var_os("SOURCE_DATE_EPOCH")
        .and_then(|value| value.to_str().and_then(|s| s.parse::<u64>().ok()))
}

/// Current time, or `SOURCE_DATE_EPOCH` when set.
pub fn timestamp() -> u64 {
    source_date_epoch().unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Convert seconds since the Unix epoch into a civil UTC date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's `civil_from_days`, valid for the whole proleptic
    // Gregorian calendar.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn split_timestamp(secs: u64) -> (i64, u32, u32, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (rem / 3600) as u8,
        ((rem % 3600) / 60) as u8,
        (rem % 60) as u8,
    )
}

/// RFC 3339 / ISO 8601 timestamp, e.g. `2026-11-17T12:00:00Z`.
pub fn iso8601(secs: u64) -> String {
    let (year, month, day, hour, min, sec) = split_timestamp(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// RFC 2822 timestamp, e.g. `Tue, 17 Nov 2026 12:00:00 +0000`.
pub fn rfc2822(secs: u64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = (secs / 86_400) as usize;
    let (year, month, day, hour, min, sec) = split_timestamp(secs);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        WEEKDAYS[days % 7],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        min,
        sec
    )
}

/// Seven-byte ISO 9660 recording date: years since 1900, month, day, hour,
/// minute, second, and a signed GMT offset in 15-minute intervals.
pub fn iso9660_datetime(secs: u64) -> [u8; 7] {
    let (year, month, day, hour, min, sec) = split_timestamp(secs);
    let year = (year - 1900).clamp(0, 255) as u8;
    [year, month as u8, day as u8, hour, min, sec, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso8601_epoch_and_known_date() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_rfc2822_epoch() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
    }

    #[test]
    fn test_iso9660_datetime() {
        assert_eq!(iso9660_datetime(0), [70, 1, 1, 0, 0, 0, 0]);
    }
}
