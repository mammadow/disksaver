#![forbid(unsafe_code)]

/// Windows FILETIME intervals (100-nanoseconds) between January 1, 1601 and January 1, 2000 UTC.
pub const FILETIME_EPOCH_2000: u64 = 125_911_584_000_000_000;

/// Number of 100-nanosecond intervals in one minute (60 * 10^7).
pub const INTERVALS_PER_MINUTE: u64 = 600_000_000;

/// Converts a 64-bit Windows FILETIME (100-ns intervals since 1601-01-01 UTC) into minutes
/// elapsed since 2000-01-01 00:00:00 UTC.
///
/// Saturates to 0 for timestamps earlier than year 2000, and to `u32::MAX` for the far future.
pub fn filetime_to_min2000(ft: u64) -> u32 {
    if ft < FILETIME_EPOCH_2000 {
        0
    } else {
        let delta = ft - FILETIME_EPOCH_2000;
        let mins = delta / INTERVALS_PER_MINUTE;
        mins.min(u32::MAX as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch_2000_is_zero() {
        assert_eq!(filetime_to_min2000(125_911_584_000_000_000), 0);
    }

    #[test]
    fn filetime_one_minute() {
        assert_eq!(
            filetime_to_min2000(125_911_584_000_000_000 + 600_000_000),
            1
        );
    }

    #[test]
    fn filetime_before_2000_saturates() {
        assert_eq!(filetime_to_min2000(0), 0);
    }

    #[test]
    fn filetime_far_future_saturates() {
        assert_eq!(filetime_to_min2000(u64::MAX), u32::MAX);
    }

    #[test]
    fn filetime_sub_minute_truncates() {
        assert_eq!(
            filetime_to_min2000(125_911_584_000_000_000 + 599_999_999),
            0
        );
        assert_eq!(
            filetime_to_min2000(125_911_584_000_000_000 + 600_000_001),
            1
        );
    }
}
