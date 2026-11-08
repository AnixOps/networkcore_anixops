//! Cron expressions of scheduled plugin scripts (Surge `type=cron`
//! `cronexp=`, Loon `cron "..."`, Quantumult X `[task_local]`).
//!
//! Five fields (`minute hour day-of-month month day-of-week`) or six with a
//! leading `second`. A field is `*` (or `?`), a value, a range `a-b`, a step
//! `*/n` or `a-b/n`, or a comma list of those. Months and weekdays may be
//! names (`JAN`, `MON`); weekday 7 is Sunday. When both day fields are
//! restricted a day matches either one, as in Vixie cron. Times are local.

use jiff::civil::Date;
pub use jiff::Zoned;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CronSchedule {
    seconds: u64,
    minutes: u64,
    hours: u32,
    days: u32,
    months: u16,
    weekdays: u8,
    days_restricted: bool,
    weekdays_restricted: bool,
}

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const WEEKDAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

/// Bits `min..=max` set by one field; `names[i]` stands for `min + i`.
fn field(text: &str, min: u32, max: u32, names: &[&str]) -> Option<(u64, bool)> {
    let value = |token: &str| -> Option<u32> {
        if let Some(index) = names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(token))
        {
            return Some(min + index as u32);
        }
        token.parse::<u32>().ok()
    };
    let mut bits = 0u64;
    let restricted = !matches!(text, "*" | "?");
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, step.parse::<u32>().ok().filter(|step| *step > 0)?),
            None => (part, 1),
        };
        let (start, end) = if matches!(range, "*" | "?") {
            (min, max)
        } else if let Some((start, end)) = range.split_once('-') {
            (value(start)?, value(end)?)
        } else {
            let start = value(range)?;
            // `5/15` runs from 5 to the end of the range.
            (start, if part.contains('/') { max } else { start })
        };
        if start < min || end > max || start > end {
            return None;
        }
        let mut at = start;
        while at <= end {
            bits |= 1 << at;
            at += step;
        }
    }
    (bits != 0).then_some((bits, restricted))
}

impl CronSchedule {
    pub fn parse(expression: &str) -> Option<Self> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        let (seconds, rest) = match fields.len() {
            5 => (1, &fields[..]),
            6 => (field(fields[0], 0, 59, &[])?.0, &fields[1..]),
            _ => return None,
        };
        let (minutes, _) = field(rest[0], 0, 59, &[])?;
        let (hours, _) = field(rest[1], 0, 23, &[])?;
        let (days, days_restricted) = field(rest[2], 1, 31, &[])?;
        let (months, _) = field(rest[3], 1, 12, &MONTHS)?;
        let (mut weekdays, weekdays_restricted) = field(rest[4], 0, 7, &WEEKDAYS)?;
        if weekdays & (1 << 7) != 0 {
            weekdays = (weekdays & !(1 << 7)) | 1;
        }
        Some(Self {
            seconds,
            minutes,
            hours: hours as u32,
            days: days as u32,
            months: months as u16,
            weekdays: weekdays as u8,
            days_restricted,
            weekdays_restricted,
        })
    }

    fn day_matches(&self, date: Date) -> bool {
        if self.months & (1 << date.month()) == 0 {
            return false;
        }
        let day = self.days & (1 << date.day()) != 0;
        let weekday = self.weekdays & (1 << date.weekday().to_sunday_zero_offset()) != 0;
        match (self.days_restricted, self.weekdays_restricted) {
            (true, true) => day || weekday,
            (true, false) => day,
            (false, true) => weekday,
            (false, false) => true,
        }
    }

    /// The first matching time after `now`, in `now`'s time zone; `None`
    /// when nothing matches within about five years (`0 0 30 2 *`).
    pub fn next_after(&self, now: &Zoned) -> Option<Zoned> {
        let tz = now.time_zone().clone();
        let mut date = now.datetime().date();
        for _ in 0..(366 * 5) {
            if self.day_matches(date) {
                for hour in (0..24).filter(|hour| self.hours & (1 << hour) != 0) {
                    for minute in (0..60).filter(|minute| self.minutes & (1 << minute) != 0) {
                        for second in (0..60).filter(|second| self.seconds & (1 << second) != 0) {
                            let Ok(at) = date
                                .at(hour as i8, minute as i8, second as i8, 0)
                                .to_zoned(tz.clone())
                            else {
                                continue;
                            };
                            if at.timestamp() > now.timestamp() {
                                return Some(at);
                            }
                        }
                    }
                }
            }
            date = date.tomorrow().ok()?;
        }
        None
    }
}

/// A schedule against the wall clock. Every poll reads the clock afresh, so
/// a device that slept through a run fires it once on waking, and a clock
/// change moves the schedule with it.
#[derive(Debug, Clone)]
pub struct CronTimer {
    schedule: CronSchedule,
    next: Option<Zoned>,
}

impl CronTimer {
    pub fn new(schedule: CronSchedule, now: &Zoned) -> Self {
        Self {
            schedule,
            next: schedule.next_after(now),
        }
    }

    /// Whether a run is due at `now`. Either way the next run becomes the
    /// first one after `now`.
    pub fn poll(&mut self, now: &Zoned) -> bool {
        let due = self
            .next
            .as_ref()
            .is_some_and(|next| next.timestamp() <= now.timestamp());
        self.next = self.schedule.next_after(now);
        due
    }

    pub fn next(&self) -> Option<&Zoned> {
        self.next.as_ref()
    }

    /// Time from `now` until the next run; `None` when it never runs.
    pub fn until_next(&self, now: &Zoned) -> Option<Duration> {
        let next = self.next.as_ref()?;
        let millis = next.timestamp().as_millisecond() - now.timestamp().as_millisecond();
        Some(Duration::from_millis(u64::try_from(millis).unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;
    use jiff::tz::TimeZone;

    fn at(text: &str) -> Zoned {
        let (day, time) = text.split_once(' ').unwrap();
        let parts = day
            .split('-')
            .map(|p| p.parse::<i32>().unwrap())
            .collect::<Vec<_>>();
        let clock = time
            .split(':')
            .map(|p| p.parse::<i8>().unwrap())
            .collect::<Vec<_>>();
        date(parts[0] as i16, parts[1] as i8, parts[2] as i8)
            .at(clock[0], clock[1], clock[2], 0)
            .to_zoned(TimeZone::UTC)
            .unwrap()
    }

    fn next(expression: &str, now: &str) -> String {
        let next = CronSchedule::parse(expression)
            .unwrap_or_else(|| panic!("{expression} should parse"))
            .next_after(&at(now))
            .expect("a next time");
        next.datetime().to_string()
    }

    #[test]
    fn schedules_used_by_published_plugins() {
        assert_eq!(
            next("0 9 * * *", "2026-11-08 08:59:59"),
            "2026-11-08T09:00:00"
        );
        assert_eq!(
            next("0 9 * * *", "2026-11-08 09:00:00"),
            "2026-11-09T09:00:00"
        );
        assert_eq!(
            next("55 23 * * *", "2026-11-08 12:00:00"),
            "2026-11-08T23:55:00"
        );
        assert_eq!(
            next("*/30 * * * *", "2026-11-08 12:01:00"),
            "2026-11-08T12:30:00"
        );
        assert_eq!(
            next("30 8-20/4 * * 1-5", "2026-11-08 12:00:00"),
            "2026-11-09T08:30:00"
        );
        assert_eq!(
            next("0 0 1 JAN *", "2026-11-08 12:00:00"),
            "2027-01-01T00:00:00"
        );
        assert_eq!(
            next("0 12 * * SUN", "2026-11-08 13:00:00"),
            "2026-11-15T12:00:00"
        );
        assert_eq!(
            next("0 12 * * 7", "2026-11-08 13:00:00"),
            "2026-11-15T12:00:00"
        );
        // Six fields: seconds first.
        assert_eq!(
            next("30 0 9 * * *", "2026-11-08 09:00:00"),
            "2026-11-08T09:00:30"
        );
        // Both day fields restricted: either matches.
        assert_eq!(
            next("0 0 1 * 1", "2026-11-08 12:00:00"),
            "2026-11-09T00:00:00"
        );
        assert!(CronSchedule::parse("0 0 30 2 *")
            .unwrap()
            .next_after(&at("2026-11-08 12:00:00"))
            .is_none());
        for invalid in [
            "",
            "* * * *",
            "61 * * * *",
            "* * * * * * *",
            "*/0 * * * *",
            "a b c d e",
        ] {
            assert!(CronSchedule::parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn timer_fires_once_per_slot_and_follows_the_clock() {
        let schedule = CronSchedule::parse("0 9 * * *").unwrap();
        let mut timer = CronTimer::new(schedule, &at("2026-11-08 08:00:00"));
        assert_eq!(
            timer.until_next(&at("2026-11-08 08:00:00")),
            Some(Duration::from_secs(3600))
        );
        assert!(!timer.poll(&at("2026-11-08 08:59:59")));
        assert!(timer.poll(&at("2026-11-08 09:00:00")));
        assert!(!timer.poll(&at("2026-11-08 09:00:00")));
        // Asleep through two runs: one run on waking.
        assert!(timer.poll(&at("2026-11-10 12:00:00")));
        assert_eq!(
            timer.next().unwrap().datetime().to_string(),
            "2026-11-11T09:00:00"
        );
        // The clock moved back a day.
        assert!(!timer.poll(&at("2026-11-09 08:00:00")));
        assert_eq!(
            timer.next().unwrap().datetime().to_string(),
            "2026-11-09T09:00:00"
        );
    }
}
