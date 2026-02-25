use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationSpan {
    millis: u64,
}

impl DurationSpan {
    pub fn from_millis(millis: u64) -> Self {
        Self { millis }
    }

    pub fn from_secs(secs: u64) -> Self {
        Self {
            millis: secs.saturating_mul(1_000),
        }
    }

    pub fn as_millis(self) -> u64 {
        self.millis
    }

    pub fn as_std(self) -> Duration {
        Duration::from_millis(self.millis)
    }

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.millis.checked_add(rhs.millis).map(Self::from_millis)
    }

    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.millis.checked_sub(rhs.millis).map(Self::from_millis)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    pub fn after(timeout: DurationSpan) -> Self {
        Self::from_parts(Instant::now(), timeout)
    }

    pub fn from_parts(start: Instant, timeout: DurationSpan) -> Self {
        let at = start.checked_add(timeout.as_std()).unwrap_or(start);
        Self { at }
    }

    pub fn has_expired_at(self, now: Instant) -> bool {
        now >= self.at
    }

    pub fn remaining_at(self, now: Instant) -> DurationSpan {
        let duration = self.at.saturating_duration_since(now);
        DurationSpan::from_millis(duration.as_millis() as u64)
    }

    pub fn instant(self) -> Instant {
        self.at
    }
}

pub fn compose_deadline(start: Instant, timeout: DurationSpan) -> Instant {
    start.checked_add(timeout.as_std()).unwrap_or(start)
}

#[cfg(test)]
mod tests {
    use super::{compose_deadline, Deadline, DurationSpan};
    use std::time::{Duration, Instant};

    #[test]
    fn duration_span_checked_math() {
        let a = DurationSpan::from_millis(100);
        let b = DurationSpan::from_secs(1);
        assert_eq!(a.checked_add(b).expect("add").as_millis(), 1_100);
        assert_eq!(b.checked_sub(a).expect("sub").as_millis(), 900);
    }

    #[test]
    fn deadline_composition_is_monotonic() {
        let start = Instant::now();
        let timeout = DurationSpan::from_millis(25);
        let deadline = Deadline::from_parts(start, timeout);
        assert!(deadline.instant() >= start);
        let check = compose_deadline(start, timeout);
        assert_eq!(check, deadline.instant());

        let now = start + Duration::from_millis(10);
        let remaining = deadline.remaining_at(now);
        assert!(remaining.as_millis() <= 15);
    }
}
