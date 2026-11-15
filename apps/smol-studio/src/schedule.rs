use std::time::{Duration, Instant};

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Scheduling is independent of rendering: an unfocused/minimized app does
/// not request timer repaints or launch observational runtime processes.
#[derive(Default)]
pub struct RefreshSchedule {
    last: Option<Instant>,
    was_active: bool,
}

impl RefreshSchedule {
    pub fn due(&mut self, now: Instant, active: bool, busy: bool) -> bool {
        let regained_focus = active && !self.was_active;
        self.was_active = active;
        active
            && !busy
            && (regained_focus
                || self
                    .last
                    .is_none_or(|t| now.duration_since(t) >= REFRESH_INTERVAL))
    }

    pub fn completed(&mut self, now: Instant) {
        self.last = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_background_polls_or_overlap_and_refresh_on_focus() {
        let mut s = RefreshSchedule::default();
        let now = Instant::now();
        assert!(!s.due(now, false, false));
        assert!(s.due(now, true, false));
        s.completed(now);
        assert!(!s.due(now + Duration::from_secs(1), true, false));
        assert!(!s.due(now + Duration::from_secs(10), true, true));
        assert!(!s.due(now + Duration::from_secs(10), false, false));
        assert!(s.due(now + Duration::from_secs(10), true, false));
    }
}
