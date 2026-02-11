#[derive(Debug, Clone, Copy)]
pub struct RestartSignal {
    pub exit_code: i32,
    pub recent_failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    Restart,
    DoNotRestart,
}

pub fn decide_restart(signal: RestartSignal) -> RestartDecision {
    if signal.exit_code == 0 {
        return RestartDecision::DoNotRestart;
    }
    if signal.recent_failures >= 3 {
        return RestartDecision::DoNotRestart;
    }
    RestartDecision::Restart
}
