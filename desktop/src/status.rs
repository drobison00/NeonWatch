//! The tray's state, from the dashboard's `/api/overview`: the worst open severity, unless the
//! agent's heartbeat is older than the dashboard's own stale threshold.

use serde_json::Value;

/// The dashboard's `HEARTBEAT_STALE_S`: an older heartbeat means nothing is being watched.
pub const HEARTBEAT_STALE_S: f64 = 180.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Quiet,
    Watch,
    Warn,
    Critical,
    /// The agent's heartbeat is stale or absent.
    Stale,
    /// The service is not running, or not reachable.
    Down,
}

impl Level {
    /// The tray icon for this level.
    pub fn icon(self) -> &'static [u8] {
        match self {
            Level::Quiet => include_bytes!("../icons/tray-quiet.png"),
            Level::Watch => include_bytes!("../icons/tray-watch.png"),
            Level::Warn => include_bytes!("../icons/tray-warn.png"),
            Level::Critical => include_bytes!("../icons/tray-critical.png"),
            Level::Stale => include_bytes!("../icons/tray-stale.png"),
            Level::Down => include_bytes!("../icons/tray-down.png"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub level: Level,
    /// One line for the tray's tooltip.
    pub summary: String,
    /// The window title: "NeonWatch", with the open counts when there are any.
    pub title: String,
}

impl Status {
    pub fn down(reason: &str) -> Self {
        Status {
            level: Level::Down,
            summary: format!("NeonWatch: {reason}"),
            title: "NeonWatch".into(),
        }
    }

    /// Read `/api/overview`. A critical issue outranks a stale agent, which outranks the rest:
    /// with nothing watched, a quiet tray would be a claim nobody can make.
    pub fn from_overview(overview: &Value) -> Self {
        let count = |s: &str| overview["counts"][s].as_u64().unwrap_or(0);
        let (critical, warn, watch) = (count("critical"), count("warn"), count("watch"));
        let age = overview["heartbeat"]["age_s"].as_f64();
        let stale = age.map_or(true, |a| a > HEARTBEAT_STALE_S);
        let level = if critical > 0 {
            Level::Critical
        } else if stale {
            Level::Stale
        } else if warn > 0 {
            Level::Warn
        } else if watch > 0 {
            Level::Watch
        } else {
            Level::Quiet
        };
        let mut open: Vec<String> = [("critical", critical), ("warn", warn), ("watch", watch)]
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(s, n)| format!("{n} {s}"))
            .collect();
        let title = if open.is_empty() {
            "NeonWatch".into()
        } else {
            format!("NeonWatch — {}", open.join(", "))
        };
        if open.is_empty() {
            open.push("nothing open".into());
        }
        let agent = match age {
            None => "no agent heartbeat".to_string(),
            Some(a) if a > HEARTBEAT_STALE_S => format!("agent silent for {}", ago(a)),
            Some(a) => format!("agent {} ago", ago(a)),
        };
        Status {
            level,
            summary: format!("NeonWatch: {} · {agent}", open.join(", ")),
            title,
        }
    }
}

fn ago(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    match s {
        0..=89 => format!("{s} s"),
        90..=5399 => format!("{} min", (s + 30) / 60),
        _ => format!("{} h", (s + 1800) / 3600),
    }
}

/// GET `/api/overview` with the per-launch token. Plain HTTP only: a TLS or password-mode
/// dashboard has no status in the tray, and says so.
pub fn fetch(origin: &str, token: Option<&str>) -> Status {
    let Some(token) = token else {
        return Status::down("status needs the per-launch token (password mode)");
    };
    if !origin.starts_with("http://") {
        return Status::down("status over TLS is not supported");
    }
    let response = ureq::get(&format!("{origin}/api/overview"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .call();
    match response {
        Ok(r) => match r
            .into_string()
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
        {
            Ok(v) => Status::from_overview(&v),
            Err(e) => Status::down(&format!("unreadable overview ({e})")),
        },
        Err(ureq::Error::Status(401, _)) => Status::down("signed out: the service restarted"),
        Err(ureq::Error::Status(code, _)) => {
            Status::down(&format!("the dashboard answered {code}"))
        }
        Err(e) => Status::down(&format!("the service is not reachable ({})", e.kind())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn overview(critical: u64, warn: u64, watch: u64, age: Option<f64>) -> Value {
        json!({"counts": {"critical": critical, "warn": warn, "watch": watch, "info": 0},
               "heartbeat": age.map(|a| json!({"age_s": a}))})
    }

    #[test]
    fn the_worst_open_severity_is_the_level() {
        assert_eq!(
            Status::from_overview(&overview(0, 0, 0, Some(30.0))).level,
            Level::Quiet
        );
        assert_eq!(
            Status::from_overview(&overview(0, 0, 2, Some(30.0))).level,
            Level::Watch
        );
        assert_eq!(
            Status::from_overview(&overview(0, 9, 1, Some(30.0))).level,
            Level::Warn
        );
        assert_eq!(
            Status::from_overview(&overview(1, 9, 1, Some(30.0))).level,
            Level::Critical
        );
    }

    #[test]
    fn a_silent_agent_outranks_warnings_but_not_a_critical_issue() {
        assert_eq!(
            Status::from_overview(&overview(0, 9, 1, Some(181.0))).level,
            Level::Stale
        );
        assert_eq!(
            Status::from_overview(&overview(0, 0, 0, None)).level,
            Level::Stale
        );
        assert_eq!(
            Status::from_overview(&overview(1, 0, 0, Some(900.0))).level,
            Level::Critical
        );
    }

    #[test]
    fn the_tooltip_and_title_say_what_is_open_and_how_recent_the_agent_is() {
        let s = Status::from_overview(&overview(1, 9, 1, Some(39.1)));
        assert_eq!(
            s.summary,
            "NeonWatch: 1 critical, 9 warn, 1 watch · agent 39 s ago"
        );
        assert_eq!(s.title, "NeonWatch — 1 critical, 9 warn, 1 watch");
        let quiet = Status::from_overview(&overview(0, 0, 0, Some(400.0)));
        assert_eq!(
            quiet.summary,
            "NeonWatch: nothing open · agent silent for 7 min"
        );
        assert_eq!(quiet.title, "NeonWatch");
        assert!(Status::from_overview(&overview(0, 0, 0, None))
            .summary
            .ends_with("no agent heartbeat"));
        assert_eq!(ago(7300.0), "2 h");
    }

    #[test]
    fn a_missing_token_or_tls_is_said_rather_than_guessed() {
        assert!(fetch("http://127.0.0.1:1", None)
            .summary
            .contains("password mode"));
        assert!(fetch("https://127.0.0.1:1", Some("t"))
            .summary
            .contains("TLS"));
        assert_eq!(fetch("http://127.0.0.1:1", Some("t")).level, Level::Down); // nothing listens
    }

    #[test]
    fn every_level_has_a_png_icon() {
        for level in [
            Level::Quiet,
            Level::Watch,
            Level::Warn,
            Level::Critical,
            Level::Stale,
            Level::Down,
        ] {
            assert!(level.icon().starts_with(b"\x89PNG"), "{level:?}");
        }
    }
}
