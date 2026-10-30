//! A desktop notification the service hands over (`--notify JSON`), shown so that it can be
//! acted on: the app stays connected to the session bus until the notification is closed, and
//! "Open in NeonWatch" (a button, since Cinnamon closes a notification clicked on its body) or
//! the default action (a body click elsewhere) opens the window at the issue.

use crate::address::valid_issue_id;
use serde::Deserialize;

/// Caps on what is shown, whatever the service sends.
pub const MAX_SUMMARY: usize = 200;
pub const MAX_BODY: usize = 1000;

/// The service's `Notification`: the issue it is about (none for a storm summary), the lines
/// to show, and the freedesktop urgency (0 low, 1 normal, 2 critical).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub issue_id: Option<String>,
    pub summary: String,
    pub body: String,
    pub urgency: u8,
}

impl Notice {
    pub fn parse(json: &str) -> Result<Self, String> {
        let mut n: Notice = serde_json::from_str(json).map_err(|e| format!("--notify: {e}"))?;
        if let Some(id) = &n.issue_id {
            if !valid_issue_id(id) {
                return Err(format!("--notify: not an issue id: {id:?}"));
            }
        }
        if n.urgency > 2 {
            return Err(format!("--notify: urgency is 0, 1 or 2, not {}", n.urgency));
        }
        n.summary = cap(&n.summary, MAX_SUMMARY);
        n.body = cap(&n.body, MAX_BODY);
        Ok(n)
    }

    /// The body as notification markup: Cinnamon renders `<b>` and friends, and a next step
    /// such as `ss -ltnp | grep '<port>'` must show as written.
    pub fn body_markup(&self) -> String {
        self.body
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Show it and wait, on a thread of its own, for what is done with it. `opened` runs when
    /// the user picks "Open in NeonWatch" or the default action; a notification closed or
    /// expired does nothing. A failure to show it is returned as text and never panics.
    pub fn show(self, opened: impl FnOnce(Option<String>) + Send + 'static) {
        std::thread::spawn(move || {
            let urgency = match self.urgency {
                0 => notify_rust::Urgency::Low,
                1 => notify_rust::Urgency::Normal,
                _ => notify_rust::Urgency::Critical,
            };
            let shown = notify_rust::Notification::new()
                .appname("NeonWatch")
                .summary(&self.summary)
                .body(&self.body_markup())
                .icon("neonwatch")
                .urgency(urgency)
                .hint(notify_rust::Hint::DesktopEntry("neonwatch".into()))
                .action("default", "Open")
                .action("open", "Open in NeonWatch")
                .show();
            match shown {
                Ok(handle) => handle.wait_for_action(|action| {
                    if action == "default" || action == "open" {
                        opened(self.issue_id.clone());
                    }
                }),
                Err(e) => eprintln!("neonwatch-desktop: cannot show a notification: {e}"),
            }
        });
    }
}

fn cap(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars()
        .take(limit - 1)
        .chain(std::iter::once('…'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_services_notification_parses() {
        let n = Notice::parse(r#"{"issue_id":"i-66d58c3c7d6e43e2","summary":"neonwatch: CRITICAL — x","body":"disk/nvme0n1\nsudo smartctl -a /dev/nvme0","urgency":2}"#).unwrap();
        assert_eq!(n.issue_id.as_deref(), Some("i-66d58c3c7d6e43e2"));
        assert_eq!(n.urgency, 2);
    }

    #[test]
    fn a_storm_summary_has_no_issue() {
        let n = Notice::parse(r#"{"issue_id":null,"summary":"neonwatch: 4 more issues need attention","body":"b","urgency":1}"#).unwrap();
        assert_eq!(n.issue_id, None);
    }

    #[test]
    fn bad_ids_urgencies_fields_and_json_are_refused() {
        for bad in [
            r#"{"issue_id":"a b","summary":"s","body":"b","urgency":1}"#,
            r#"{"issue_id":"i-1","summary":"s","body":"b","urgency":3}"#,
            r#"{"issue_id":"i-1","summary":"s","body":"b","urgency":1,"extra":true}"#,
            r#"{"issue_id":"i-1","summary":"s","urgency":1}"#,
            "not json",
        ] {
            assert!(Notice::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn long_text_is_capped_on_a_character_boundary() {
        let long = "é".repeat(MAX_BODY + 50);
        let json =
            serde_json::json!({"issue_id": null, "summary": long, "body": long, "urgency": 0});
        let n = Notice::parse(&json.to_string()).unwrap();
        assert_eq!(n.summary.chars().count(), MAX_SUMMARY);
        assert_eq!(n.body.chars().count(), MAX_BODY);
        assert!(n.body.ends_with('…'));
    }

    #[test]
    fn the_body_is_escaped_for_notification_markup() {
        let n = Notice::parse(r#"{"issue_id":null,"summary":"s","body":"ss -ltnp | grep '<port>' && echo <b>","urgency":1}"#).unwrap();
        assert_eq!(
            n.body_markup(),
            "ss -ltnp | grep '&lt;port&gt;' &amp;&amp; echo &lt;b&gt;"
        );
    }
}
