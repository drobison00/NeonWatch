//! The command line, for the first launch and for every later one the running instance is
//! handed (single instance): open the window, open an issue, or show a notification.

use crate::address::valid_issue_id;
use crate::notice::Notice;
use tauri::Url;

pub const USAGE: &str =
    "usage: neonwatch-desktop [--hidden] [--issue ID | neonwatch://issue/ID | --notify JSON]";

#[derive(Debug, PartialEq)]
pub enum Request {
    /// Show the window (a launch with nothing else to do).
    Show,
    /// Show the window at one issue.
    Issue(String),
    /// Show a desktop notification whose "Open" opens the window at its issue.
    Notify(Notice),
}

#[derive(Debug, PartialEq)]
pub struct Launch {
    /// Start in the tray: the autostart entry, and a launch only to show a notification.
    pub hidden: bool,
    pub request: Request,
}

/// Parse `argv` (program name first).
pub fn parse(argv: &[String]) -> Result<Launch, String> {
    let mut hidden = false;
    let mut request = None;
    let mut args = argv.iter().skip(1);
    let set = |r: Request, request: &mut Option<Request>| -> Result<(), String> {
        if request.replace(r).is_some() {
            return Err(format!(
                "one of --issue, --notify or a neonwatch:// link, not several\n{USAGE}"
            ));
        }
        Ok(())
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--hidden" => hidden = true,
            "--issue" => {
                let id = args.next().ok_or(format!("--issue needs an id\n{USAGE}"))?;
                set(Request::Issue(issue(id)?), &mut request)?;
            }
            "--notify" => {
                let json = args.next().ok_or(format!("--notify needs JSON\n{USAGE}"))?;
                set(Request::Notify(Notice::parse(json)?), &mut request)?;
            }
            "-h" | "--help" => return Err(USAGE.into()),
            link if link.starts_with("neonwatch:") => {
                set(Request::Issue(deep_link(link)?), &mut request)?
            }
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let request = request.unwrap_or(Request::Show);
    // A launch only to show a notification keeps the window hidden until it is opened.
    let hidden = hidden || matches!(request, Request::Notify(_));
    Ok(Launch { hidden, request })
}

fn issue(id: &str) -> Result<String, String> {
    if valid_issue_id(id) {
        Ok(id.to_string())
    } else {
        Err(format!("not an issue id: {id:?}"))
    }
}

/// `neonwatch://issue/<id>`, the link the desktop entry is registered for.
fn deep_link(link: &str) -> Result<String, String> {
    let url = Url::parse(link).map_err(|e| format!("not a neonwatch:// link ({e})"))?;
    let id = url.path().strip_prefix('/').unwrap_or("");
    if url.scheme() != "neonwatch" || url.host_str() != Some("issue") || url.query().is_some() {
        return Err(format!("not a neonwatch://issue/<id> link: {link}"));
    }
    issue(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        std::iter::once("neonwatch-desktop")
            .chain(args.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn no_arguments_shows_the_window_and_hidden_starts_in_the_tray() {
        assert_eq!(
            parse(&argv(&[])).unwrap(),
            Launch {
                hidden: false,
                request: Request::Show
            }
        );
        assert_eq!(
            parse(&argv(&["--hidden"])).unwrap(),
            Launch {
                hidden: true,
                request: Request::Show
            }
        );
    }

    #[test]
    fn an_issue_comes_from_the_flag_or_a_neonwatch_link() {
        for args in [
            &["--issue", "i-66d58c3c7d6e43e2"][..],
            &["neonwatch://issue/i-66d58c3c7d6e43e2"],
        ] {
            assert_eq!(
                parse(&argv(args)).unwrap().request,
                Request::Issue("i-66d58c3c7d6e43e2".into())
            );
        }
    }

    #[test]
    fn a_notification_launch_stays_hidden() {
        let launch = parse(&argv(&[
            "--notify",
            r#"{"issue_id":"i-1","summary":"s","body":"b","urgency":2}"#,
        ]))
        .unwrap();
        assert!(launch.hidden);
        assert!(matches!(launch.request, Request::Notify(_)));
    }

    #[test]
    fn bad_ids_links_and_arguments_are_refused_with_usage() {
        for args in [
            &["--issue"][..],
            &["--issue", "a b"],
            &["--notify"],
            &["--notify", "{"],
            &["neonwatch://issue/"],
            &["neonwatch://view/logs"],
            &["neonwatch://issue/x?y=1"],
            &["neonwatch:junk"],
            &["--frobnicate"],
            &["--help"],
            &["--issue", "i-1", "--issue", "i-2"],
        ] {
            assert!(parse(&argv(args)).is_err(), "{args:?}");
        }
        assert!(parse(&argv(&["--wat"])).unwrap_err().contains("usage:"));
    }
}
