//! Where the dashboard is: the URL the service writes to `dashboard.url` beside its store, and the
//! addresses inside it (`#/issues/<id>`, `#/view/<name>`).

use std::path::{Path, PathBuf};
use tauri::Url;

/// The file name the service writes, beside the store.
pub const URL_FILE: &str = "dashboard.url";
/// The most the file may hold: one URL and a newline.
const MAX_BYTES: u64 = 4096;

/// The service's `dashboard.url`: `$NEONWATCH_URL_FILE` when the store is somewhere other than
/// its default, else `~/.local/state/neonwatch/dashboard.url`.
pub fn url_file() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NEONWATCH_URL_FILE") {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME")?;
    Some(
        Path::new(&home)
            .join(".local/state/neonwatch")
            .join(URL_FILE),
    )
}

/// The dashboard as the service announced it: the sign-in URL (with its per-launch token, or
/// without one in password mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dashboard {
    signin: Url,
}

impl Dashboard {
    /// One URL on the first line: http or https, a host, the root path, no fragment.
    pub fn parse(text: &str) -> Result<Self, String> {
        let line = text.lines().next().unwrap_or("").trim();
        let signin = Url::parse(line).map_err(|e| format!("not a URL ({e})"))?;
        if !matches!(signin.scheme(), "http" | "https") {
            return Err(format!("not an http(s) URL: {}", signin.scheme()));
        }
        if signin.host_str().is_none() || signin.path() != "/" || signin.fragment().is_some() {
            return Err("not the dashboard's root URL".into());
        }
        Ok(Self { signin })
    }

    /// Read and parse the service's file, refusing anything larger than one URL.
    pub fn read(path: &Path) -> Result<Self, String> {
        let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
        if size > MAX_BYTES {
            return Err(format!("{} is {size} bytes, not one URL", path.display()));
        }
        Self::parse(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
    }

    /// The sign-in URL with `fragment` (without its `#`) appended, or none.
    pub fn at(&self, fragment: Option<&str>) -> Url {
        let mut url = self.signin.clone();
        url.set_fragment(fragment);
        url
    }

    /// The per-launch token, absent in password mode.
    pub fn token(&self) -> Option<String> {
        self.signin
            .query_pairs()
            .find(|(k, _)| k == "token")
            .map(|(_, v)| v.into_owned())
    }

    /// `scheme://host:port`, for API requests.
    pub fn origin(&self) -> String {
        self.signin.origin().ascii_serialization()
    }

    /// Whether `url` is on the dashboard: same scheme, host and port.
    pub fn is_ours(&self, url: &Url) -> bool {
        url.origin() == self.signin.origin()
    }
}

/// What the dashboard accepts as an issue id in an address.
pub fn valid_issue_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// The fragment that opens an issue, for an id that `valid_issue_id` accepts.
pub fn issue_fragment(id: &str) -> Option<String> {
    valid_issue_id(id).then(|| format!("/issues/{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: &str = "http://127.0.0.1:8765/?token=abc_DEF-123\n";

    #[test]
    fn the_services_line_is_the_sign_in_url_and_names_its_token_and_origin() {
        let d = Dashboard::parse(LIVE).unwrap();
        assert_eq!(
            d.at(None).as_str(),
            "http://127.0.0.1:8765/?token=abc_DEF-123"
        );
        assert_eq!(d.token().as_deref(), Some("abc_DEF-123"));
        assert_eq!(d.origin(), "http://127.0.0.1:8765");
        assert_eq!(
            d.at(Some("/issues/i-1")).as_str(),
            "http://127.0.0.1:8765/?token=abc_DEF-123#/issues/i-1"
        );
    }

    #[test]
    fn password_mode_has_no_token() {
        let d = Dashboard::parse("https://monitor.lan:8765/\n").unwrap();
        assert_eq!(d.token(), None);
        assert_eq!(d.origin(), "https://monitor.lan:8765");
    }

    #[test]
    fn anything_but_the_dashboards_root_url_is_refused() {
        for bad in [
            "",
            "not a url",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://127.0.0.1:8765/api/overview",
            "http://127.0.0.1:8765/#/x",
        ] {
            assert!(Dashboard::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_dashboards_own_origin_is_ours() {
        let d = Dashboard::parse(LIVE).unwrap();
        let ours = |u: &str| d.is_ours(&Url::parse(u).unwrap());
        assert!(ours("http://127.0.0.1:8765/#/issues/i-1"));
        assert!(ours("http://127.0.0.1:8765/login"));
        assert!(!ours("http://127.0.0.1:8766/"));
        assert!(!ours("https://127.0.0.1:8765/"));
        assert!(!ours("http://localhost:8765/"));
        assert!(!ours("https://example.com/"));
    }

    #[test]
    fn issue_ids_are_the_dashboards_charset_and_nothing_that_could_leave_a_string() {
        assert_eq!(
            issue_fragment("i-66d58c3c7d6e43e2").as_deref(),
            Some("/issues/i-66d58c3c7d6e43e2")
        );
        for bad in [
            "",
            "a b",
            "i-1'",
            "i-1\"",
            "x/../y",
            "i-1#x",
            "<script>",
            &"x".repeat(129),
        ] {
            assert_eq!(issue_fragment(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_file_is_read_and_one_too_large_or_missing_is_refused() {
        let dir = std::env::temp_dir().join(format!("nw-address-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(URL_FILE);
        std::fs::write(&file, LIVE).unwrap();
        assert_eq!(
            Dashboard::read(&file).unwrap(),
            Dashboard::parse(LIVE).unwrap()
        );
        std::fs::write(&file, "x".repeat(5000)).unwrap();
        assert!(Dashboard::read(&file).unwrap_err().contains("not one URL"));
        assert!(Dashboard::read(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
