//! NeonWatch on the desktop: the dashboard in its own window, desktop notifications that open it at
//! their issue, and a tray icon coloured by the worst open severity.
//!
//! The window shows the service's own dashboard, so it looks and works exactly as it does in a
//! browser. The app reads where it is, token included, from the `dashboard.url` the service writes
//! (0600, removed when the service stops), signs in again when the service restarts with a new
//! token, and shows its own page while the service is not running. The dashboard gets no IPC: no
//! capability names it, and the app's page needs none, since its buttons are `neonwatch-action:`
//! links the navigation handler intercepts. Anything off the dashboard opens in the browser.
//!
//! One instance runs; a later launch hands its arguments over and exits, which is how the service
//! delivers a notification (`--notify JSON`) and how a `neonwatch://issue/<id>` link opens.

pub mod address;
pub mod cli;
pub mod notice;
pub mod status;
#[cfg(target_os = "linux")]
mod titlebar;

use address::Dashboard;
use cli::{Launch, Request};
use status::Status;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{
    AppHandle, Manager, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent, Wry,
};
use tauri_plugin_window_state::StateFlags;

const MAIN: &str = "main";
const TRAY: &str = "neonwatch";
/// How often the service's file is checked, and how many checks between status reads.
const POLL: Duration = Duration::from_secs(5);
const STATUS_EVERY: u32 = 3;
const PAUSE: Duration = Duration::from_secs(3600);
/// How long "Start the service" waits for the dashboard to answer.
const START_WAIT: Duration = Duration::from_secs(20);
/// The scheme of the app page's buttons, handled here and never loaded.
const ACTION: &str = "neonwatch-action";

#[derive(Default)]
struct Shared {
    /// The dashboard as last found: announced in the service's file and answering.
    dashboard: Mutex<Option<Dashboard>>,
    /// The dashboard the window last signed in to.
    signed_in: Mutex<Option<Dashboard>>,
    /// Where to go once the dashboard can be reached: an issue asked for while it could not.
    wanted: Mutex<Option<String>>,
    /// Notifications are dropped until then.
    paused_until: Mutex<Option<Instant>>,
    pause_item: Mutex<Option<MenuItem<Wry>>>,
    /// One sync at a time: the watcher and the page's buttons both start one.
    syncing: Mutex<()>,
}

fn log(message: impl std::fmt::Display) {
    eprintln!("neonwatch-desktop: {message}");
}

/// Run the app. Arguments it cannot parse end it with the usage, before any window.
pub fn run() {
    let argv: Vec<String> = std::env::args().collect();
    let launch = match cli::parse(&argv) {
        Ok(launch) => launch,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            |app, argv, _cwd| match cli::parse(&argv) {
                Ok(Launch {
                    request: Request::Show,
                    ..
                }) => open(app, None),
                Ok(launch) => handle(app, launch.request),
                Err(message) => log(format!("ignored a launch: {message}")),
            },
        ))
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(StateFlags::all() & !StateFlags::VISIBLE)
                .build(),
        )
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close(); // to the tray; "Quit NeonWatch" there ends the app
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            app.manage(Shared::default());
            let handle = app.handle().clone();
            build_window(&handle, !launch.hidden)?;
            build_tray(&handle)?;
            let watcher = handle.clone();
            std::thread::spawn(move || watch(&watcher));
            self::handle(&handle, launch.request);
            Ok(())
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        log(format!("cannot start: {e}"));
        std::process::exit(1);
    }
}

fn handle(app: &AppHandle, request: Request) {
    match request {
        Request::Show => {}
        Request::Issue(id) => open(app, Some(id)),
        Request::Notify(notice) => {
            let shared = app.state::<Shared>();
            let paused = shared
                .paused_until
                .lock()
                .unwrap()
                .is_some_and(|t| Instant::now() < t);
            if paused {
                log(format!(
                    "notifications are paused; not shown: {}",
                    notice.summary
                ));
                return;
            }
            let app = app.clone();
            notice.show(move |issue| open(&app, issue));
        }
    }
}

// --- the window ----------------------------------------------------------------------------

fn build_window(app: &AppHandle, visible: bool) -> tauri::Result<WebviewWindow> {
    let navigating = app.clone();
    // Built hidden whatever `visible` says: GTK takes the title bar only before the first show.
    let window = WebviewWindowBuilder::new(app, MAIN, WebviewUrl::App("index.html".into()))
        .title("NeonWatch")
        .inner_size(1440.0, 900.0)
        .min_inner_size(900.0, 600.0)
        .visible(false)
        .zoom_hotkeys_enabled(true)
        .on_navigation(move |url| allow(&navigating, url))
        .build()?;
    #[cfg(target_os = "linux")]
    if let Err(e) = titlebar::install(&window) {
        log(format!("the window keeps the system title bar: {e}"));
    }
    if visible {
        window.show()?;
    }
    Ok(window)
}

/// The navigation policy: the app's page and the dashboard load here; the page's buttons act;
/// any other web address opens in the browser; nothing else loads.
fn allow(app: &AppHandle, url: &Url) -> bool {
    match url.scheme() {
        ACTION => {
            let (app, action) = (app.clone(), url.host_str().unwrap_or("").to_string());
            std::thread::spawn(move || act(&app, &action));
            false
        }
        "tauri" => true,
        "http" | "https" => {
            let shared = app.state::<Shared>();
            let ours = shared
                .dashboard
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|d| d.is_ours(url));
            if !ours {
                if let Err(e) = Command::new("xdg-open").arg(url.as_str()).spawn() {
                    log(format!("cannot open {url} in the browser: {e}"));
                }
            }
            ours
        }
        _ => false,
    }
}

/// Show the window, at an issue if one is given.
fn open(app: &AppHandle, issue: Option<String>) {
    let Some(window) = app.get_webview_window(MAIN) else {
        return;
    };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    let Some(fragment) = issue.as_deref().and_then(address::issue_fragment) else {
        return;
    };
    let shared = app.state::<Shared>();
    let current = shared.dashboard.lock().unwrap().clone();
    let signed_in = shared.signed_in.lock().unwrap().clone();
    let on_it = window
        .url()
        .is_ok_and(|u| current.as_ref().is_some_and(|d| d.is_ours(&u)));
    if on_it && current.is_some() && current == signed_in {
        // Signed in already: move within the page; no reload, no new sign-in.
        let hash = serde_json::to_string(&format!("#{fragment}")).expect("a string");
        if let Err(e) = window.eval(format!("location.hash = {hash}")) {
            log(format!("cannot open the issue: {e}"));
        }
        return;
    }
    *shared.wanted.lock().unwrap() = Some(fragment);
    let app = app.clone();
    std::thread::spawn(move || sync(&app, true));
}

/// The app's own page in one of its states.
fn page(state: &str, reason: &str) -> Url {
    let mut url = Url::parse("tauri://localhost/index.html").expect("a constant");
    url.query_pairs_mut()
        .append_pair("state", state)
        .append_pair("reason", reason);
    url
}

fn on_page(window: &WebviewWindow) -> bool {
    window.url().is_ok_and(|u| u.scheme() == "tauri")
}

// --- following the service -------------------------------------------------------------------

/// The dashboard the service announces, if it answers.
fn find() -> Result<Dashboard, String> {
    let path = address::url_file().ok_or("no HOME to find the service's dashboard.url in")?;
    let dashboard = Dashboard::read(&path).map_err(|e| match std::fs::metadata(&path) {
        Err(_) => format!(
            "{} does not exist: the service is not running",
            path.display()
        ),
        Ok(_) => format!("{}: {e}", path.display()),
    })?;
    let at = dashboard.at(None);
    let addrs = at
        .socket_addrs(|| None)
        .map_err(|e| format!("{}: {e}", dashboard.origin()))?;
    let answers = addrs
        .iter()
        .flat_map(|a| a.to_socket_addrs().into_iter().flatten())
        .any(|a| TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok());
    if !answers {
        return Err(format!(
            "nothing answers at {} (a stale dashboard.url?)",
            dashboard.origin()
        ));
    }
    Ok(dashboard)
}

/// Bring the window in line with the service: sign in when it appears or restarts with a new
/// token (staying on the same view or issue), show the app's page while it cannot be reached.
/// `force` signs in even when nothing changed (a wanted issue, or the Retry button).
fn sync(app: &AppHandle, force: bool) {
    let shared = app.state::<Shared>();
    let _one = shared.syncing.lock().unwrap();
    let Some(window) = app.get_webview_window(MAIN) else {
        return;
    };
    let found = find();
    let previous = std::mem::replace(&mut *shared.dashboard.lock().unwrap(), found.clone().ok());
    match found {
        Ok(dashboard) => {
            let changed = previous.as_ref() != Some(&dashboard);
            if !(force || changed || on_page(&window)) {
                return;
            }
            let here = window
                .url()
                .ok()
                .filter(|u| previous.as_ref().is_some_and(|p| p.is_ours(u)));
            let fragment = shared
                .wanted
                .lock()
                .unwrap()
                .take()
                .or_else(|| here.and_then(|u| u.fragment().map(String::from)));
            *shared.signed_in.lock().unwrap() = Some(dashboard.clone());
            if let Err(e) = window.navigate(dashboard.at(fragment.as_deref())) {
                log(format!("cannot open the dashboard: {e}"));
            }
        }
        Err(reason) => {
            // On the dashboard, its own status line says it lost the service; leave it there.
            let showing = window.url().ok().filter(|u| u.scheme() == "tauri");
            let same = showing
                .as_ref()
                .is_some_and(|u| u.query_pairs().any(|(k, v)| k == "reason" && v == reason));
            if showing.is_some() && !same {
                let _ = window.navigate(page("down", &reason));
            }
        }
    }
}

/// The app page's buttons.
fn act(app: &AppHandle, action: &str) {
    match action {
        "retry" => sync(app, true),
        "start-service" => {
            if let Some(window) = app.get_webview_window(MAIN) {
                let _ = window.navigate(page("starting", ""));
            }
            let started = Command::new("systemctl")
                .args(["--user", "start", "neonwatch-service"])
                .output();
            let failed = match started {
                Ok(out) if out.status.success() => None,
                Ok(out) => Some(String::from_utf8_lossy(&out.stderr).trim().to_string()),
                Err(e) => Some(e.to_string()),
            };
            if let Some(why) = failed {
                if let Some(window) = app.get_webview_window(MAIN) {
                    let reason = format!("systemctl --user start neonwatch-service failed: {why}");
                    let _ = window.navigate(page("down", &reason));
                }
                return;
            }
            let until = Instant::now() + START_WAIT;
            while Instant::now() < until && find().is_err() {
                std::thread::sleep(Duration::from_millis(500));
            }
            sync(app, true);
        }
        other => log(format!("ignored an unknown action {other:?}")),
    }
}

/// Every `POLL`: follow the service's file; every `STATUS_EVERY` polls (and on a change), read
/// the overview for the tray and the window title.
fn watch(app: &AppHandle) {
    let mut tick = 0;
    let mut last: Option<Dashboard> = None;
    loop {
        sync(app, false);
        let current = app.state::<Shared>().dashboard.lock().unwrap().clone();
        if tick % STATUS_EVERY == 0 || current != last {
            let status = match &current {
                None => Status::down("the service is not running"),
                Some(d) => status::fetch(&d.origin(), d.token().as_deref()),
            };
            show_status(app, &status);
            last = current;
        }
        tick += 1;
        std::thread::sleep(POLL);
    }
}

// --- the tray --------------------------------------------------------------------------------

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open_item = MenuItem::with_id(app, "open", "Open NeonWatch", true, None::<&str>)?;
    let pause = MenuItem::with_id(
        app,
        "pause",
        "Pause notifications for 1 hour",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit NeonWatch", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open_item,
            &pause,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    *app.state::<Shared>().pause_item.lock().unwrap() = Some(pause);
    TrayIconBuilder::with_id(TRAY)
        .icon(Image::from_bytes(status::Level::Down.icon())?)
        .tooltip("NeonWatch: connecting")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => open(app, None),
            "pause" => toggle_pause(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn toggle_pause(app: &AppHandle) {
    let shared = app.state::<Shared>();
    let mut until = shared.paused_until.lock().unwrap();
    let paused = until.is_some_and(|t| Instant::now() < t);
    *until = if paused {
        None
    } else {
        Some(Instant::now() + PAUSE)
    };
    drop(until);
    label_pause(app);
}

fn label_pause(app: &AppHandle) {
    let shared = app.state::<Shared>();
    let left = shared
        .paused_until
        .lock()
        .unwrap()
        .and_then(|t| t.checked_duration_since(Instant::now()));
    let text = match left {
        Some(left) => format!(
            "Resume notifications (paused, {} min left)",
            left.as_secs().div_ceil(60)
        ),
        None => "Pause notifications for 1 hour".to_string(),
    };
    let item = shared.pause_item.lock().unwrap().clone();
    if let Some(item) = item {
        let _ = item.set_text(text);
    }
}

fn show_status(app: &AppHandle, status: &Status) {
    if let Some(tray) = app.tray_by_id(TRAY) {
        match Image::from_bytes(status.level.icon()) {
            Ok(icon) => {
                let _ = tray.set_icon(Some(icon));
            }
            Err(e) => log(format!("tray icon: {e}")),
        }
        let _ = tray.set_tooltip(Some(&status.summary));
    }
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.set_title(&status.title);
    }
    label_pause(app);
}
