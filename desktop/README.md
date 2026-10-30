# NeonWatch desktop app

The dashboard in its own window, desktop notifications that open it at their issue, and a tray
icon coloured by the worst open severity. It sits beside the browser dashboard, not instead of
it. The window shows the service's own page, so the two look and work the same.

A [Tauri 2](https://v2.tauri.app/) app (Rust, on the system WebKitGTK). It needs the service
running. It talks to nothing else.

![The app window: the dashboard under a neon title bar that carries the open counts](../docs/images/desktop-window.png)

## Build and run

```sh
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
cd desktop
cargo build --release
target/release/neonwatch-desktop
```

Installing it as an application (its desktop entry, icons, `neonwatch://` links and autostart)
is planned and not built yet. Until then, run the binary from `target/`.

| Command | What it does |
| --- | --- |
| `neonwatch-desktop` | Open the window (or raise it, if the app is already running). |
| `neonwatch-desktop --hidden` | Start in the tray. Autostart uses this. |
| `neonwatch-desktop --issue <id>` | Open the window at one issue. |
| `neonwatch-desktop neonwatch://issue/<id>` | The same, as a link. |
| `neonwatch-desktop --notify '<json>'` | Show a notification the service hands over (see below). |

One instance runs. A later launch hands its arguments to the running one and exits.

## How it works

- **Signing in.** The service writes its URL, with its per-launch token, to
  `~/.local/state/neonwatch/dashboard.url` (0600, removed when it stops). The app reads it, so
  nobody copies a URL. When the service restarts with a new token, the app signs in again
  within 5 s and stays on the same view or issue. If the store is not in its default place,
  set `NEONWATCH_URL_FILE` to the file beside it.
- **When the service is not running,** the window shows the app's own page, with Retry and
  "Start the service" (`systemctl --user start neonwatch-service`).

  ![The app when the service is not running](../docs/images/desktop-service-down.png)
- **Notifications.** `--notify` takes the service's notification as JSON:
  `{"issue_id": "i-…" or null, "summary": "…", "body": "…", "urgency": 0|1|2}`. The app shows
  it with an **Open in NeonWatch** button and a default action, and stays connected to the
  session bus until it closes. Either one opens the window at the issue. Cinnamon closes a
  notification clicked on its body without invoking anything, which is why there is a button.
  GNOME and KDE treat a body click as the default action. The tray's "Pause notifications for
  1 hour" drops them meanwhile; the dashboard still shows every issue.

  ![A notification with its Open in NeonWatch button](../docs/images/desktop-notification.png)
- **The tray** reads `/api/overview` every 15 s:

  | Colour | Means |
  | --- | --- |
  | red | anything critical is open |
  | grey eye | the agent's heartbeat is more than 180 s old, the dashboard's own threshold |
  | yellow | warn |
  | cyan | watch |
  | green | nothing open |
  | grey with a slash | the service is down |

  ![The six tray states](../docs/images/desktop-tray-states.png)

  The window title carries the same counts. Closing the window hides it to the tray; **Quit
  NeonWatch** in the tray menu ends the app.
- **The title bar** is a GTK header bar in the dashboard's palette, in place of the window
  manager's. Dragging, resizing, double-click to maximise and snapping stay native. Window
  controls inside the page would have needed IPC. The app also asks GTK for its dark variant,
  which WebKitGTK reports to the page, so the dashboard's Auto theme is dark.

## Security

- **The dashboard gets no IPC.** No capability names it, and Tauri 2.11.1 or later puts every
  remote origin through ACL resolution. The app's own page needs no IPC either: its buttons are
  `neonwatch-action:` links that the navigation handler intercepts.
- **Only the dashboard's own origin loads in the window.** Any other web address opens in your
  browser (`xdg-open`), and nothing else loads.
- **Issue ids are checked** against the dashboard's character set (`[A-Za-z0-9._:-]`, 1 to 128
  characters) before they reach the page.
- **The window's storage is its own** (cookies, theme, folded cards), separate from your
  browser's, under `~/.local/share/io.github.drobison00.neonwatch/`.

## Limits

- **The tray's status needs the per-launch token over plain HTTP.** A dashboard in password
  mode, or one served over TLS, opens in the window, but the tray says it has no status.
- **Built and tested on Linux Mint 22 (Cinnamon 6.2, X11) with NVIDIA drivers.** WebKitGTK
  rendered with no workarounds. Other desktops are untested.

## Tests

```sh
cargo test                               # address, command line, notification and status logic
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The window, tray and notifications were checked by hand on Cinnamon:
- the page when the service is down;
- signing in;
- a second launch moving the running window to an issue;
- closing to the tray;
- a notification's button opening the window.

## Icons

`icons/make_icons.py` renders the app and tray icons (needs ImageMagick). The PNGs are committed.
