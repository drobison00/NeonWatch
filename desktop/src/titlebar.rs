//! The window's title bar: a GTK header bar in the dashboard's neon palette, in place of the
//! window manager's. Dragging, resizing, double-click to maximise and snapping stay native; the
//! dashboard is untouched and gets no IPC (window controls inside the page would need it).
//!
//! The title is a label that follows the window's own title (GTK's stock one is cut short at a
//! fixed width), so `set_title` from any thread keeps the open counts in it without touching GTK
//! off the main thread: the label changes in the title's notify handler, on the main thread.

use gtk::prelude::*;
use tauri::WebviewWindow;

const CSS: &str = r#"
headerbar.neonwatch {
  background: #06050b;
  border: none;
  border-bottom: 1px solid #3a3062;
  box-shadow: none;
  min-height: 34px;
  padding: 0 4px 0 10px;
}
headerbar.neonwatch .neonwatch-title { color: #e8e3ff; font-weight: 600; letter-spacing: 1px; }
headerbar.neonwatch button.control {
  background: transparent; border: none; box-shadow: none; border-radius: 0;
  color: #8f88b3; min-width: 40px; min-height: 30px; padding: 0;
}
headerbar.neonwatch button.control:hover { color: #00f0ff; background: rgba(0, 240, 255, .10); }
headerbar.neonwatch button.control.close:hover { color: #06050b; background: #ff3864; }
headerbar.neonwatch button.control:active { background: rgba(0, 240, 255, .22); }
window.neonwatch decoration { border-radius: 0; box-shadow: 0 0 0 1px #3a3062, 0 6px 22px rgba(0, 0, 0, .55); }
"#;

/// Put the header bar on `window`. Call before the window is first shown: GTK takes a title bar
/// only on a window that is not yet realized.
pub fn install(window: &WebviewWindow) -> tauri::Result<()> {
    let gtk_window = window.gtk_window()?;
    if let Some(settings) = gtk::Settings::default() {
        // The dark variant for this app alone; WebKitGTK reports it to the page as
        // prefers-color-scheme: dark, so the dashboard's Auto theme matches.
        settings.set_gtk_application_prefer_dark_theme(true);
    }
    let css = gtk::CssProvider::new();
    if let Err(e) = css.load_from_data(CSS.as_bytes()) {
        eprintln!("neonwatch-desktop: title bar style: {e}");
    }
    if let Some(screen) = gtk::prelude::GtkWindowExt::screen(&gtk_window) {
        gtk::StyleContext::add_provider_for_screen(
            &screen,
            &css,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
    gtk_window.style_context().add_class("neonwatch");

    let bar = gtk::HeaderBar::new();
    bar.style_context().add_class("neonwatch");
    bar.set_show_close_button(false);
    if let Some(eye) = eye() {
        bar.pack_start(&eye);
    }
    let title = gtk::Label::new(gtk_window.title().as_deref());
    title.style_context().add_class("neonwatch-title");
    // Not ellipsized: the header bar gives an ellipsizing label only its minimum width.
    title.set_max_width_chars(96);
    bar.set_custom_title(Some(&title));
    gtk_window.connect_title_notify(move |w| title.set_text(w.title().as_deref().unwrap_or("")));
    let close = control("window-close-symbolic", "Close to the tray");
    close.style_context().add_class("close");
    let maximize = control("window-maximize-symbolic", "Maximise");
    let minimize = control("window-minimize-symbolic", "Minimise");
    // pack_end fills from the right: close, then maximise, then minimise.
    bar.pack_end(&close);
    bar.pack_end(&maximize);
    bar.pack_end(&minimize);

    let w = gtk_window.clone();
    close.connect_clicked(move |_| w.close()); // delete-event: the app hides to the tray
    let w = gtk_window.clone();
    minimize.connect_clicked(move |_| w.iconify());
    let w = gtk_window.clone();
    maximize.connect_clicked(move |_| {
        if w.is_maximized() {
            w.unmaximize()
        } else {
            w.maximize()
        }
    });
    let icon = maximize.clone();
    gtk_window.connect_window_state_event(move |_, event| {
        let maximized = event
            .new_window_state()
            .contains(gtk::gdk::WindowState::MAXIMIZED);
        let (name, tip) = if maximized {
            ("window-restore-symbolic", "Restore")
        } else {
            ("window-maximize-symbolic", "Maximise")
        };
        icon.set_image(Some(&gtk::Image::from_icon_name(
            Some(name),
            gtk::IconSize::Menu,
        )));
        icon.set_tooltip_text(Some(tip));
        gtk::glib::Propagation::Proceed
    });

    bar.show_all();
    gtk_window.set_titlebar(Some(&bar));
    Ok(())
}

fn control(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(Some(icon), gtk::IconSize::Menu);
    button.style_context().add_class("control");
    button.set_relief(gtk::ReliefStyle::None);
    button.set_tooltip_text(Some(tooltip));
    button.set_can_focus(false);
    button
}

/// The eye, from the 32 px app icon, scaled to the bar.
fn eye() -> Option<gtk::Image> {
    let loader = gtk::gdk_pixbuf::PixbufLoader::new();
    loader.write(include_bytes!("../icons/32x32.png")).ok()?;
    loader.close().ok()?;
    let pixbuf = loader
        .pixbuf()?
        .scale_simple(22, 22, gtk::gdk_pixbuf::InterpType::Bilinear)?;
    Some(gtk::Image::from_pixbuf(Some(&pixbuf)))
}
