// The release build is a desktop app; no console window on platforms that have one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    neonwatch_desktop::run()
}
