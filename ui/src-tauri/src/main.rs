// Tauri desktop entry — hides the console window in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    khaos_c2_lib::run();
}