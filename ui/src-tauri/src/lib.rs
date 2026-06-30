use discord_rich_presence::{activity, DiscordIpc, DiscordIpcClient};
use std::process::{Child, Command};
use std::sync::Mutex;

const DISCORD_APP_ID: &str = "1504801899222794282";

static SERVER: Mutex<Option<Child>> = Mutex::new(None);

fn start_server() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();

    #[cfg(target_os = "windows")]
    let server_exe = exe_dir.join("khaos-server.exe");
    #[cfg(not(target_os = "windows"))]
    let server_exe = exe_dir.join("khaos-server");

    if !server_exe.exists() {
        return;
    }

    match Command::new(&server_exe).spawn() {
        Ok(child) => { *SERVER.lock().unwrap() = Some(child); }
        Err(e)    => { eprintln!("[KHAOS] Failed to start server: {e}"); }
    }
}

fn stop_server() {
    if let Ok(mut g) = SERVER.lock() {
        if let Some(mut child) = g.take() {
            let _ = child.kill();
        }
    }
}

fn start_discord_rpc() {
    std::thread::spawn(|| {
        let mut client = DiscordIpcClient::new(DISCORD_APP_ID);

        // Retry connect loop (Discord peut ne pas être lancé tout de suite)
        loop {
            if client.connect().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let activity = activity::Activity::new()
            .state("github.com/khaos-c2")
            .details("KHAOS Framework")
            .timestamps(activity::Timestamps::new().start(now))
            .assets(
                activity::Assets::new()
                    .large_image("khaos_logo")
                    .large_text("KHAOS C2 — Red Team Framework")
                    .small_image("khaos_logo")
                    .small_text("v1.0"),
            );

        let _ = client.set_activity(activity);

        // Maintenir la connexion RPC vivante
        loop {
            std::thread::sleep(std::time::Duration::from_secs(15));
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    start_discord_rpc();
    start_server();

    tauri::Builder::default()
        .on_window_event(|_window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                stop_server();
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to start KHAOS C2");
}
