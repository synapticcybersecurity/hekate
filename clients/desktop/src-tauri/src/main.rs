// Hekate desktop — Tauri 2 shell around the SolidJS web vault.
//
// Foundation milestone (tier A): this is a thin wrapper. It loads the
// already-built SPA from `clients/web/dist` (see tauri.conf.json
// `frontendDist`) and renders it in a native window. The vault talks to
// whichever Hekate server the user configures on first run — the same
// `hekate-core` WASM crypto core as the browser build runs client-side.
//
// Deliberately no custom IPC commands yet: nothing here is exposed to
// the webview, so the IPC attack surface is empty. Touch ID unlock,
// system tray, native menu, an SSH agent (tier C), and the native
// credential provider (tier B) layer on in follow-up milestones.

// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Hekate desktop");
}
