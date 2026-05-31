// Hekate desktop — Tauri 2 shell around the SolidJS web vault.
//
// Foundation milestone (tier A): this is a thin wrapper. It loads the
// already-built SPA from `clients/web/dist` (see tauri.conf.json
// `frontendDist`) and renders it in a native window. The vault talks to
// whichever Hekate server the user configures on first run — the same
// `hekate-core` WASM crypto core as the browser build runs client-side.
//
// Tier-A polish lives in Rust, not the webview: a native macOS app menu
// (so Cmd-C/V/Q and friends work) and a menu-bar tray icon that keeps the
// app resident — closing the window hides it to the tray rather than
// quitting. The IPC surface stays empty (no custom commands exposed to
// the webview); the menu and tray are driven entirely from the backend.
// Touch ID unlock (tier A), an SSH agent (tier C), and the native
// credential provider (tier B) layer on in follow-up milestones.

// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, WindowEvent,
};

/// Bring the main window back to the foreground (from the tray, the dock,
/// or a re-open). Best-effort: a missing window or a platform that refuses
/// focus is non-fatal — we never want a menu/tray click to panic.
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Hide the main window into the tray (the app keeps running).
fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

/// Native menu bar. The first submenu is the macOS application menu; the
/// Edit submenu's predefined items wire the standard clipboard/undo
/// accelerators into the webview (without them, Cmd-C/V do nothing).
fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let app_menu = Submenu::with_items(
        app,
        "Hekate",
        true,
        &[
            &PredefinedMenuItem::about(app, Some("About Hekate"), None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;

    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;

    let view_menu = Submenu::with_items(
        app,
        "View",
        true,
        &[&PredefinedMenuItem::fullscreen(app, None)?],
    )?;

    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;

    Menu::with_items(app, &[&app_menu, &edit_menu, &view_menu, &window_menu])
}

/// Menu-bar tray icon: show / hide the window plus a real quit (the window
/// close button only hides). Left-clicking the icon re-shows the window.
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let show_item = MenuItem::with_id(app, "tray-show", "Show Hekate", true, None::<&str>)?;
    let hide_item = MenuItem::with_id(app, "tray-hide", "Hide Hekate", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "tray-quit", "Quit Hekate", true, None::<&str>)?;
    let tray_menu = Menu::with_items(
        app,
        &[
            &show_item,
            &hide_item,
            &PredefinedMenuItem::separator(app)?,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id("hekate-tray")
        .tooltip("Hekate")
        .menu(&tray_menu)
        // Left-click re-opens the window; the menu is reachable via
        // right-click, the platform-conventional gesture.
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "tray-show" => show_main_window(app),
            "tray-hide" => hide_main_window(app),
            "tray-quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    // Reuse the bundled app icon for the tray. Missing icon is non-fatal —
    // the tray simply renders without one.
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle();
            let menu = build_app_menu(handle)?;
            app.set_menu(menu)?;
            build_tray(handle)?;
            Ok(())
        })
        // Closing the main window hides it to the tray instead of quitting,
        // so the app stays resident and ready. Tray "Quit" / Cmd-Q exit.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Hekate desktop")
        .run(|app, event| {
            // macOS: clicking the dock icon while the window is hidden
            // re-opens it.
            if let RunEvent::Reopen { .. } = event {
                show_main_window(app);
            }
        });
}
