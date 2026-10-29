// No console window behind the GUI on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RV Hub — Rakvor")
            .with_inner_size([860.0, 720.0])
            .with_min_inner_size([640.0, 520.0])
            .with_drag_and_drop(true),
        // wgpu falls back to a software adapter (WARP on Windows), so the GUI also runs on
        // forensic VMs without a GPU driver.
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    eframe::run_native(
        "RV Hub",
        options,
        // `--case-dir DIR` (or a folder dropped on the .exe icon) preselects the case folder.
        Box::new(|_cc| {
            Ok(Box::new(rv_hub_gui::app::HubApp::with_args(
                std::env::args_os().skip(1),
            )))
        }),
    )
}
