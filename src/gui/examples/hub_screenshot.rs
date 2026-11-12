//! Renders the hub window headless (no display, no GPU) to a PNG, for the documentation:
//!
//!     cargo run -p rv-hub-gui --example hub_screenshot -- docs/images/hub-tools.png tools [en|es|fr]
//!     cargo run -p rv-hub-gui --example hub_screenshot -- docs/images/hub-case.png case [en|es|fr]
//!
//! The discovery is faked: the six Rakvor tools at their released versions (rv-hashinv 0.4.1, rv-pdfauth 0.4.1,
//! rv-rsmf 0.3.1, rv-imgauth 0.3.1, rv-certcheck 0.2.2, rv-mailauth 0.2.0, its first release), all Rakvor-signed except one unsigned portable copy of
//! rv-imgauth, to show the amber badge. The Case tab shows a copy of `examples/sample/case`. A few egui frames run, then egui's tessellated meshes are rasterised on the CPU
//! (textured triangles, premultiplied alpha), so the picture is what the window draws, minus the GPU.
#![forbid(unsafe_code)]

use eframe::egui;
use egui::epaint::{ClippedPrimitive, Color32, ImageData, Primitive, TextureId};
use rv_hub_core::launch::Spawner;
use rv_hub_core::signature::{SignatureStatus, StaticVerifier};
use rv_hub_core::tools::{APP_IDS, Source, ToolInfo};
use rv_hub_gui::app::HubApp;
use rv_hub_gui::state::{HubState, Tab, testing::preview_tool};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

/// Never starts anything (the screenshot only draws).
struct NoSpawn;
impl Spawner for NoSpawn {
    fn spawn_detached(&self, _: &Path, _: &[OsString]) -> std::io::Result<u32> {
        Err(std::io::Error::other("screenshot"))
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("folder");
    for e in std::fs::read_dir(from).expect("sample case") {
        let e = e.expect("entry");
        if e.path().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).expect("copy");
        }
    }
}

/// The six tools as a workstation with the released versions would list them. AppIds: the real ones of
/// `rv_hub_core::tools::APP_IDS`. One unsigned portable copy (rv-imgauth) shows the amber "unsigned" badge.
fn released_tools() -> Vec<ToolInfo> {
    let programs = r"C:\Users\examiner\AppData\Local\Programs\Rakvor";
    let p = |title: &str| std::path::PathBuf::from(format!("{programs}\\{title}"));
    let reg = |tool: &str| Source::Registry {
        app_id: APP_IDS
            .iter()
            .find(|k| k.tool == Some(tool))
            .map(|k| k.app_id.to_string())
            .expect("known AppId"),
    };
    let signed = SignatureStatus::SignedRakvor;
    let mut v = vec![
        preview_tool(
            &p("RV HashInv"),
            "rv-hashinv",
            signed.clone(),
            "0.4.1",
            reg("rv-hashinv"),
        ),
        preview_tool(
            &p("RV PDFAuth"),
            "rv-pdfauth",
            signed.clone(),
            "0.4.1",
            Source::LocalPrograms,
        ),
        preview_tool(
            &p("RV RSMF"),
            "rv-rsmf",
            signed.clone(),
            "0.3.1",
            reg("rv-rsmf"),
        ),
        preview_tool(
            std::path::Path::new(r"E:\rakvor-portable\rv-imgauth-0.3.1"),
            "rv-imgauth",
            SignatureStatus::Unsigned,
            "0.3.1",
            Source::UserFolder,
        ),
        preview_tool(
            &p("RV CertCheck"),
            "rv-certcheck",
            signed.clone(),
            "0.2.2",
            reg("rv-certcheck"),
        ),
        preview_tool(
            &p("RV MailAuth"),
            "rv-mailauth",
            signed,
            "0.2.0",
            reg("rv-mailauth"),
        ),
    ];
    v.sort_by(|a, b| a.tool.cmp(&b.tool));
    v
}

const W: usize = 1280;
const H: usize = 900;

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

impl Tex {
    /// Bilinear sample of premultiplied texels, clamped at the edges.
    fn sample(&self, u: f32, v: f32) -> [f32; 4] {
        let x = (u * self.w as f32 - 0.5).clamp(0.0, (self.w - 1) as f32);
        let y = (v * self.h as f32 - 0.5).clamp(0.0, (self.h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(self.w - 1), (y0 + 1).min(self.h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = self.px[y * self.w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut o = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bot = c[i] + (d[i] - c[i]) * fx;
            o[i] = (top + (bot - top) * fy) / 255.0;
        }
        o
    }
}

fn rasterise(
    prims: &[ClippedPrimitive],
    textures: &HashMap<TextureId, Tex>,
    ppp: f32,
) -> Vec<[f32; 4]> {
    let mut canvas = vec![[0.0f32, 0.0, 0.0, 1.0]; W * H];
    for p in prims {
        let Primitive::Mesh(mesh) = &p.primitive else {
            continue;
        };
        let Some(tex) = textures.get(&mesh.texture_id) else {
            continue;
        };
        let cx0 = (p.clip_rect.min.x * ppp).max(0.0).floor() as i64;
        let cy0 = (p.clip_rect.min.y * ppp).max(0.0).floor() as i64;
        let cx1 = ((p.clip_rect.max.x * ppp).ceil() as i64).min(W as i64);
        let cy1 = ((p.clip_rect.max.y * ppp).ceil() as i64).min(H as i64);
        for t in mesh.indices.chunks_exact(3) {
            let v = [
                &mesh.vertices[t[0] as usize],
                &mesh.vertices[t[1] as usize],
                &mesh.vertices[t[2] as usize],
            ];
            let pt: Vec<[f32; 2]> = v.iter().map(|v| [v.pos.x * ppp, v.pos.y * ppp]).collect();
            let area = (pt[1][0] - pt[0][0]) * (pt[2][1] - pt[0][1])
                - (pt[2][0] - pt[0][0]) * (pt[1][1] - pt[0][1]);
            if area.abs() < 1e-9 {
                continue;
            }
            let minx = pt.iter().map(|p| p[0]).fold(f32::MAX, f32::min).floor() as i64;
            let maxx = pt.iter().map(|p| p[0]).fold(f32::MIN, f32::max).ceil() as i64;
            let miny = pt.iter().map(|p| p[1]).fold(f32::MAX, f32::min).floor() as i64;
            let maxy = pt.iter().map(|p| p[1]).fold(f32::MIN, f32::max).ceil() as i64;
            for y in miny.max(cy0)..maxy.min(cy1) {
                for x in minx.max(cx0)..maxx.min(cx1) {
                    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                    let e = |a: [f32; 2], b: [f32; 2]| {
                        (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
                    };
                    let w0 = e(pt[1], pt[2]) / area;
                    let w1 = e(pt[2], pt[0]) / area;
                    let w2 = e(pt[0], pt[1]) / area;
                    if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                        continue;
                    }
                    let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                    let vv = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                    let s = tex.sample(u, vv);
                    let col = |i: usize| {
                        let c = |v: &egui::epaint::Vertex| v.color.to_array()[i] as f32 / 255.0;
                        w0 * c(v[0]) + w1 * c(v[1]) + w2 * c(v[2])
                    };
                    let src = [s[0] * col(0), s[1] * col(1), s[2] * col(2), s[3] * col(3)];
                    let d = &mut canvas[y as usize * W + x as usize];
                    for i in 0..4 {
                        d[i] = src[i] + d[i] * (1.0 - src[3]);
                    }
                }
            }
        }
    }
    canvas
}

fn main() {
    let mut args = std::env::args().skip(1);
    let target = std::path::PathBuf::from(args.next().unwrap_or_else(|| "hub.png".into()));
    let tab = args.next().unwrap_or_else(|| "tools".into());
    let ui_lang = args.next().unwrap_or_else(|| "en".into());
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tmp = std::env::temp_dir().join(format!("rv-hub-screenshot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    let mut s = HubState::new(vec![tmp.join("hub-data")], "Examiner");
    s.apply_discovery(released_tools());
    s.settings.user_folders = vec![r"E:\rakvor-portable".into()];
    if tab == "case" {
        let case = tmp.join("CASE-SAMPLE-1");
        copy_dir(&root.join("examples/sample/case"), &case);
        s.open_case(&case.display().to_string());
        s.set_tab(Tab::Case);
    }
    s.set_ui_lang(&ui_lang);
    s.notice = None;
    let verifier = StaticVerifier::always(SignatureStatus::SignedRakvor);
    let mut app = HubApp::from_parts(s, Box::new(verifier), Box::new(NoSpawn));

    let ctx = egui::Context::default();
    let mut textures: HashMap<TextureId, Tex> = HashMap::new();
    let mut last = None;
    for frame in 0..4 {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(W as f32, H as f32),
            )),
            time: Some(frame as f64 * 0.1),
            focused: true,
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw, |ui| app.draw(ui));
        for (id, deltas) in &output.textures_delta.set {
            for d in deltas {
                let ImageData::Color(img) = &d.image;
                match d.pos {
                    None => {
                        textures.insert(
                            *id,
                            Tex {
                                w: img.size[0],
                                h: img.size[1],
                                px: img.pixels.clone(),
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = textures.get_mut(id).expect("patch of a known texture");
                        for y in 0..img.size[1] {
                            for x in 0..img.size[0] {
                                t.px[(y0 + y) * t.w + x0 + x] = img.pixels[y * img.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
        // Applied above (this renderer keeps every texture until the end).
        output.textures_delta.clear();
        last = Some(output);
    }
    let output = last.expect("frames ran");
    let ppp = output.pixels_per_point;
    let prims = ctx.tessellate(output.shapes, ppp);
    let canvas = rasterise(&prims, &textures, ppp);
    let rgba: Vec<u8> = canvas
        .iter()
        .flat_map(|p| {
            let a = p[3].clamp(1e-6, 1.0);
            [p[0] / a, p[1] / a, p[2] / a, 1.0].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as u8)
        })
        .collect();
    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).expect("output folder");
    }
    let file = std::fs::File::create(&target).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), W as u32, H as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .expect("png")
        .write_image_data(&rgba)
        .expect("png data");
    println!(
        "wrote {} ({W}x{H}, {} meshes, {} audited ui actions)",
        target.display(),
        prims.len(),
        app.state().audit_trail.len()
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
