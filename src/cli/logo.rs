//! The CakePass login screen: a truly 3D-rendered, spinning logo in the terminal.
//!
//! How it works (no external libraries needed):
//! 1. Every letter of "CakePass" is a 7×9 pixel font. Each pixel becomes a
//!    block with depth ("extrusion"), so the text becomes a 3D object.
//! 2. On the surfaces of those blocks we place a grid of points with a normal
//!    vector and a material: pink frosting (front), cake with a cream layer
//!    (sides) and chocolate (back).
//! 3. For every frame we rotate all points, project them with perspective
//!    onto a pixel grid (with a z-buffer), and shade them with light and shine.
//! 4. Every terminal cell shows two pixels on top of each other using the
//!    character "▀" (foreground = upper pixel, background = lower pixel), in
//!    truecolor.
//!
//! The logo only appears when the output is a color terminal. In pipes,
//! scripts and tests nothing happens. With the animation switched off
//! (`cakepass config set animation off`, `--no-animation` or
//! `CAKEPASS_NO_ANIMATION=1`) the logo is shown as a still image.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::ui;

const TEXT: &str = "CakePass";
const GLYPH_W: usize = 7;
const GLYPH_H: usize = 9;
const GAP: usize = 1;
const DEPTH: f32 = 1.3;
const FINAL_YAW: f32 = -0.20;
const FINAL_PITCH: f32 = -0.12;
const FINAL_DIST: f32 = 60.0;
const FRAME: Duration = Duration::from_millis(33);
const SPIN_SECS: f32 = 1.25;
const SHINE_SECS: f32 = 0.85;

static ANIMATION_OFF: AtomicBool = AtomicBool::new(false);

/// Turn the animation on or off (setting, `--no-animation` flag). With the
/// animation off, the logo is shown as a still image.
pub fn set_animation(on: bool) {
    ANIMATION_OFF.store(!on, Ordering::Relaxed);
}

/// Whether the animation is currently enabled.
fn animation_enabled() -> bool {
    !ANIMATION_OFF.load(Ordering::Relaxed)
        && std::env::var_os("CAKEPASS_NO_ANIMATION").is_none_or(|v| v.is_empty() || v == "0")
}

fn glyph(c: char) -> [&'static str; GLYPH_H] {
    match c {
        'C' => [
            "..#####", ".#.....", "#......", "#......", "#......", "#......", "#......", ".#.....", "..#####",
        ],
        'a' => [
            ".......", ".......", ".......", ".#####.", "......#", ".######", "#.....#", "#.....#", ".######",
        ],
        'k' => [
            "#......", "#......", "#......", "#...##.", "#..##..", "#.##...", "###....", "#..##..", "#...##.",
        ],
        'e' => [
            ".......", ".......", ".......", ".#####.", "#.....#", "#######", "#......", "#......", ".######",
        ],
        'P' => [
            "######.", "#.....#", "#.....#", "#.....#", "######.", "#......", "#......", "#......", "#......",
        ],
        's' => [
            ".......", ".......", ".......", ".######", "#......", ".#####.", "......#", "......#", "######.",
        ],
        _ => ["......."; GLYPH_H],
    }
}

/// De tekst als bitmap: `bits[y][x]`, y=0 is de bovenste rij.
fn bitmap() -> Vec<Vec<bool>> {
    let n = TEXT.chars().count();
    let width = n * GLYPH_W + (n - 1) * GAP;
    let mut bits = vec![vec![false; width]; GLYPH_H];
    for (i, c) in TEXT.chars().enumerate() {
        let x0 = i * (GLYPH_W + GAP);
        for (y, row) in glyph(c).iter().enumerate() {
            for (x, ch) in row.chars().enumerate() {
                bits[y][x0 + x] = ch == '#';
            }
        }
    }
    bits
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Material {
    /// Pink frosting, with sprinkles (index 1..=4) or without (0).
    Frosting(u8),
    /// Cake; `t` = position in the depth (0..1) for the cream layer.
    Cake(f32),
    Chocolate,
}

#[derive(Clone, Copy)]
struct Point {
    p: [f32; 3],
    n: [f32; 3],
    /// Horizontal position (0..1) for the color gradient.
    u: f32,
    mat: Material,
}

/// Simple, deterministic hash for the sprinkles.
fn hash(a: usize, b: usize, c: usize) -> u32 {
    let mut h = (a as u32).wrapping_mul(73_856_093)
        ^ (b as u32).wrapping_mul(19_349_663)
        ^ (c as u32).wrapping_mul(83_492_791);
    h ^= h >> 13;
    h = h.wrapping_mul(0x5bd1_e995);
    h ^ (h >> 15)
}

/// Build the point cloud of the 3D model. `n` = samples per unit.
fn build_points(n: usize) -> Vec<Point> {
    let bits = bitmap();
    let (h, w) = (bits.len(), bits[0].len());
    let lit = |x: isize, y: isize| -> bool {
        x >= 0 && y >= 0 && (x as usize) < w && (y as usize) < h && bits[y as usize][x as usize]
    };
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    let half = DEPTH / 2.0;
    let nd = ((DEPTH * n as f32).ceil() as usize).max(2);
    let step = |i: usize, count: usize| (i as f32 + 0.5) / count as f32;
    let mut pts = Vec::new();
    for (gy, row) in bits.iter().enumerate() {
        for (gx, &on) in row.iter().enumerate() {
            if !on {
                continue;
            }
            let x0 = gx as f32 - cx;
            let y1 = cy - gy as f32; // top of the pixel
            let u = gx as f32 / w as f32;
            for i in 0..n {
                for j in 0..n {
                    let (a, b) = (step(i, n), step(j, n));
                    let sprinkle = match hash(gx, gy, i * n + j) % 100 {
                        0..=2 => 1 + (hash(gy, gx, j) % 4) as u8,
                        _ => 0,
                    };
                    pts.push(Point {
                        p: [x0 + a, y1 - b, -half],
                        n: [0.0, 0.0, -1.0],
                        u,
                        mat: Material::Frosting(sprinkle),
                    });
                    pts.push(Point {
                        p: [x0 + a, y1 - b, half],
                        n: [0.0, 0.0, 1.0],
                        u,
                        mat: Material::Chocolate,
                    });
                }
            }
            let (ix, iy) = (gx as isize, gy as isize);
            for k in 0..nd {
                let t = step(k, nd);
                let z = -half + t * DEPTH;
                for i in 0..n {
                    let a = step(i, n);
                    if !lit(ix - 1, iy) {
                        pts.push(Point {
                            p: [x0, y1 - a, z],
                            n: [-1.0, 0.0, 0.0],
                            u,
                            mat: Material::Cake(t),
                        });
                    }
                    if !lit(ix + 1, iy) {
                        pts.push(Point {
                            p: [x0 + 1.0, y1 - a, z],
                            n: [1.0, 0.0, 0.0],
                            u,
                            mat: Material::Cake(t),
                        });
                    }
                    if !lit(ix, iy - 1) {
                        pts.push(Point { p: [x0 + a, y1, z], n: [0.0, 1.0, 0.0], u, mat: Material::Cake(t) });
                    }
                    if !lit(ix, iy + 1) {
                        pts.push(Point {
                            p: [x0 + a, y1 - 1.0, z],
                            n: [0.0, -1.0, 0.0],
                            u,
                            mat: Material::Cake(t),
                        });
                    }
                }
            }
        }
    }
    pts
}

/// Pose of the logo in a single frame.
#[derive(Clone, Copy, Debug)]
pub struct Pose {
    yaw: f32,
    pitch: f32,
    dist: f32,
    /// Position of the shine streak (in model coordinates), or no shine.
    shine: Option<f32>,
}

impl Pose {
    pub fn rest() -> Pose {
        Pose { yaw: FINAL_YAW, pitch: FINAL_PITCH, dist: FINAL_DIST, shine: None }
    }
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

/// Overshoots and springs back: gives the "wobble" at the end.
fn ease_out_back(t: f32) -> f32 {
    let c1 = 1.70158;
    let c3 = c1 + 1.0;
    1.0 + c3 * (t - 1.0).powi(3) + c1 * (t - 1.0).powi(2)
}

/// The pose at time `t` (seconds) of the animation.
fn pose_at(t: f32) -> Pose {
    if t < SPIN_SECS {
        let k = (t / SPIN_SECS).clamp(0.0, 1.0);
        Pose {
            yaw: lerp(-2.2, FINAL_YAW, ease_out_back(k)),
            pitch: lerp(-0.75, FINAL_PITCH, ease_out_cubic(k)),
            dist: lerp(150.0, FINAL_DIST, ease_out_cubic(k)),
            shine: None,
        }
    } else {
        let k = ((t - SPIN_SECS) / SHINE_SECS).clamp(0.0, 1.0);
        Pose { shine: Some(lerp(-34.0, 34.0, ease_out_cubic(k))), ..Pose::rest() }
    }
}

type Rgb = [u8; 3];

/// A rendered image: `w` × `h` pixels (h is even; 2 pixels per terminal row).
pub struct Frame {
    w: usize,
    h: usize,
    px: Vec<Option<Rgb>>,
}

#[cfg(test)]
impl Frame {
    pub fn filled(&self) -> usize {
        self.px.iter().filter(|p| p.is_some()).count()
    }
}

fn dot(a: [f32; 3], b: [f32; 3]) -> f32 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn normalize(v: [f32; 3]) -> [f32; 3] {
    let l = dot(v, v).sqrt();
    [v[0] / l, v[1] / l, v[2] / l]
}

fn rotate(v: [f32; 3], yaw: f32, pitch: f32) -> [f32; 3] {
    let (sy, cy) = yaw.sin_cos();
    let (sp, cp) = pitch.sin_cos();
    let x = v[0] * cy + v[2] * sy;
    let z = -v[0] * sy + v[2] * cy;
    let y = v[1] * cp - z * sp;
    let z = v[1] * sp + z * cp;
    [x, y, z]
}

fn mix(a: Rgb, b: Rgb, t: f32) -> [f32; 3] {
    [lerp(a[0] as f32, b[0] as f32, t), lerp(a[1] as f32, b[1] as f32, t), lerp(a[2] as f32, b[2] as f32, t)]
}

fn base_color(p: &Point) -> [f32; 3] {
    const PINK: Rgb = [255, 70, 160];
    const PEACH: Rgb = [255, 160, 205];
    const SPRINKLES: [Rgb; 4] = [[255, 244, 120], [110, 220, 255], [255, 255, 255], [160, 255, 160]];
    match p.mat {
        Material::Frosting(0) => mix(PINK, PEACH, p.u),
        Material::Frosting(s) => mix(SPRINKLES[(s as usize - 1) % 4], SPRINKLES[(s as usize - 1) % 4], 0.0),
        Material::Cake(t) if (0.40..0.60).contains(&t) => mix([255, 238, 205], [255, 238, 205], 0.0),
        Material::Cake(_) => mix([236, 176, 96], [222, 156, 80], p.u),
        Material::Chocolate => mix([112, 62, 38], [112, 62, 38], 0.0),
    }
}

/// Render one frame of `w` × `h` pixels.
fn render(points: &[Point], pose: Pose, w: usize, h: usize, scale: f32) -> Frame {
    let mut px: Vec<Option<Rgb>> = vec![None; w * h];
    let mut zbuf = vec![f32::INFINITY; w * h];
    let light = normalize([-0.35, 0.85, -0.75]);
    let half_vec = normalize([light[0], light[1], light[2] - 1.0]);
    let focal = scale * FINAL_DIST;
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    for pt in points {
        let n = rotate(pt.n, pose.yaw, pose.pitch);
        let mut p = rotate(pt.p, pose.yaw, pose.pitch);
        p[2] += pose.dist;
        if p[2] <= 1.0 || dot(n, [-p[0], -p[1], -p[2]]) <= 0.0 {
            continue; // behind the camera, or facing away from us
        }
        let sx = cx + focal * p[0] / p[2];
        let sy = cy - focal * p[1] / p[2];
        if sx < 0.0 || sy < 0.0 {
            continue;
        }
        let (ix, iy) = (sx as usize, sy as usize);
        if ix >= w || iy >= h {
            continue;
        }
        let idx = iy * w + ix;
        if p[2] >= zbuf[idx] {
            continue;
        }
        zbuf[idx] = p[2];
        let diffuse = dot(n, light).max(0.0);
        let spec = dot(n, half_vec).max(0.0).powi(28) * 0.45;
        let mut c = base_color(pt);
        let ambient = match pt.mat {
            Material::Frosting(_) => 0.50,
            Material::Cake(_) => 0.42,
            Material::Chocolate => 0.30,
        };
        let lit = ambient + (1.0 - ambient) * diffuse;
        for ch in &mut c {
            *ch = *ch * lit + 255.0 * spec;
        }
        if let (Some(s), Material::Frosting(_)) = (pose.shine, pt.mat) {
            let d = (pt.p[0] + 0.7 * pt.p[1] - s).abs();
            if d < 2.6 {
                let glow = (1.0 - d / 2.6).powi(2) * 0.85;
                for ch in &mut c {
                    *ch = lerp(*ch, 255.0, glow);
                }
            }
        }
        px[idx] = Some([c[0].min(255.0) as u8, c[1].min(255.0) as u8, c[2].min(255.0) as u8]);
    }
    Frame { w, h, px }
}

/// Color → ANSI code (truecolor or the 256-color cube).
fn color_code(c: Rgb, background: bool, truecolor: bool) -> String {
    let layer = if background { 48 } else { 38 };
    if truecolor {
        format!("\x1b[{layer};2;{};{};{}m", c[0], c[1], c[2])
    } else {
        let q = |v: u8| ((v as u16 * 5 + 127) / 255) as u8;
        format!("\x1b[{layer};5;{}m", 16 + 36 * q(c[0]) + 6 * q(c[1]) + q(c[2]))
    }
}

/// Convert a frame to terminal text (half blocks, 2 pixels per cell).
fn encode(frame: &Frame, indent: usize, truecolor: bool) -> String {
    let mut out = String::with_capacity(frame.w * frame.h * 12);
    let pad = " ".repeat(indent);
    for row in 0..frame.h / 2 {
        out.push_str(&pad);
        let (mut fg, mut bg): (Option<Rgb>, Option<Rgb>) = (None, None);
        for x in 0..frame.w {
            let top = frame.px[2 * row * frame.w + x];
            let bottom = frame.px[(2 * row + 1) * frame.w + x];
            let (glyph, want_fg, want_bg) = match (top, bottom) {
                (None, None) => (' ', fg, None),
                (Some(t), None) => ('▀', Some(t), None),
                (None, Some(b)) => ('▄', Some(b), None),
                (Some(t), Some(b)) => ('▀', Some(t), Some(b)),
            };
            if want_bg != bg {
                match want_bg {
                    Some(b) => out.push_str(&color_code(b, true, truecolor)),
                    None => out.push_str("\x1b[49m"),
                }
                bg = want_bg;
            }
            if want_fg != fg
                && let Some(f) = want_fg
            {
                out.push_str(&color_code(f, false, truecolor));
                fg = want_fg;
            }
            out.push(glyph);
        }
        out.push_str("\x1b[0m\x1b[K\n");
    }
    out
}

/// Terminal size (columns, rows) of stderr.
fn terminal_size() -> Option<(usize, usize)> {
    // SAFETY: winsize is a plain C struct that ioctl fills in.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        (libc::ioctl(2, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0)
            .then_some((ws.ws_col as usize, ws.ws_row as usize))
    }
}

fn truecolor() -> bool {
    std::env::var("COLORTERM").is_ok_and(|v| v.contains("truecolor") || v.contains("24bit"))
}

/// Whether the logo may be shown at all (only on a color terminal).
fn allowed() -> bool {
    ui::color_on_stderr()
}

/// Restore the cursor if someone presses Ctrl+C during the animation.
extern "C" fn on_interrupt(_: libc::c_int) {
    const RESTORE: &[u8] = b"\x1b[0m\x1b[?25h\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(2, RESTORE.as_ptr().cast(), RESTORE.len());
        libc::_exit(130);
    }
}

/// Dimensions: (pixels wide, pixels high, scale, indent).
fn layout(cols: usize) -> (usize, usize, f32, usize) {
    let text_w = (TEXT.chars().count() * (GLYPH_W + GAP) - GAP) as f32;
    let w = cols.saturating_sub(4).min(120);
    let scale = 0.84 * w as f32 / text_w;
    let mut h = (GLYPH_H as f32 * scale * 1.7) as usize + 4;
    h += h % 2;
    (w, h, scale, (cols - w) / 2)
}

/// Show the CakePass logo, animated if `animate` is true and the animation
/// is enabled. Does nothing if the terminal cannot do it (pipe, no color,
/// too small).
pub fn show(animate: bool) {
    if !allowed() {
        return;
    }
    let Some((cols, rows)) = terminal_size() else { return };
    if cols < 48 || rows < 14 {
        return;
    }
    let (w, h, scale, indent) = layout(cols);
    let tc = truecolor();
    let points = build_points(((scale * 1.6).ceil() as usize).clamp(2, 6));
    let mut err = std::io::stderr().lock();
    let rows_out = h / 2;

    if !animate || !animation_enabled() {
        let _ = write!(err, "\n{}", encode(&render(&points, Pose::rest(), w, h, scale), indent, tc));
        return;
    }
    // SAFETY: we install a simple, async-signal-safe handler and restore the
    // default afterwards.
    unsafe {
        libc::signal(libc::SIGINT, on_interrupt as *const () as libc::sighandler_t);
    }
    let _ = writeln!(err, "\x1b[?25l");
    let start = Instant::now();
    let total = SPIN_SECS + SHINE_SECS;
    let mut first = true;
    loop {
        let t = start.elapsed().as_secs_f32();
        let pose = if t >= total { Pose::rest() } else { pose_at(t) };
        let mut buf = String::new();
        if !first {
            buf.push_str(&format!("\x1b[{rows_out}A"));
        }
        buf.push_str(&encode(&render(&points, pose, w, h, scale), indent, tc));
        let _ = err.write_all(buf.as_bytes());
        let _ = err.flush();
        first = false;
        if t >= total {
            break;
        }
        let spent = start.elapsed().as_secs_f32() - t;
        std::thread::sleep(FRAME.saturating_sub(Duration::from_secs_f32(spent)));
    }
    let _ = write!(err, "\x1b[?25h");
    let _ = err.flush();
    // SAFETY: restore the default behavior of Ctrl+C.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}

/// A centered line below the logo.
pub fn tagline(text: &str) {
    if !allowed() {
        return;
    }
    let cols = terminal_size().map_or(80, |(c, _)| c);
    let pad = cols.saturating_sub(text.chars().count()) / 2;
    eprintln!("{}{}\n", " ".repeat(pad), ui::pink(text));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn font_is_complete() {
        for c in TEXT.chars() {
            let g = glyph(c);
            assert!(g.iter().all(|r| r.len() == GLYPH_W), "glyph {c}");
            assert!(g.iter().any(|r| r.contains('#')), "glyph {c} is empty");
        }
        let bits = bitmap();
        assert_eq!(bits.len(), GLYPH_H);
        assert_eq!(bits[0].len(), 8 * GLYPH_W + 7 * GAP);
    }

    #[test]
    fn model_and_renderer() {
        let pts = build_points(3);
        assert!(pts.len() > 2000);
        assert!(pts.iter().any(|p| matches!(p.mat, Material::Frosting(s) if s > 0)), "sprinkles");
        let (w, h, scale, _) = layout(100);
        let rest = render(&pts, Pose::rest(), w, h, scale);
        // The logo fills a good part of the image, but not all of it.
        let filled = rest.filled();
        assert!(filled > w * h / 10 && filled < w * h * 3 / 4, "filled: {filled} of {}", w * h);
        // Seen from the side it is narrow; from the front it is wide.
        let edge = render(&pts, Pose { yaw: 1.5, ..Pose::rest() }, w, h, scale);
        assert!(edge.filled() < filled / 2);
        // Shine makes pixels lighter.
        let shiny = render(&pts, Pose { shine: Some(0.0), ..Pose::rest() }, w, h, scale);
        let sum =
            |f: &Frame| f.px.iter().flatten().map(|c| c.iter().map(|&v| v as u64).sum::<u64>()).sum::<u64>();
        assert!(sum(&shiny) > sum(&rest));
    }

    #[test]
    fn animation_ends_in_rest_pose() {
        let p = pose_at(SPIN_SECS - 0.0001);
        assert!((p.yaw - FINAL_YAW).abs() < 0.01);
        assert!(pose_at(0.0).dist > pose_at(SPIN_SECS).dist, "zooms in");
        assert!(pose_at(SPIN_SECS + 0.1).shine.is_some());
        // ease_out_back overshoots (the "wobble") and ends at 1.
        assert!((0..100).any(|i| ease_out_back(i as f32 / 100.0) > 1.0));
        assert!((ease_out_back(1.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn encoding() {
        let f = Frame { w: 2, h: 2, px: vec![Some([255, 0, 0]), None, Some([0, 0, 255]), Some([0, 255, 0])] };
        let s = encode(&f, 1, true);
        assert!(s.starts_with(' '));
        assert!(s.contains("\x1b[38;2;255;0;0m") && s.contains("\x1b[48;2;0;0;255m") && s.contains('▄'));
        let s256 = encode(&f, 0, false);
        assert!(s256.contains("\x1b[38;5;196m"), "red in the 256-color cube");
    }
}
