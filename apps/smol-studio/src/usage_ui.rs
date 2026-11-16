use crate::design::{self, INK, LINE, MUTED};
use eframe::egui::{self, RichText};
use smol_studio::{
    model::Machine,
    usage::{HISTORY_WINDOW, Sample, Usage},
};
use std::time::{Duration, Instant};

pub fn show(ui: &mut egui::Ui, usage: &Usage, machine: &Machine) {
    if machine.state != "running" {
        ui.label(
            RichText::new("Resource usage is available while this machine is running.")
                .color(MUTED),
        );
        return;
    }
    let now = Instant::now();
    let last = usage.history.back();
    ui.horizontal(|ui| {
        if usage.pending() && last.is_none() {
            ui.spinner();
        }
        let status = if !usage.active {
            "Updates paused while this view is inactive".to_owned()
        } else if let Some(point) = last {
            format!(
                "Last sample {}s ago · updates while visible",
                now.saturating_duration_since(point.at).as_secs()
            )
        } else if usage.error.is_some() {
            "Waiting for resource measurements".to_owned()
        } else {
            "Measuring CPU and memory…".to_owned()
        };
        ui.label(RichText::new(status).size(11.5).color(MUTED));
    });
    if let Some(error) = &usage.error {
        ui.add_space(8.0);
        design::error_notice(
            ui,
            "Usage could not be updated. Retrying while this view is active.",
            error,
        );
    }
    ui.add_space(12.0);
    let sample = last.map(|p| &p.sample);
    ui.columns(2, |cols| {
        design::card().show(&mut cols[0], |ui| {
            ui.set_width(ui.available_width());
            let cpu = sample.and_then(|s| s.cpu_percent);
            design::metric(
                ui,
                "Machine CPU",
                &cpu.map(|v| format!("{v:.1}")).unwrap_or_else(|| "—".into()),
                if cpu.is_some() { "%" } else { "" },
            );
            let capacity = f64::from(sample.map(|s| s.cpus).unwrap_or(machine.cpus)) * 100.0;
            let peak = usage
                .history
                .iter()
                .filter_map(|p| p.sample.cpu_percent)
                .fold(capacity.max(100.0), f64::max);
            ui.add_space(10.0);
            chart(ui, usage, now, peak, &format!("{peak:.0}%"), |s| {
                s.cpu_percent
            });
            ui.add_space(8.0);
            ui.label(RichText::new("100% = one CPU core").size(11.0).color(MUTED));
            if sample.is_some() && cpu.is_none() {
                ui.label(
                    RichText::new("CPU measurement unavailable")
                        .size(11.0)
                        .color(MUTED),
                );
            }
        });
        design::card().show(&mut cols[1], |ui| {
            ui.set_width(ui.available_width());
            let memory = sample.and_then(|s| s.memory.as_ref());
            let text = memory
                .map(|m| byte_size(m.used_bytes))
                .unwrap_or_else(|| "—".into());
            let (value, unit) = text.split_once(' ').unwrap_or((&text, ""));
            design::metric(ui, "Guest memory used", value, unit);
            let max = memory.map(|m| m.total_bytes as f64).unwrap_or(1.0);
            ui.add_space(10.0);
            chart(
                ui,
                usage,
                now,
                max,
                &memory
                    .map(|m| byte_size(m.total_bytes))
                    .unwrap_or_else(|| "—".into()),
                |s| s.memory.as_ref().map(|m| m.used_bytes as f64),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    memory
                        .map(|m| format!("{} available", byte_size(m.available_bytes)))
                        .unwrap_or_else(|| "Memory measurement unavailable".into()),
                )
                .size(11.0)
                .color(MUTED),
            );
        });
    });
    ui.add_space(12.0);
    ui.label(RichText::new("CPU measures the machine’s host process. Memory is reported by Linux inside the machine; it is not host memory consumption.").size(11.5).color(MUTED));
}

fn chart(
    ui: &mut egui::Ui,
    usage: &Usage,
    now: Instant,
    max: f64,
    ceiling: &str,
    value: impl Fn(&Sample) -> Option<f64>,
) {
    ui.label(
        RichText::new(if ceiling == "—" {
            "No measurement".to_owned()
        } else {
            format!("Range: 0–{ceiling}")
        })
        .size(10.0)
        .color(MUTED),
    );
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 80.0), egui::Sense::hover());
    let plot = rect.shrink(2.0);
    let painter = ui.painter_at(rect);
    for portion in [0.0, 0.5, 1.0] {
        let y = plot.top() + portion * plot.height();
        painter.line_segment(
            [egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)],
            egui::Stroke::new(1.0, LINE),
        );
    }
    let mut previous: Option<(Instant, egui::Pos2)> = None;
    for point in &usage.history {
        let age = now.saturating_duration_since(point.at);
        if age > HISTORY_WINDOW {
            continue;
        }
        let Some(value) = value(&point.sample) else {
            previous = None;
            continue;
        };
        let position = egui::pos2(
            plot.right() - (age.as_secs_f64() / HISTORY_WINDOW.as_secs_f64()) as f32 * plot.width(),
            plot.bottom() - (value / max).clamp(0.0, 1.0) as f32 * plot.height(),
        );
        if let Some((at, before)) = previous
            && point.at.saturating_duration_since(at) <= Duration::from_secs(15)
        {
            painter.line_segment([before, position], egui::Stroke::new(1.5, INK));
        }
        painter.circle_filled(position, 1.8, INK);
        previous = Some((point.at, position));
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("5m ago").size(10.0).color(MUTED));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new("Now").size(10.0).color(MUTED));
        });
    });
}

fn byte_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / 1073741824.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / 1048576.0)
    }
}
