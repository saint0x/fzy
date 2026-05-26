use super::*;

pub(super) fn heap_folded(heap: &HeapProfile) -> Vec<FoldedStack> {
    let mut out = heap
        .hotspots
        .iter()
        .map(|h| FoldedStack {
            stack: format!("fozzy::heap;callsite::{}", h.callsite_hash),
            weight: h.alloc_bytes.max(1),
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.stack.cmp(&b.stack)));
    out
}

pub(super) fn folded_to_text(folded: &[FoldedStack]) -> String {
    if folded.is_empty() {
        return "# empty profile: no samples in trace".to_string();
    }
    let mut out = String::new();
    for row in folded {
        out.push_str(&format!("{} {}\n", row.stack, row.weight));
    }
    out.trim_end().to_string()
}

pub(super) fn folded_to_svg(folded: &[FoldedStack]) -> String {
    let width = 900;
    let bar_h = 18;
    let gap = 4;
    let max = folded.iter().map(|f| f.weight).max().unwrap_or(1) as f64;
    let height = (folded.len() as i32) * (bar_h + gap) + 40;
    let mut out = String::new();
    out.push_str(&format!(
        r#"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\">"#
    ));
    out.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#111827\"/>");
    if folded.is_empty() {
        out.push_str(
            "<text x=\"24\" y=\"36\" fill=\"#e5e7eb\" font-size=\"13\">empty profile: no samples in trace</text>",
        );
    }
    for (i, row) in folded.iter().enumerate() {
        let y = 20 + (i as i32) * (bar_h + gap);
        let w = ((row.weight as f64 / max) * 820.0).round() as i32;
        out.push_str(&format!(
            "<rect x=\"20\" y=\"{y}\" width=\"{w}\" height=\"{bar_h}\" fill=\"#2563eb\"/>"
        ));
        out.push_str(&format!(
            "<text x=\"{x}\" y=\"{ty}\" fill=\"#e5e7eb\" font-size=\"12\">{label}</text>",
            x = 24,
            ty = y + 13,
            label = escape_xml(&format!("{} ({})", row.stack, row.weight)),
        ));
    }
    out.push_str("</svg>");
    out
}

pub(super) fn folded_to_speedscope(run: &str, folded: &[FoldedStack]) -> serde_json::Value {
    let mut frames: Vec<serde_json::Value> = vec![];
    let mut frame_index = BTreeMap::<String, usize>::new();
    let mut samples = Vec::<Vec<usize>>::new();
    let mut weights = Vec::<u64>::new();

    for row in folded {
        let mut stack = Vec::<usize>::new();
        for frame in row.stack.split(';') {
            let idx = if let Some(i) = frame_index.get(frame) {
                *i
            } else {
                let i = frames.len();
                frames.push(serde_json::json!({"name": frame}));
                frame_index.insert(frame.to_string(), i);
                i
            };
            stack.push(idx);
        }
        samples.push(stack);
        weights.push(row.weight);
    }

    serde_json::json!({
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "shared": {"frames": frames},
        "profiles": [{
            "type": "sampled",
            "name": format!("fozzy profile {run}"),
            "unit": "milliseconds",
            "startValue": 0,
            "endValue": weights.iter().copied().sum::<u64>(),
            "samples": samples,
            "weights": weights,
        }],
        "activeProfileIndex": 0,
        "exporter": "fozzy",
    })
}

pub(super) fn timeline_html(events: &[ProfileEvent]) -> String {
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.t_virtual,
            e.kind,
            e.thread,
            escape_xml(&e.span_id),
            escape_xml(e.tags.get("name").map(|s| s.as_str()).unwrap_or("")),
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Fozzy Profile Timeline</title><style>body{{font-family:ui-monospace,Menlo,monospace;background:#0b1020;color:#e5e7eb;padding:20px}}table{{border-collapse:collapse;width:100%}}th,td{{padding:6px 8px;border-bottom:1px solid #1f2937;text-align:left}}</style></head><body><h1>Fozzy Profile Timeline</h1><table><thead><tr><th>t_virtual</th><th>kind</th><th>thread</th><th>span_id</th><th>name</th></tr></thead><tbody>{rows}</tbody></table></body></html>"
    )
}

pub(super) fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
