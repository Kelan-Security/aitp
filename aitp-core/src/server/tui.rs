//! Ratatui-based terminal UI for the AITP server.
//!
//! Layout (vertical):
//! ```text
//! ┌─── header ──────────────────────────────────── 3 rows ─┐
//! ├─── main (horizontal split) ─────────────────── flex ───┤
//! │  clients 30% │ live log 70%                            │
//! ├─── alerts ──────────────────────────────────── 9 rows ─┤
//! └─── stats bar ───────────────────────────────── 3 rows ─┘
//! ```

use super::state::{AlertEntry, ConnectedClient, LogEntry, LogLevel, ServerState};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::Stdout;

// ────────────────────────── Color palette ──────────────────────────

fn level_color(level: &LogLevel) -> Color {
    match level {
        LogLevel::Ok => Color::Green,
        LogLevel::Info => Color::Cyan,
        LogLevel::Warn => Color::Yellow,
        LogLevel::Alert => Color::Red,
        LogLevel::Trust => Color::Magenta,
        LogLevel::Intent => Color::Blue,
        LogLevel::Sys => Color::DarkGray,
    }
}

// ────────────────────────── Pane renderers ──────────────────────────

pub fn render_header(
    f: &mut Frame,
    area: Rect,
    listen_addr: &str,
    identity_hex: &str,
    mode: &str,
    ebpf_active: bool,
) {
    let ebpf_str = if ebpf_active {
        "eBPF: ●ACTIVE"
    } else {
        "eBPF: ○OFF"
    };
    let title = format!(" AITP SERVER v0.2.0              ● LISTENING  {listen_addr}/UDP");
    let sub = format!(" identity: {identity_hex:.16}…    {mode}   {ebpf_str}");
    let text = vec![
        Line::from(vec![Span::styled(
            &title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            &sub,
            Style::default().fg(Color::DarkGray),
        )]),
    ];
    let para = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(para, area);
}

pub fn render_clients(f: &mut Frame, area: Rect, state: &ServerState) {
    let client_count = state.clients.len();

    // Eagerly collect into an owned Vec to avoid holding a DashMap ref-guard
    // across the ListItem iterator, which would fail the borrow checker.
    let clients: Vec<ConnectedClient> = state.clients.iter().map(|e| e.value().clone()).collect();

    let items: Vec<ListItem> = clients
        .iter()
        .map(|c| {
            let trust_color = match c.trust_score {
                185..=255 => Color::Green,
                128..=184 => Color::Yellow,
                64..=127 => Color::Rgb(255, 165, 0),
                _ => Color::Red,
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("● ", Style::default().fg(Color::Green)),
                    Span::styled(
                        c.display_name.clone(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        c.peer_addr.to_string(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  trust: "),
                    Span::styled(
                        c.trust_score.to_string(),
                        Style::default()
                            .fg(trust_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(c.trust_label(), Style::default().fg(trust_color)),
                ]),
                Line::from(vec![
                    Span::raw("  intent: "),
                    Span::styled(c.intent.as_str(), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(Span::raw("")), // spacer
            ])
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(format!(" CONNECTED CLIENTS ({client_count}) "))
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(list, area);
}

pub fn render_log(f: &mut Frame, area: Rect, state: &ServerState) {
    let log = match state.log.read() {
        Ok(l) => l,
        Err(_) => return,
    };

    let visible = area.height.saturating_sub(2) as usize; // 2 for borders
    let items: Vec<ListItem> = log
        .iter()
        .rev()
        .take(visible)
        .map(|entry: &LogEntry| {
            let ts = entry.timestamp.format("%H:%M:%S%.3f").to_string();
            let color = level_color(&entry.level);
            let level_str = entry.level.as_str();

            let mut spans = vec![
                Span::styled(ts + " ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    level_str,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::raw(entry.message.clone()),
            ];

            // Append first metadata pair inline if present.
            if let Some((k, v)) = entry.metadata.iter().next() {
                spans.push(Span::styled(
                    format!("  {k}={v}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" LIVE SESSION LOG ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(list, area);
}

pub fn render_alerts(f: &mut Frame, area: Rect, state: &ServerState) {
    let alerts = match state.alerts.read() {
        Ok(a) => a,
        Err(_) => return,
    };

    if let Some(latest) = alerts.last() {
        render_alert_box(f, area, latest);
    } else {
        let para = Paragraph::new("  No alerts. All systems nominal. ✓")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" SECURITY ALERTS "),
            );
        f.render_widget(para, area);
    }
}

fn render_alert_box(f: &mut Frame, area: Rect, alert: &AlertEntry) {
    let ts = alert.timestamp.format("%H:%M:%S%.3f").to_string();
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "⚠  ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(&ts, Style::default().fg(Color::Yellow)),
            Span::raw("   "),
            Span::styled(
                format!("[attempt #{}]", alert.occurrence_count),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![Span::styled(
            alert.alert_type.as_str(),
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD | Modifier::SLOW_BLINK),
        )]),
        Line::from(vec![]),
        Line::from(vec![
            Span::styled("source_ip: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                alert.source_ip.to_string(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("detail:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(&alert.detail, Style::default().fg(Color::White)),
        ]),
    ];
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(" ⚠ SECURITY ALERT ")
                .title_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

pub fn render_stats(f: &mut Frame, area: Rect, state: &ServerState) {
    use std::sync::atomic::Ordering;
    let sessions = state.stats.active_sessions.load(Ordering::Relaxed);
    let avg_trust = state.stats.avg_trust();
    let blocked = state.stats.blocked_packets.load(Ordering::Relaxed);
    let alerts = state.stats.alert_count.load(Ordering::Relaxed);

    let trust_color = match avg_trust {
        185..=255 => Color::Green,
        128..=184 => Color::Yellow,
        _ => Color::Red,
    };

    let line = Line::from(vec![
        Span::raw("  Sessions: "),
        Span::styled(
            sessions.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   Avg Trust: "),
        Span::styled(
            avg_trust.to_string(),
            Style::default()
                .fg(trust_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   Blocked: "),
        Span::styled(
            blocked.to_string(),
            Style::default().fg(if blocked > 0 {
                Color::Yellow
            } else {
                Color::Green
            }),
        ),
        Span::raw("   Alerts: "),
        Span::styled(
            alerts.to_string(),
            Style::default().fg(if alerts > 0 { Color::Red } else { Color::Green }),
        ),
        Span::raw("   "),
        Span::styled("[q] quit", Style::default().fg(Color::DarkGray)),
    ]);

    let para = Paragraph::new(line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .alignment(Alignment::Left);
    f.render_widget(para, area);
}

// ────────────────────────── Full frame draw ──────────────────────────

/// Draw the full server TUI frame.
pub fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &ServerState,
    listen_addr: &str,
    identity_hex: &str,
    mode: &str,
    ebpf_active: bool,
) -> std::io::Result<()> {
    terminal.draw(|f| {
        let size = f.area();

        // Vertical split: header | main | alerts | stats
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // header
                Constraint::Min(8),    // main content
                Constraint::Length(9), // alert box
                Constraint::Length(3), // stats bar
            ])
            .split(size);

        render_header(f, chunks[0], listen_addr, identity_hex, mode, ebpf_active);

        // Horizontal split: clients | log
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(chunks[1]);

        render_clients(f, main_chunks[0], state);
        render_log(f, main_chunks[1], state);
        render_alerts(f, chunks[2], state);
        render_stats(f, chunks[3], state);
    })?;
    Ok(())
}
