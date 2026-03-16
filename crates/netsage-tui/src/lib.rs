use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap, Gauge, Sparkline},
    Terminal,
};
use std::io;
use tui_textarea::TextArea;
use tokio::sync::mpsc;
use std::time::Duration;
use netsage_capture::topology::SharedTopology;
use netsage_agent::Persona;

#[derive(Debug, Clone)]
pub enum TuiEvent {
    Input(String),
    AgentResponse(String),
    TextDelta(String),
    PacketUpdate(String),
    ThroughputUpdate(f64),
    AgentThinking(bool),
    ExportRequested,
    PersonaUpdate(Persona),
    MermaidRequested,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum View {
    Dashboard,
    Packets,
    Topology,
    Logs,
    History,
    Scanner,
}

pub struct App<'a> {
    pub textarea: TextArea<'a>,
    pub messages: Vec<String>,
    pub packets: Vec<String>,
    pub logs: Vec<String>,
    pub mode: String,
    pub current_view: View,
    pub topology: Option<SharedTopology>,
    pub scan_results: Vec<String>,
    pub interface: String,
    pub throughput: f64,
    pub throughput_history: Vec<u64>,
    pub is_thinking: bool,
}

impl<'a> App<'a> {
    pub fn new(topology: Option<SharedTopology>) -> App<'a> {
        let mut textarea = TextArea::default();
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Investigation Prompt ")
                .border_style(Style::default().fg(Color::Cyan)),
        );
        textarea.set_cursor_line_style(Style::default());
        textarea.set_placeholder_text("Ask NetSage anything... (e.g. 'Why is latency high?')");

        App {
            textarea,
            messages: vec!["NetSage Agent: System online. Waiting for network intelligence requests...".to_string()],
            packets: vec!["[PCAP] Listening for traffic...".to_string()],
            logs: vec!["[INFO] NetSage initialization complete.".to_string()],
            mode: "SUPERVISED".to_string(),
            current_view: View::Dashboard,
            topology,
            scan_results: vec!["No active scans.".to_string()],
            interface: "eth0".to_string(),
            throughput: 45.2,
            throughput_history: vec![0; 50],
            is_thinking: false,
        }
    }

    pub fn handle_command(&mut self, cmd: String) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() { return; }

        match parts[0] {
            "/clear" => {
                self.messages.clear();
                self.messages.push("History cleared.".to_string());
            }
            "/mode" if parts.len() > 1 => {
                self.mode = parts[1].to_uppercase();
                self.messages.push(format!("System: Approval mode changed to {}", self.mode));
            }
            "/capture" if parts.len() > 1 => {
                self.interface = parts[1].to_string();
                self.messages.push(format!("System: Capturing on interface {}", self.interface));
            }
            "/topology" => self.current_view = View::Topology,
            "/export" => {
                self.messages.push("System: Exporting session report...".to_string());
                // We'll let the main loop handle the actual IO
            }
            "/persona" => {
                self.messages.push("System: Usage: /persona [general|netops|secops|sre]".to_string());
            }
            "/persona general" => {
                self.messages.push("System: Switching to General Persona".to_string());
            }
            "/persona netops" => {
                self.messages.push("System: Switching to NetOps Persona".to_string());
            }
            "/persona secops" => {
                self.messages.push("System: Switching to SecOps Persona".to_string());
            }
            "/persona sre" => {
                self.messages.push("System: Switching to SRE Persona".to_string());
            }
            "/mermaid" => {
                self.messages.push("System: Generating Mermaid diagram...".to_string());
            }
            _ => self.messages.push(format!("You: {}", cmd)),
        }
    }
}

pub async fn run_tui(mut rx: mpsc::Receiver<TuiEvent>, tx: mpsc::Sender<TuiEvent>, topology: Option<SharedTopology>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new(topology);
    let res = run_app(&mut terminal, app, &mut rx, tx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App<'_>,
    rx: &mut mpsc::Receiver<TuiEvent>,
    tx: mpsc::Sender<TuiEvent>,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), 
                    Constraint::Min(10),   
                    Constraint::Length(5), 
                ])
                .split(f.area());

            let bg_color = match app.mode.as_str() {
                "AUTONOMOUS" => Color::Red,
                "SUPERVISED" => Color::Yellow,
                _ => Color::Green,
            };
            let fg_color = if bg_color == Color::Yellow { Color::Black } else { Color::White };

            let header = Paragraph::new(Line::from(vec![
                Span::styled(" NETSAGE ", Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD)),
                Span::raw(" | "),
                Span::styled(format!(" MODE: {} ", app.mode), Style::default().bg(bg_color).fg(fg_color).add_modifier(Modifier::BOLD)),
                Span::raw(" | "),
                Span::styled(format!(" IFACE: {} ", app.interface), Style::default().fg(Color::Cyan)),
                Span::raw(" | "),
                Span::styled(format!(" VIEW: {:?} ", app.current_view), Style::default().fg(Color::White)),
                if app.is_thinking {
                    Span::styled(" [THINKING...]", Style::default().fg(Color::Magenta).add_modifier(Modifier::ITALIC))
                } else {
                    Span::raw("")
                }
            ]))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
            f.render_widget(header, root[0]);

            match app.current_view {
                View::Dashboard => render_dashboard(f, root[1], &app),
                View::Packets => render_packets(f, root[1], &app),
                View::Topology => render_topology(f, root[1], &app),
                View::Logs => render_logs(f, root[1], &app),
                View::Scanner => render_scanner(f, root[1], &app),
                View::History => render_history(f, root[1], &app),
            }

            f.render_widget(&app.textarea, root[2]);
        })?;

        let event_ready = event::poll(Duration::from_millis(10))?;

        tokio::select! {
            res = async {
                if event_ready {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok::<bool, io::Error>(true),
                            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::Dashboard,
                            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::Packets,
                            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::Topology,
                            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::Logs,
                            KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::History,
                            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => app.current_view = View::Scanner,
                            
                            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                                let lines: Vec<String> = app.textarea.lines().iter().cloned().collect();
                                let cmd = lines.join(" ").trim().to_string();
                                if !cmd.is_empty() {
                                    if cmd.starts_with('/') {
                                        app.handle_command(cmd.clone());
                                        if cmd == "/export" {
                                            let _ = tx.send(TuiEvent::ExportRequested).await;
                                        } else if cmd == "/persona general" {
                                            let _ = tx.send(TuiEvent::PersonaUpdate(Persona::General)).await;
                                        } else if cmd == "/persona netops" {
                                            let _ = tx.send(TuiEvent::PersonaUpdate(Persona::NetOps)).await;
                                        } else if cmd == "/persona secops" {
                                            let _ = tx.send(TuiEvent::PersonaUpdate(Persona::SecOps)).await;
                                        } else if cmd == "/persona sre" {
                                            let _ = tx.send(TuiEvent::PersonaUpdate(Persona::SRE)).await;
                                        } else if cmd == "/mermaid" {
                                            let _ = tx.send(TuiEvent::MermaidRequested).await;
                                        }
                                    } else {
                                        app.messages.push(format!("You: {}", cmd));
                                        let _ = tx.send(TuiEvent::Input(cmd)).await;
                                    }
                                    let mut next_textarea = TextArea::default();
                                    next_textarea.set_block(Block::default().borders(Borders::ALL).title(" Investigation Prompt ").border_style(Style::default().fg(Color::Cyan)));
                                    next_textarea.set_placeholder_text("Ask NetSage anything...");
                                    app.textarea = next_textarea;
                                }
                            }
                            _ => {
                                app.textarea.input(key);
                            }
                        }
                    }
                }
                Ok(false)
            } => {
                if res? { return Ok(()); }
            }

            Some(msg) = rx.recv() => {
                match msg {
                    TuiEvent::AgentResponse(res) => {
                        app.messages.push(format!("NetSage Agent: {}", res));
                    }
                    TuiEvent::TextDelta(delta) => {
                        if let Some(last) = app.messages.last_mut() {
                            if last.starts_with("NetSage Agent:") {
                                last.push_str(&delta);
                            } else {
                                app.messages.push(format!("NetSage Agent: {}", delta));
                            }
                        } else {
                            app.messages.push(format!("NetSage Agent: {}", delta));
                        }
                    }
                    TuiEvent::PacketUpdate(p) => {
                        app.packets.push(p);
                        if app.packets.len() > 100 { app.packets.remove(0); }
                    }
                    TuiEvent::ThroughputUpdate(val) => {
                        app.throughput = val;
                        app.throughput_history.push(val as u64);
                        if app.throughput_history.len() > 50 { app.throughput_history.remove(0); }
                    }
                    TuiEvent::AgentThinking(val) => {
                        app.is_thinking = val;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn render_dashboard(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let items: Vec<ListItem> = app.messages.iter().map(|m| {
        let style = if m.starts_with("NetSage Agent:") { Style::default().fg(Color::Magenta) } 
                    else if m.starts_with("System:") { Style::default().fg(Color::Cyan) }
                    else { Style::default().fg(Color::White) };
        ListItem::new(m.as_str()).style(style)
    }).collect();
    
    let chat = List::new(items).block(Block::default().borders(Borders::ALL).title(" Investigation Trace ").border_style(Style::default().fg(Color::Blue)));
    f.render_widget(chat, layout[0]);

    let sidebar = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), 
            Constraint::Length(3), 
            Constraint::Length(4),
            Constraint::Min(5)
        ])
        .split(layout[1]);

    let throughput_gauge = Gauge::default()
        .block(Block::default().title(" Throughput (Mbps) ").borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
        .gauge_style(Style::default().fg(Color::Yellow).bg(Color::Black).add_modifier(Modifier::BOLD))
        .percent((app.throughput as u16).min(100));
    f.render_widget(throughput_gauge, sidebar[0]);

    let drop_rate = Gauge::default()
        .block(Block::default().title(" Packet Drop Rate ").borders(Borders::ALL).border_style(Style::default().fg(Color::Red)))
        .gauge_style(Style::default().fg(Color::Red))
        .percent(2); 
    f.render_widget(drop_rate, sidebar[1]);

    let sparkline = Sparkline::default()
        .block(Block::default().title(" Traffic Load ").borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)))
        .data(&app.throughput_history)
        .style(Style::default().fg(Color::Magenta));
    f.render_widget(sparkline, sidebar[2]);

    let packet_items: Vec<ListItem> = app.packets.iter().take(10).map(|p| ListItem::new(p.as_str()).style(Style::default().fg(Color::Green))).collect();
    let packet_list = List::new(packet_items).block(Block::default().borders(Borders::ALL).title(" Live Snoop ").border_style(Style::default().fg(Color::Green)));
    f.render_widget(packet_list, sidebar[3]);
}

fn render_packets(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Packet Inspector (Ctrl+P) ").border_style(Style::default().fg(Color::Green));
    let items: Vec<ListItem> = app.packets.iter().map(|p| ListItem::new(p.as_str())).collect();
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn render_topology(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Network Topology Map (Ctrl+T) ").border_style(Style::default().fg(Color::LightRed));
    
    let content = if let Some(shared_topo) = &app.topology {
        if let Ok(graph) = shared_topo.lock() {
            graph.to_ascii()
        } else {
            "Error locking topology graph.".to_string()
        }
    } else {
        "        ┌───────┐\n        │ Cloud │\n        └───┬───┘\n            ▼\n    ┌───────┴───────┐\n    │ Gateway (R1)  │\n    └───────┬───────┘\n            ▼\n    ┌───────┴───────┐\n    │  Local Host   │\n    └───────────────┘\n\n(Mock Visualization)".to_string()
    };

    let p = Paragraph::new(content).block(block).wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_logs(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Structured Log Stream (Ctrl+L) ").border_style(Style::default().fg(Color::White));
    let items: Vec<ListItem> = app.logs.iter().map(|l| ListItem::new(l.as_str())).collect();
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn render_scanner(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Port Scan Results (Ctrl+S) ").border_style(Style::default().fg(Color::Yellow));
    let items: Vec<ListItem> = app.scan_results.iter().map(|r| ListItem::new(r.as_str())).collect();
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn render_history(f: &mut ratatui::Frame, area: Rect, _app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Session History (Ctrl+H) ").border_style(Style::default().fg(Color::Magenta));
    let p = Paragraph::new("No previous sessions found in SQLite store.").block(block);
    f.render_widget(p, area);
}
