use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netsage_agent::Persona;
use netsage_capture::topology::SharedTopology;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, List, ListItem},
    Terminal,
};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use tui_textarea::TextArea;

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
        textarea.set_block(Block::default());
        textarea.set_cursor_line_style(Style::default());
        textarea.set_placeholder_text("Ask NetSage anything... (e.g. 'Why is latency high?')");

        App {
            textarea,
            messages: vec![
                "NetSage Agent: System online. Waiting for network intelligence requests..."
                    .to_string(),
            ],
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
        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "/clear" => {
                self.messages.clear();
                self.messages.push("History cleared.".to_string());
            }
            "/mode" if parts.len() > 1 => {
                self.mode = parts[1].to_uppercase();
                self.messages
                    .push(format!("System: Approval mode changed to {}", self.mode));
            }
            "/capture" if parts.len() > 1 => {
                self.interface = parts[1].to_string();
                self.messages
                    .push(format!("System: Capturing on interface {}", self.interface));
            }
            "/topology" => self.current_view = View::Topology,
            "/export" => {
                self.messages
                    .push("System: Exporting session report...".to_string());
                // We'll let the main loop handle the actual IO
            }
            "/persona" => {
                self.messages
                    .push("System: Usage: /persona [general|netops|secops|sre]".to_string());
            }
            "/persona general" => {
                self.messages
                    .push("System: Switching to General Persona".to_string());
            }
            "/persona netops" => {
                self.messages
                    .push("System: Switching to NetOps Persona".to_string());
            }
            "/persona secops" => {
                self.messages
                    .push("System: Switching to SecOps Persona".to_string());
            }
            "/persona sre" => {
                self.messages
                    .push("System: Switching to SRE Persona".to_string());
            }
            "/mermaid" => {
                self.messages
                    .push("System: Generating Mermaid diagram...".to_string());
            }
            _ => self.messages.push(format!("You: {}", cmd)),
        }
    }
}

pub async fn run_tui(
    mut rx: mpsc::Receiver<TuiEvent>,
    tx: mpsc::Sender<TuiEvent>,
    topology: Option<SharedTopology>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new(topology);

    // Create a dedicated event task to avoid blocking the UI
    let (event_tx, mut event_rx) = mpsc::channel(100);
    tokio::spawn(async move {
        loop {
            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(event) = event::read() {
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let res = run_app(&mut terminal, app, &mut rx, tx, &mut event_rx).await;

    // Guaranteed cleanup
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    if let Err(err) = res {
        eprintln!("TUI Error: {:?}", err);
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App<'_>,
    rx: &mut mpsc::Receiver<TuiEvent>,
    tx: mpsc::Sender<TuiEvent>,
    event_rx: &mut mpsc::Receiver<Event>,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(1)])
                .split(f.area());

            let items: Vec<ListItem> = app
                .messages
                .iter()
                .map(|m| {
                    let style = if m.starts_with("NetSage Agent:") {
                        Style::default().fg(Color::Magenta)
                    } else if m.starts_with("System:") {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(m.as_str()).style(style)
                })
                .collect();

            let chat = List::new(items).block(Block::default());
            f.render_widget(chat, root[0]);
            f.render_widget(&app.textarea, root[1]);
        })?;

        tokio::select! {
            Some(event) = event_rx.recv() => {
                if let Event::Key(key) = event {
                    match key.code {
                        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),

                        KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                            let lines: Vec<String> = app.textarea.lines().to_vec();
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
                                next_textarea.set_block(Block::default());
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
                    TuiEvent::AgentThinking(val) => {
                        app.is_thinking = val;
                    }
                    _ => {}
                }
            }
        }
    }
}
