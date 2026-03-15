use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;

#[derive(Debug, PartialEq)]
pub enum View {
    Dashboard,
    Topology,
}

pub struct App {
    pub input: String,
    pub messages: Vec<String>,
    pub packets: Vec<String>,
    pub mode_info: String,
    pub current_view: View,
    pub topology_map: String,
    pub export_path: Option<String>,
}

impl App {
    pub fn new() -> App {
        App {
            input: String::new(),
            messages: vec!["NetSage Agent: Waiting for input...".to_string()],
            packets: vec!["Packet capture not started...".to_string()],
            mode_info: "Mode: SUPERVISED".to_string(),
            current_view: View::Dashboard,
            topology_map: "Topology scan not triggered.".to_string(),
            export_path: None,
        }
    }
}

pub fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let res = run_app(&mut terminal, app);

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

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(3),  // Header/Mode
                        Constraint::Min(10),    // Chat/Main
                        Constraint::Length(10), // Packet Inspector
                        Constraint::Length(3),  // Input
                    ]
                    .as_ref(),
                )
                .split(f.area());

            // Header
            let header = Paragraph::new(app.mode_info.clone()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" NetSage status "),
            );
            f.render_widget(header, chunks[0]);

            // Main Content Area (View Switch)
            match app.current_view {
                View::Dashboard => {
                    let chat_items: Vec<ListItem> = app
                        .messages
                        .iter()
                        .map(|m| ListItem::new(m.as_str()))
                        .collect();
                    let chat = List::new(chat_items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Investigation Trace "),
                    );
                    f.render_widget(chat, chunks[1]);

                    let packet_items: Vec<ListItem> = app
                        .packets
                        .iter()
                        .map(|p| ListItem::new(p.as_str()))
                        .collect();
                    let packet_list = List::new(packet_items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Live Packets (L1/L2) "),
                    );
                    f.render_widget(packet_list, chunks[2]);
                }
                View::Topology => {
                    let topology = Paragraph::new(app.topology_map.clone()).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Network Topology (Ctrl+T) "),
                    );
                    f.render_widget(topology, chunks[1]);
                    // Hide packets or show a smaller version? For now hide.
                }
            }

            // Input
            let input = Paragraph::new(app.input.clone())
                .block(Block::default().borders(Borders::ALL).title(" Prompt "));
            f.render_widget(input, chunks[3]);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Char('t') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    app.current_view = if app.current_view == View::Dashboard {
                        View::Topology
                    } else {
                        View::Dashboard
                    };
                }
                KeyCode::Enter => {
                    let input = app.input.trim();
                    if input == "/clear" {
                        app.messages.clear();
                        app.messages.push("History cleared.".to_string());
                    } else if input == "/export" {
                        app.messages
                            .push("Exporting session to report.md...".to_string());
                        // In a real app, this would trigger the actual SessionStore export
                    }
                    app.input.clear();
                }
                KeyCode::Char(c) => app.input.push(c),
                KeyCode::Backspace => {
                    app.input.pop();
                }
                _ => {}
            }
        }
    }
}
