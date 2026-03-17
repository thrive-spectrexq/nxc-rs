use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netsage_capture::topology::SharedTopology;
use netsage_common::AppEvent;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem},
    Terminal,
};
use std::io;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tui_textarea::TextArea;

pub struct App<'a> {
    pub textarea: TextArea<'a>,
    pub messages: Vec<String>,
    pub is_thinking: bool,
    pub event_tx: broadcast::Sender<AppEvent>,
    pub user_tx: mpsc::Sender<String>,
    pub topology: SharedTopology,
}

impl<'a> App<'a> {
    pub fn new(
        event_tx: broadcast::Sender<AppEvent>,
        user_tx: mpsc::Sender<String>,
        topology: SharedTopology,
    ) -> Self {
        let mut textarea = TextArea::default();
        textarea.set_block(Block::default().borders(Borders::ALL).title(" Prompt "));
        textarea.set_cursor_line_style(Style::default());

        Self {
            textarea,
            messages: vec!["System: NetSage Agent initialized and ready.".to_string()],
            is_thinking: false,
            event_tx,
            user_tx,
            topology,
        }
    }
}

pub async fn run_tui(
    event_tx: broadcast::Sender<AppEvent>,
    user_tx: mpsc::Sender<String>,
    topology: SharedTopology,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(event_tx.clone(), user_tx, topology);
    let mut rx = event_tx.subscribe();

    let res = run_loop(&mut terminal, &mut app, &mut rx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App<'_>,
    event_rx: &mut broadcast::Receiver<AppEvent>,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                        let content = app.textarea.lines().join("\n");
                        if !content.is_empty() {
                            app.messages.push(format!("You: {}", content));
                            let _ = app.user_tx.send(content).await;
                            app.textarea = TextArea::default();
                            app.textarea.set_block(
                                Block::default().borders(Borders::ALL).title(" Prompt "),
                            );
                        }
                    }
                    _ => {
                        app.textarea.input(key);
                    }
                }
            }
        }

        while let Ok(event) = event_rx.try_recv() {
            match event {
                AppEvent::AgentThinking(val) => app.is_thinking = val,
                AppEvent::AgentToken(token) => {
                    if let Some(last) = app.messages.last_mut() {
                        if last.starts_with("NetSage Agent:") {
                            last.push_str(&token);
                        } else {
                            app.messages.push(format!("NetSage Agent: {}", token));
                        }
                    } else {
                        app.messages.push(format!("NetSage Agent: {}", token));
                    }
                }
                AppEvent::Quit => return Ok(()),
                _ => {} // Packets and other events are ignored by the UI but processed by other tasks
            }
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(f.area());

    // Chat Area (Agent and User Conversation)
    let chat_items: Vec<ListItem> = app
        .messages
        .iter()
        .rev()
        .map(|m| {
            let style = if m.starts_with("NetSage Agent:") {
                Style::default().fg(Color::Magenta)
            } else if m.starts_with("You:") {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Gray).add_modifier(Modifier::DIM)
            };
            ListItem::new(m.as_str()).style(style)
        })
        .collect();

    let chat = List::new(chat_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" NetSage Intelligence Log "),
    );
    f.render_widget(chat, main_layout[0]);

    // Input Area
    let mut textarea = app.textarea.clone();
    if app.is_thinking {
        textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .title(" NetSage is thinking... "),
        );
    }
    f.render_widget(&textarea, main_layout[1]);
}
