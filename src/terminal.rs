use crate::app::{App, CompletionContext};
use rustyline::{
    Cmd, ConditionalEventHandler, Context, Editor, Event, EventContext, EventHandler, Helper,
    KeyEvent, RepeatCount,
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
    validate::Validator,
};
use std::sync::mpsc::{Sender, channel};

struct CliHelper(CompletionContext);
impl Completer for CliHelper {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let candidates = self.0.suggestions(&line[..pos]).unwrap_or_default();
        let start = candidates.first().map_or(pos, |c| c.start);
        let pairs = candidates
            .into_iter()
            .filter(|c| !c.word.starts_with('<'))
            .map(|c| Pair {
                display: c.word.clone(),
                replacement: c.word,
            })
            .collect();
        Ok((start, pairs))
    }
}
impl Hinter for CliHelper {
    type Hint = String;
}
impl Highlighter for CliHelper {}
impl Validator for CliHelper {}
impl Helper for CliHelper {}

#[derive(Clone, Copy)]
enum Control {
    Help,
    End,
}
struct Pending {
    control: Control,
    line: String,
    position: usize,
}
struct ControlHandler {
    control: Control,
    sender: Sender<Pending>,
}
impl ConditionalEventHandler for ControlHandler {
    fn handle(
        &self,
        _: &Event,
        _: RepeatCount,
        _: bool,
        context: &EventContext<'_>,
    ) -> Option<Cmd> {
        self.sender
            .send(Pending {
                control: self.control,
                line: context.line().into(),
                position: context.pos(),
            })
            .ok()?;
        Some(Cmd::Interrupt)
    }
}
pub fn run(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = Editor::<CliHelper, DefaultHistory>::new()?;
    let (sender, receiver) = channel();
    for (key, control) in [
        (KeyEvent::from('?'), Control::Help),
        (KeyEvent::ctrl('Z'), Control::End),
    ] {
        editor.bind_sequence(
            key,
            EventHandler::Conditional(Box::new(ControlHandler {
                control,
                sender: sender.clone(),
            })),
        );
    }
    let mut initial = String::new();
    let mut position = 0;
    loop {
        editor.set_helper(Some(CliHelper(app.completion())));
        let prompt = app.prompt();
        let input =
            editor.readline_with_initial(&prompt, (&initial[..position], &initial[position..]));
        initial.clear();
        position = 0;
        match input {
            Ok(line) => {
                if !line.trim().is_empty() {
                    editor.add_history_entry(&line)?;
                }
                if app.process(&line) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                let control = receiver.try_recv().ok();
                if let Some(control) = control {
                    match control.control {
                        Control::Help => {
                            println!();
                            let context = &control.line[..control.position];
                            match app.completion().suggestions(context) {
                                Ok(items) => {
                                    for item in items {
                                        println!("  {:<20} {}", item.word, item.help);
                                    }
                                }
                                Err(error) => print!("{}", error.render(&prompt, context)),
                            }
                            initial = control.line;
                            position = control.position;
                        }
                        Control::End => {
                            println!();
                            app.end_configuration();
                        }
                    }
                } else {
                    println!("^C");
                }
            }
            Err(ReadlineError::Eof) => {
                if app.close_connection() {
                    break;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
