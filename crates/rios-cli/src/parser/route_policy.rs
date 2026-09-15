//! Routing policy argument parsing and contextual help share one grammar.
use super::*;
use rios_config::{AccessListAction, PrefixListEntry};
pub(super) fn options(action: Action, args: &[Token<'_>]) -> Result<ospf::Options, ParseError> {
    use Action::*;
    let pending = |choices| {
        Ok(ospf::Options {
            command: None,
            choices,
        })
    };
    let complete = |command, choices| {
        Ok(ospf::Options {
            command: Some(command),
            choices,
        })
    };
    let sequence = |token: &Token<'_>| {
        token
            .text
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0 && *n < u32::MAX)
            .ok_or_else(|| invalid(token.offset, "expected sequence 1-4294967294"))
    };
    let exact = |n: usize| {
        args.get(n)
            .map_or(Ok(()), |t| Err(invalid(t.offset, "unexpected argument")))
    };
    let action_word = |token: &Token<'_>| {
        unique_choice(token, &["permit", "deny"]).map(|s| {
            if s == "permit" {
                AccessListAction::Permit
            } else {
                AccessListAction::Deny
            }
        })
    };
    let command = match action {
        PrefixList | NoPrefixList => {
            let Some(name) = args.first() else {
                return pending(vec!["<name>"]);
            };
            let mut index = 1;
            let mut seq = None;
            if let Some(token) = args.get(index) {
                let choices: &[&str] = if matches!(action, NoPrefixList) {
                    &["seq"]
                } else {
                    &["seq", "permit", "deny"]
                };
                if unique_choice(token, choices)? == "seq" {
                    let Some(token) = args.get(index + 1) else {
                        return pending(vec!["<sequence>"]);
                    };
                    seq = Some(sequence(token)?);
                    index += 2;
                }
            }
            if matches!(action, NoPrefixList) {
                exact(index)?;
                return complete(
                    Command::RemovePrefixList {
                        name: name.text.into(),
                        sequence: seq,
                    },
                    if seq.is_none() {
                        vec!["<cr>", "seq"]
                    } else {
                        vec!["<cr>"]
                    },
                );
            }
            let Some(token) = args.get(index) else {
                return pending(if seq.is_none() {
                    vec!["seq", "permit", "deny"]
                } else {
                    vec!["permit", "deny"]
                });
            };
            let permit = action_word(token)?;
            let Some(token) = args.get(index + 1) else {
                return pending(vec!["<prefix/length>"]);
            };
            let (ip, bits) = token
                .text
                .split_once('/')
                .ok_or_else(|| invalid(token.offset, "expected prefix/length"))?;
            let prefix = Ipv4Network::new(
                ip.parse()
                    .map_err(|_| invalid(token.offset, "invalid IPv4 address"))?,
                bits.parse()
                    .map_err(|_| invalid(token.offset, "invalid prefix length"))?,
            )
            .map_err(|_| invalid(token.offset, "invalid prefix length"))?;
            let mut entry = PrefixListEntry {
                action: permit,
                prefix,
                ge: None,
                le: None,
            };
            index += 2;
            while let Some(token) = args.get(index) {
                let word = unique_choice(token, &["ge", "le"])?;
                let target = if word == "ge" {
                    &mut entry.ge
                } else {
                    &mut entry.le
                };
                if target.is_some() {
                    return Err(invalid(token.offset, "duplicate length constraint"));
                }
                let Some(value) = args.get(index + 1) else {
                    return pending(vec!["<0-32>"]);
                };
                *target = Some(
                    value
                        .text
                        .parse::<u8>()
                        .ok()
                        .filter(|v| *v <= 32)
                        .ok_or_else(|| invalid(value.offset, "expected prefix length 0-32"))?,
                );
                index += 2;
            }
            if !entry.valid() {
                return Err(invalid(token.offset, "inconsistent prefix length bounds"));
            }
            let mut choices = vec!["<cr>"];
            if entry.ge.is_none() {
                choices.push("ge");
            }
            if entry.le.is_none() {
                choices.push("le");
            }
            return complete(
                Command::SetPrefixList {
                    name: name.text.into(),
                    sequence: seq,
                    entry,
                },
                choices,
            );
        }
        RouteMap | NoRouteMap => {
            let Some(name) = args.first() else {
                return pending(vec!["<name>"]);
            };
            let action_value = args
                .get(1)
                .map(action_word)
                .transpose()?
                .unwrap_or(AccessListAction::Permit);
            let seq = args.get(2).map(sequence).transpose()?;
            exact(3)?;
            let command = if matches!(action, NoRouteMap) {
                Command::RemoveRouteMap {
                    name: name.text.into(),
                    sequence: if args.len() > 1 {
                        Some(seq.unwrap_or(10))
                    } else {
                        None
                    },
                }
            } else {
                Command::EnterRouteMap {
                    name: name.text.into(),
                    action: action_value,
                    sequence: seq.unwrap_or(10),
                }
            };
            return complete(
                command,
                match args.len() {
                    1 => vec!["<cr>", "permit", "deny"],
                    2 => vec!["<cr>", "<sequence>"],
                    _ => vec!["<cr>"],
                },
            );
        }
        RouteMapMatch => {
            if args.is_empty() {
                return pending(vec!["<prefix-list-name>"]);
            }
            return complete(
                Command::SetRouteMapMatch(args.iter().map(|t| t.text.into()).collect()),
                vec!["<cr>", "<prefix-list-name>"],
            );
        }
        NoRouteMapMatch => {
            exact(0)?;
            Command::SetRouteMapMatch(Default::default())
        }
        RouteMapPrepend => {
            if args.is_empty() {
                return pending(vec!["<1-4294967294>"]);
            }
            if args.len() > 64 {
                return Err(invalid(args[64].offset, "at most 64 prepended AS numbers"));
            }
            return complete(
                Command::SetRouteMapPrepend(args.iter().map(sequence).collect::<Result<_, _>>()?),
                vec!["<cr>", "<1-4294967294>"],
            );
        }
        NoRouteMapPrepend => {
            exact(0)?;
            Command::SetRouteMapPrepend(Vec::new())
        }
        RouteMapLocalPref | RouteMapMetric => {
            let Some(token) = args.first() else {
                return pending(vec!["<0-4294967295>"]);
            };
            let value = token
                .text
                .parse::<u32>()
                .map_err(|_| invalid(token.offset, "expected unsigned 32-bit value"))?;
            exact(1)?;
            if matches!(action, RouteMapLocalPref) {
                Command::SetRouteMapLocalPreference(Some(value))
            } else {
                Command::SetRouteMapMetric(Some(value))
            }
        }
        NoRouteMapLocalPref | NoRouteMapMetric => {
            exact(0)?;
            if matches!(action, NoRouteMapLocalPref) {
                Command::SetRouteMapLocalPreference(None)
            } else {
                Command::SetRouteMapMetric(None)
            }
        }
        _ => return Err(invalid(0, "invalid routing policy command")),
    };
    complete(command, vec!["<cr>"])
}
pub(super) fn suggest(
    action: Action,
    args: &[Token<'_>],
    partial: &str,
    start: usize,
) -> Result<Vec<Suggestion>, ParseError> {
    Ok(options(action, args)?
        .choices
        .into_iter()
        .filter(|s| s.starts_with('<') || s.starts_with(&partial.to_ascii_lowercase()))
        .map(|word| Suggestion {
            word: word.into(),
            help: String::new(),
            start,
        })
        .collect())
}
