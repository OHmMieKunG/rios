//! One grammar for QoS arguments, units, abbreviations and contextual help.
use super::*;
use rios_config::QosRate;
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
            command: Some(Command::Qos(command)),
            choices,
        })
    };
    let exact = |n: usize| {
        args.get(n)
            .map_or(Ok(()), |t| Err(invalid(t.offset, "unexpected argument")))
    };
    let command = match action {
        QosClassMap => {
            let Some(token) = args.first() else {
                return pending(vec!["match-all", "match-any", "<name>"]);
            };
            let word = token.text.to_ascii_lowercase();
            let (match_all, index) = if ["match-all", "match-any"]
                .iter()
                .any(|s| s.starts_with(&word))
            {
                (
                    unique_choice(token, &["match-all", "match-any"])? == "match-all",
                    1,
                )
            } else {
                (true, 0)
            };
            let Some(name) = args.get(index) else {
                return pending(vec!["<name>"]);
            };
            exact(index + 1)?;
            QosCommand::EnterClass {
                name: name.text.into(),
                match_all,
            }
        }
        NoQosClassMap | QosPolicyMap | NoQosPolicyMap | QosPolicyClass | NoQosPolicyClass
        | QosOutput | NoQosOutput => {
            let Some(name) = args.first() else {
                return pending(vec!["<name>"]);
            };
            exact(1)?;
            let name = name.text.into();
            match action {
                NoQosClassMap => QosCommand::RemoveClass(name),
                QosPolicyMap => QosCommand::EnterPolicy(name),
                NoQosPolicyMap => QosCommand::RemovePolicy(name),
                QosPolicyClass => QosCommand::EnterPolicyClass(name),
                NoQosPolicyClass => QosCommand::RemovePolicyClass(name),
                _ => QosCommand::BindOutput {
                    name,
                    present: matches!(action, QosOutput),
                },
            }
        }
        QosDscp | QosPrecedence => {
            let dscp = matches!(action, QosDscp);
            let hint = if dscp { "<0-63|ef|afXY|csN>" } else { "<0-7>" };
            if args.is_empty() {
                return pending(vec![hint]);
            }
            let values = args
                .iter()
                .map(|t| {
                    let word = t.text.to_ascii_lowercase();
                    let value = if dscp {
                        dscp_value(&word)
                    } else {
                        word.parse::<u8>().ok().filter(|n| *n <= 7)
                    };
                    value.ok_or_else(|| invalid(t.offset, "invalid DSCP or precedence value"))
                })
                .collect::<Result<_, _>>()?;
            return complete(
                if dscp {
                    QosCommand::Dscp(values)
                } else {
                    QosCommand::Precedence(values)
                },
                vec!["<cr>", hint],
            );
        }
        NoQosDscp | NoQosPrecedence => {
            exact(0)?;
            if matches!(action, NoQosDscp) {
                QosCommand::Dscp(Default::default())
            } else {
                QosCommand::Precedence(Default::default())
            }
        }
        QosAcl | NoQosAcl => {
            let Some(token) = args.first() else {
                return pending(vec!["name", "<ACL-number>"]);
            };
            let index = if "name".starts_with(&token.text.to_ascii_lowercase()) {
                1
            } else {
                0
            };
            let Some(name) = args.get(index) else {
                return pending(vec!["<ACL-name>"]);
            };
            if index == 0 && name.text.parse::<u16>().is_err() {
                return Err(invalid(name.offset, "use name before a named ACL"));
            }
            exact(index + 1)?;
            QosCommand::MatchAcl {
                name: name.text.into(),
                present: matches!(action, QosAcl),
            }
        }
        QosBandwidth | QosPriority | QosPolice | QosShape => {
            let kbps = matches!(action, QosBandwidth | QosPriority);
            let Some(token) = args.first() else {
                return pending(vec![if kbps { "<kbps>" } else { "<bits-per-second>" }]);
            };
            let value = token
                .text
                .parse::<u64>()
                .ok()
                .filter(|v| {
                    *v > 0
                        && *v
                            <= if kbps {
                                1_000_000_000
                            } else {
                                1_000_000_000_000
                            }
                })
                .ok_or_else(|| invalid(token.offset, "invalid service rate"))?;
            if matches!(action, QosBandwidth) {
                exact(1)?;
                QosCommand::Bandwidth(Some(value))
            } else {
                let bits_per_second = if kbps { value * 1000 } else { value };
                let shape = matches!(action, QosShape);
                let burst_bytes = args.get(1).map(|token| {
                    let n = token.text.parse::<u64>().ok().filter(|n| *n > 0 && (!shape || *n % 8 == 0)).ok_or_else(|| invalid(token.offset, "burst must be positive; shaper bits must be a multiple of eight"))?;
                    let bytes = if shape {n/8} else {n};
                    (bytes <= 1_073_741_824).then_some(bytes).ok_or_else(|| invalid(token.offset, "burst exceeds 1 GiB"))
                }).transpose()?;
                exact(2)?;
                let rate = Some(QosRate {
                    bits_per_second,
                    burst_bytes,
                });
                let command = match action {
                    QosPriority => QosCommand::Priority(rate),
                    QosPolice => QosCommand::Police(rate),
                    _ => QosCommand::Shape(rate),
                };
                return complete(
                    command,
                    if args.len() == 1 {
                        vec![
                            "<cr>",
                            if shape {
                                "<burst-bits>"
                            } else {
                                "<burst-bytes>"
                            },
                        ]
                    } else {
                        vec!["<cr>"]
                    },
                );
            }
        }
        NoQosBandwidth | NoQosPriority | NoQosPolice | NoQosShape => {
            exact(0)?;
            match action {
                NoQosBandwidth => QosCommand::Bandwidth(None),
                NoQosPriority => QosCommand::Priority(None),
                NoQosPolice => QosCommand::Police(None),
                _ => QosCommand::Shape(None),
            }
        }
        ShowQosInterface => {
            let name = if args.is_empty() {
                None
            } else {
                Some(
                    canonical_interface(&args.iter().map(|t| t.text).collect::<String>())
                        .map_err(|_| invalid(args[0].offset, "invalid interface"))?
                        .0,
                )
            };
            return complete(
                QosCommand::ShowInterface(name),
                if args.is_empty() {
                    vec!["<cr>", "<interface>"]
                } else {
                    vec!["<cr>"]
                },
            );
        }
        _ => return Err(invalid(0, "invalid QoS command")),
    };
    complete(command, vec!["<cr>"])
}
fn dscp_value(word: &str) -> Option<u8> {
    if word == "ef" {
        return Some(46);
    }
    if word == "default" {
        return Some(0);
    }
    if let Some(n) = word.strip_prefix("cs") {
        return n.parse::<u8>().ok().filter(|n| *n <= 7).map(|n| n * 8);
    }
    if let Some(n) = word.strip_prefix("af") {
        let [class, drop] = n.as_bytes() else {
            return None;
        };
        return (b'1'..=b'4')
            .contains(class)
            .then_some(())
            .filter(|_| (b'1'..=b'3').contains(drop))
            .map(|_| (class - b'0') * 8 + (drop - b'0') * 2);
    }
    word.parse::<u8>().ok().filter(|n| *n <= 63)
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
