//! NAT argument grammar shared by configuration parsing and contextual help.
use super::*;
use rios_config::{NatPool, NatPoolRule, NatTransport, StaticNat};

fn ip(token: &Token<'_>) -> Result<Ipv4Addr, ParseError> {
    token
        .text
        .parse()
        .map_err(|_| invalid(token.offset, "expected an IPv4 address"))
}
fn port(token: &Token<'_>) -> Result<u16, ParseError> {
    token
        .text
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| invalid(token.offset, "expected port 1-65535"))
}
fn count(args: &[Token<'_>], expected: usize) -> Result<(), ParseError> {
    if args.len() < expected {
        Err(ParseError::Incomplete)
    } else if args.len() > expected {
        Err(invalid(args[expected].offset, "unexpected argument"))
    } else {
        Ok(())
    }
}
pub(super) fn static_rule(args: &[Token<'_>]) -> Result<Command, ParseError> {
    let first = args.first().ok_or(ParseError::Incomplete)?;
    let rule = if first.text.parse::<Ipv4Addr>().is_ok() {
        count(args, 2)?;
        StaticNat::Address {
            local: ip(first)?,
            global: ip(&args[1])?,
        }
    } else {
        let protocol = match unique_choice(first, &["tcp", "udp"])? {
            "tcp" => NatTransport::Tcp,
            _ => NatTransport::Udp,
        };
        count(args, 5)?;
        StaticNat::Port {
            protocol,
            local: ip(&args[1])?,
            local_port: port(&args[2])?,
            global: ip(&args[3])?,
            global_port: port(&args[4])?,
        }
    };
    Ok(Command::AddStaticNat(rule))
}
pub(super) fn pool(args: &[Token<'_>]) -> Result<Command, ParseError> {
    count(args, 5)?;
    unique_choice(&args[3], &["netmask"])?;
    let first = ip(&args[1])?;
    let prefix_len = Ipv4InterfaceConfig::from_mask(first, ip(&args[4])?)
        .map_err(|error| invalid(args[4].offset, error.to_string()))?
        .prefix_len();
    Ok(Command::SetNatPool {
        name: args[0].text.into(),
        pool: NatPool {
            first,
            last: ip(&args[2])?,
            prefix_len,
        },
    })
}
pub(super) fn dynamic(args: &[Token<'_>]) -> Result<Command, ParseError> {
    let first = args.first().ok_or(ParseError::Incomplete)?;
    unique_choice(first, &["list"])?;
    let access_list = parse_access_list_id(args.get(1).ok_or(ParseError::Incomplete)?)?;
    let kind = unique_choice(
        args.get(2).ok_or(ParseError::Incomplete)?,
        &["interface", "pool"],
    )?;
    if kind == "pool" {
        if args.len() < 4 {
            return Err(ParseError::Incomplete);
        }
        if args.len() > 4 {
            count(args, 5)?;
            unique_choice(&args[4], &["overload"])?;
        }
        return Ok(Command::SetNatPoolRule(NatPoolRule {
            access_list,
            pool: args[3].text.into(),
            overload: args.len() == 5,
        }));
    }
    if args.len() < 5 {
        return Err(ParseError::Incomplete);
    }
    if args.len() > 6 {
        return Err(invalid(args[6].offset, "unexpected argument"));
    }
    unique_choice(&args[args.len() - 1], &["overload"])?;
    let value = args[3..args.len() - 1]
        .iter()
        .map(|token| token.text)
        .collect::<String>();
    let (outside_interface, _) =
        canonical_interface(&value).map_err(|error| invalid(args[3].offset, error.to_string()))?;
    Ok(Command::SetNatOverload {
        access_list,
        outside_interface,
    })
}
pub(super) fn suggest(
    action: Action,
    args: &[Token<'_>],
    partial: &str,
    start: usize,
) -> Result<Vec<Suggestion>, ParseError> {
    let hints: &[&str] = match action {
        Action::NatStatic => {
            if args.is_empty() {
                &["<local>", "tcp", "udp"]
            } else if args[0].text.parse::<Ipv4Addr>().is_ok() {
                if args.len() == 1 {
                    &["<global>"]
                } else {
                    static_rule(args)?;
                    &["<cr>"]
                }
            } else {
                unique_choice(&args[0], &["tcp", "udp"])?;
                match args.len() {
                    1 => &["<local>"],
                    2 => &["<local-port>"],
                    3 => &["<global>"],
                    4 => &["<global-port>"],
                    _ => {
                        static_rule(args)?;
                        &["<cr>"]
                    }
                }
            }
        }
        Action::NatPool => match args.len() {
            0 => &["<name>"],
            1 => &["<first>"],
            2 => &["<last>"],
            3 => &["netmask"],
            4 => &["<mask>"],
            _ => {
                pool(args)?;
                &["<cr>"]
            }
        },
        _ => match args.len() {
            0 => &["list"],
            1 => &["<1-99>"],
            2 => &["interface", "pool"],
            3 => {
                if unique_choice(&args[2], &["interface", "pool"])? == "pool" {
                    &["<name>"]
                } else {
                    &["<interface>"]
                }
            }
            4 if unique_choice(&args[2], &["interface", "pool"])? == "pool" => {
                dynamic(args)?;
                &["overload", "<cr>"]
            }
            4 => &["overload"],
            _ => {
                dynamic(args)?;
                &["<cr>"]
            }
        },
    };
    Ok(hints
        .iter()
        .filter(|word| {
            partial.is_empty()
                || word.starts_with('<') && **word != "<cr>"
                || word.starts_with(&partial.to_ascii_lowercase())
        })
        .map(|word| Suggestion {
            word: (*word).into(),
            help: String::new(),
            start,
        })
        .collect())
}
