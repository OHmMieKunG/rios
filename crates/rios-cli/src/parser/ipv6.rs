//! IPv6 argument grammar and contextual help.
use super::*;
use rios_ipv6::{Ipv6InterfaceConfig, Ipv6Network};
use std::net::Ipv6Addr;
fn address(token: &Token<'_>) -> Result<Ipv6Addr, ParseError> {
    token
        .text
        .parse()
        .map_err(|_| invalid(token.offset, "expected an IPv6 address"))
}
pub(super) fn interface_address(args: &[Token<'_>], present: bool) -> Result<Command, ParseError> {
    let Some(first) = args.first() else {
        return if present {
            Err(ParseError::Incomplete)
        } else {
            Ok(Command::SetIpv6Port(Ipv6PortOption::ClearAddresses))
        };
    };
    if "autoconfig".starts_with(&first.text.to_ascii_lowercase()) {
        if args.len() != 1 {
            return Err(invalid(args[1].offset, "unexpected argument"));
        }
        return Ok(Command::SetIpv6Port(Ipv6PortOption::Autoconfig(present)));
    }
    let option = if let Ok(ip) = first.text.parse::<Ipv6InterfaceConfig>() {
        if args.len() != 1 {
            return Err(invalid(args[1].offset, "unexpected argument"));
        }
        Ipv6PortOption::Address(ip, present)
    } else {
        let ip = address(first)?;
        let option = args.get(1).ok_or(ParseError::Incomplete)?;
        unique_choice(option, &["link-local"])?;
        if args.len() > 2 {
            return Err(invalid(args[2].offset, "unexpected argument"));
        }
        Ipv6PortOption::LinkLocal(ip, present)
    };
    Ok(Command::SetIpv6Port(option))
}
pub(super) fn route(args: &[Token<'_>], present: bool) -> Result<Command, ParseError> {
    if args.len() < 2 {
        return Err(ParseError::Incomplete);
    }
    if args.len() > 3 {
        return Err(invalid(args[3].offset, "unexpected argument"));
    }
    let prefix = args[0]
        .text
        .parse::<Ipv6Network>()
        .map_err(|e| invalid(args[0].offset, e.to_string()))?;
    let (interface, next) = if args.len() == 3 {
        let (name, _) = canonical_interface(args[1].text)
            .map_err(|e| invalid(args[1].offset, e.to_string()))?;
        (Some(name), &args[2])
    } else {
        (None, &args[1])
    };
    Ok(Command::SetIpv6Route {
        prefix,
        interface,
        next_hop: address(next)?,
        present,
    })
}
pub(super) fn ping(args: &[Token<'_>]) -> Result<Command, ParseError> {
    let first = args.first().ok_or(ParseError::Incomplete)?;
    if args.len() > 3 {
        return Err(invalid(args[3].offset, "unexpected argument"));
    }
    let destination = address(first)?;
    let interface = if args.len() > 1 {
        unique_choice(&args[1], &["source"])?;
        let port = args.get(2).ok_or(ParseError::Incomplete)?;
        Some(
            canonical_interface(port.text)
                .map_err(|e| invalid(port.offset, e.to_string()))?
                .0,
        )
    } else {
        None
    };
    Ok(Command::PingIpv6 {
        destination,
        interface,
    })
}
pub(super) fn suggest(
    action: Action,
    args: &[Token<'_>],
    partial: &str,
    start: usize,
) -> Result<Vec<Suggestion>, ParseError> {
    let words: &[&str] = match action {
        Action::Ipv6Address | Action::NoIpv6Address if args.is_empty() => {
            if matches!(action, Action::NoIpv6Address) {
                &[
                    "<cr>",
                    "<ipv6-address/prefix>",
                    "autoconfig",
                    "<link-local-address>",
                ]
            } else {
                &[
                    "<ipv6-address/prefix>",
                    "autoconfig",
                    "<link-local-address>",
                ]
            }
        }
        Action::Ipv6Address | Action::NoIpv6Address
            if args.len() == 1 && args[0].text.parse::<Ipv6Addr>().is_ok() =>
        {
            &["link-local"]
        }
        Action::Ipv6Address | Action::NoIpv6Address => {
            interface_address(args, matches!(action, Action::Ipv6Address))?;
            &["<cr>"]
        }
        Action::Ipv6Route | Action::NoIpv6Route if args.is_empty() => &["<ipv6-prefix>"],
        Action::Ipv6Route | Action::NoIpv6Route if args.len() == 1 => {
            &["<next-hop>", "<interface>"]
        }
        Action::Ipv6Route | Action::NoIpv6Route
            if args.len() == 2 && args[1].text.parse::<Ipv6Addr>().is_err() =>
        {
            &["<next-hop>"]
        }
        Action::Ipv6Route | Action::NoIpv6Route => {
            route(args, matches!(action, Action::Ipv6Route))?;
            &["<cr>"]
        }
        Action::PingIpv6 if args.is_empty() => &["<ipv6-address>"],
        Action::PingIpv6 if args.len() == 1 => {
            address(&args[0])?;
            &["<cr>", "source"]
        }
        Action::PingIpv6 if args.len() == 2 => {
            unique_choice(&args[1], &["source"])?;
            &["<interface>"]
        }
        Action::PingIpv6 => {
            ping(args)?;
            &["<cr>"]
        }
        _ => &["<cr>"],
    };
    Ok(words
        .iter()
        .filter(|word| word.starts_with('<') || word.starts_with(&partial.to_ascii_lowercase()))
        .map(|word| Suggestion {
            word: (*word).into(),
            help: String::new(),
            start,
        })
        .collect())
}
