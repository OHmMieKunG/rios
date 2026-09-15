//! DHCP option syntax and contextual argument hints.
use super::*;
pub(super) fn command(action: Action, args: &[Token<'_>]) -> Result<Command, ParseError> {
    let ip = |index: usize| {
        args.get(index)
            .ok_or(ParseError::Incomplete)?
            .text
            .parse::<Ipv4Addr>()
            .map_err(|_| invalid(args[index].offset, "expected IPv4 address"))
    };
    let option = match action {
        Action::DhcpLease => {
            if args.len() > 3 {
                return Err(invalid(args[3].offset, "unexpected argument"));
            }
            let mut seconds = 0u32;
            for (index, token) in args.iter().enumerate() {
                let value = token
                    .text
                    .parse::<u32>()
                    .map_err(|_| invalid(token.offset, "expected duration"))?;
                if value > [365, 23, 59][index] {
                    return Err(invalid(token.offset, "duration out of range"));
                }
                seconds += value * [86400, 3600, 60][index];
            }
            if seconds == 0 {
                return Err(invalid(args[0].offset, "lease must be at least one minute"));
            }
            DhcpPoolOption::Lease(seconds)
        }
        Action::DhcpDns => {
            if args.len() > 8 {
                return Err(invalid(args[8].offset, "at most eight DNS servers"));
            }
            DhcpPoolOption::Dns((0..args.len()).map(ip).collect::<Result<_, _>>()?)
        }
        Action::DhcpDomain => DhcpPoolOption::Domain(args[0].text.into()),
        Action::DhcpHardware => DhcpPoolOption::Hardware(
            args[0]
                .text
                .parse()
                .map_err(|_| invalid(args[0].offset, "expected MAC address"))?,
        ),
        Action::DhcpHost => DhcpPoolOption::Host(
            Ipv4InterfaceConfig::from_mask(ip(0)?, ip(1)?)
                .map_err(|error| invalid(args[1].offset, error.to_string()))?,
        ),
        Action::DhcpExcluded => {
            if args.len() > 2 {
                return Err(invalid(args[2].offset, "unexpected argument"));
            }
            let first = ip(0)?;
            return Ok(Command::ExcludeDhcpAddresses {
                first,
                last: if args.len() == 2 { ip(1)? } else { first },
            });
        }
        Action::DhcpHelper => return Ok(Command::SetDhcpHelper(ip(0)?)),
        _ => return Err(invalid(0, "invalid DHCP action")),
    };
    Ok(Command::SetDhcpPoolOption(option))
}
pub(super) fn suggest(
    action: Action,
    args: &[Token<'_>],
    partial: &str,
    start: usize,
) -> Result<Vec<Suggestion>, ParseError> {
    let mut hints = Vec::new();
    let next = match action {
        Action::DhcpLease => ["<days>", "<hours>", "<minutes>"].get(args.len()).copied(),
        Action::DhcpDns => (args.len() < 8).then_some("<address>"),
        Action::DhcpExcluded => ["<first>", "<last>"].get(args.len()).copied(),
        Action::DhcpHost => ["<address>", "<mask>"].get(args.len()).copied(),
        _ if args.is_empty() => Some(action.argument_help()[0]),
        _ => None,
    };
    if !args.is_empty() && command(action, args).is_ok() && partial.is_empty() {
        hints.push("<cr>");
    }
    if let Some(next) = next {
        hints.push(next);
    } else {
        command(action, args)?;
        if !partial.is_empty() {
            return Err(invalid(start, "unexpected argument"));
        }
    }
    Ok(hints
        .into_iter()
        .map(|word| Suggestion {
            word: word.into(),
            help: String::new(),
            start,
        })
        .collect())
}
