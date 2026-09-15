//! One grammar supplies BGP commands and context-sensitive argument help.
use super::*;
pub(super) fn options(action: Action, args: &[Token<'_>]) -> Result<ospf::Options, ParseError> {
    use Action::*;
    let pending = |choices| {
        Ok(ospf::Options {
            command: None,
            choices,
        })
    };
    let ip = |token: &Token<'_>| {
        token
            .text
            .parse::<Ipv4Addr>()
            .map_err(|_| invalid(token.offset, "expected IPv4 address"))
    };
    let asn = |token: &Token<'_>| {
        token
            .text
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0 && *n < u32::MAX)
            .ok_or_else(|| invalid(token.offset, "expected AS number 1-4294967294"))
    };
    let exact = |count: usize| {
        if let Some(token) = args.get(count) {
            Err(invalid(token.offset, "unexpected argument"))
        } else {
            Ok(())
        }
    };
    let command = match action {
        RouterBgp | NoRouterBgp => {
            let Some(token) = args.first() else {
                return pending(vec!["<1-4294967294>"]);
            };
            exact(1)?;
            Command::BgpProcess {
                asn: asn(token)?,
                present: matches!(action, RouterBgp),
            }
        }
        BgpRouterId => {
            let Some(token) = args.first() else {
                return pending(vec!["<router-id>"]);
            };
            exact(1)?;
            Command::SetBgpRouterId(Some(ip(token)?))
        }
        NoBgpRouterId => {
            exact(0)?;
            Command::SetBgpRouterId(None)
        }
        BgpNetwork | NoBgpNetwork => {
            let Some(token) = args.first() else {
                return pending(vec!["<network-address>"]);
            };
            let address = ip(token)?;
            let Some(token) = args.get(1) else {
                return pending(vec!["mask"]);
            };
            unique_choice(token, &["mask"])?;
            let Some(token) = args.get(2) else {
                return pending(vec!["<netmask>"]);
            };
            let config = Ipv4InterfaceConfig::from_mask(address, ip(token)?)
                .map_err(|_| invalid(token.offset, "invalid contiguous mask"))?;
            exact(3)?;
            Command::SetBgpNetwork {
                prefix: Ipv4Network::new(address, config.prefix_len())
                    .map_err(|_| invalid(token.offset, "invalid network"))?,
                present: matches!(action, BgpNetwork),
            }
        }
        BgpNeighbor | NoBgpNeighbor => {
            let Some(token) = args.first() else {
                return pending(vec!["<neighbor-address>"]);
            };
            let address = ip(token)?;
            let present = matches!(action, BgpNeighbor);
            let choices = vec!["remote-as", "update-source", "next-hop-self"];
            let Some(token) = args.get(1) else {
                if present {
                    return pending(choices);
                }
                let mut choices = choices;
                choices.push("<cr>");
                return Ok(ospf::Options {
                    command: Some(Command::SetBgpNeighbor {
                        address,
                        option: BgpNeighborOption::Remove,
                    }),
                    choices,
                });
            };
            let word = unique_choice(token, &choices)?;
            let option = match word {
                "next-hop-self" => {
                    exact(2)?;
                    BgpNeighborOption::NextHopSelf(present)
                }
                "remote-as" if !present && args.len() == 2 => BgpNeighborOption::Remove,
                "remote-as" => {
                    let Some(token) = args.get(2) else {
                        return pending(vec!["<1-4294967294>"]);
                    };
                    let remote_as = asn(token)?;
                    exact(3)?;
                    if present {
                        BgpNeighborOption::RemoteAs(remote_as)
                    } else {
                        BgpNeighborOption::Remove
                    }
                }
                _ if !present => {
                    exact(2)?;
                    BgpNeighborOption::UpdateSource(None)
                }
                _ => {
                    if args.len() == 2 {
                        return pending(vec!["<interface>"]);
                    }
                    let name = args[2..].iter().map(|t| t.text).collect::<String>();
                    let (name, _) = canonical_interface(&name)
                        .map_err(|_| invalid(args[2].offset, "invalid interface"))?;
                    BgpNeighborOption::UpdateSource(Some(name))
                }
            };
            Command::SetBgpNeighbor { address, option }
        }
        _ => return Err(invalid(0, "invalid BGP grammar")),
    };
    Ok(ospf::Options {
        command: Some(command),
        choices: vec!["<cr>"],
    })
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
