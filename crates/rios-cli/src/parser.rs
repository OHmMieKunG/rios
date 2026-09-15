mod acl;
use crate::{
    tree::{Action, Node, tree},
    *,
};
use rios_device::canonical_interface;
use std::fmt;

/// Parser output distinguishes informational input from executable commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedInput {
    Empty,
    Help(String),
    Command(Command),
}
/// Structured syntax failure with the original byte position for terminal rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Ambiguous(String),
    Incomplete,
    Invalid { offset: usize, reason: String },
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambiguous(input) => write!(f, "% Ambiguous command: \"{input}\""),
            Self::Incomplete => write!(f, "% Incomplete command."),
            Self::Invalid { reason, .. } => {
                write!(f, "% Invalid input detected at '^' marker.\n% {reason}")
            }
        }
    }
}
impl std::error::Error for ParseError {}
impl ParseError {
    /// Align the caret with the offending token after a frontend's prompt.
    pub fn render(&self, prompt: &str, input: &str) -> String {
        match self {
            Self::Invalid { offset, .. } => {
                let width = prompt.chars().count()
                    + input
                        .chars()
                        .take_while({
                            let mut bytes = 0;
                            move |c| {
                                bytes += c.len_utf8();
                                bytes <= *offset
                            }
                        })
                        .count();
                format!("{}^\n{self}\n", " ".repeat(width))
            }
            _ => format!("{self}\n"),
        }
    }
}
fn invalid(offset: usize, reason: impl Into<String>) -> ParseError {
    ParseError::Invalid {
        offset,
        reason: reason.into(),
    }
}
struct Token<'a> {
    text: &'a str,
    offset: usize,
}
fn tokens(input: &str) -> Vec<Token<'_>> {
    let mut cursor = 0;
    input
        .split_whitespace()
        .map(|text| {
            let offset = cursor + input[cursor..].find(text).unwrap();
            cursor = offset + text.len();
            Token { text, offset }
        })
        .collect()
}
fn resolve<'a>(node: &'a Node, token: &Token<'_>, input: &str) -> Result<&'a Node, ParseError> {
    if let Some(exact) = node
        .children
        .iter()
        .find(|n| n.word.eq_ignore_ascii_case(token.text))
    {
        return Ok(exact);
    }
    let mut candidates = node
        .children
        .iter()
        .filter(|n| n.word.starts_with(&token.text.to_ascii_lowercase()));
    match (candidates.next(), candidates.next()) {
        (Some(node), None) => Ok(node),
        (Some(_), Some(_)) => Err(ParseError::Ambiguous(input.into())),
        _ => Err(invalid(token.offset, "unknown command")),
    }
}
/// Parse without changing the session or device. Abbreviations use unique tree prefixes.
pub fn parse(input: &str, mode: CliMode) -> Result<ParsedInput, ParseError> {
    parse_input(input, mode, true)
}

pub(crate) fn parse_configuration(input: &str, mode: CliMode) -> Result<ParsedInput, ParseError> {
    parse_input(input, mode, false)
}

fn parse_input(
    input: &str,
    mode: CliMode,
    contextual_help: bool,
) -> Result<ParsedInput, ParseError> {
    if let Some((offset, _)) = input
        .char_indices()
        .find(|(_, c)| c.is_control() && *c != '\t')
    {
        return Err(invalid(offset, "control character in command"));
    }
    if contextual_help && input.trim_end().ends_with('?') {
        let before = input.trim_end().strip_suffix('?').unwrap();
        let list = suggestions(before, mode, &[])?;
        return Ok(ParsedInput::Help(
            list.into_iter()
                .map(|s| format!("  {:<20} {}\n", s.word, s.help))
                .collect(),
        ));
    }
    let words = tokens(input);
    if words.is_empty() {
        return Ok(ParsedInput::Empty);
    }
    if matches!(mode, CliMode::AccessListConfiguration(_, _))
        && words[0].text.bytes().all(|byte| byte.is_ascii_digit())
    {
        let sequence = words[0]
            .text
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0 && *value < u32::MAX)
            .ok_or_else(|| invalid(words[0].offset, "invalid sequence"))?;
        let offset = words.get(1).ok_or(ParseError::Incomplete)?.offset;
        let parsed = parse_input(&input[offset..], mode, false)
            .map_err(|error| shift_error(error, offset, input))?;
        let ParsedInput::Command(Command::AddAclEntry { entry, .. }) = parsed else {
            return Err(invalid(offset, "expected permit, deny, or remark"));
        };
        return Ok(ParsedInput::Command(Command::AddAclEntry {
            sequence: Some(sequence),
            entry,
        }));
    }
    let root = tree(mode);
    let mut node = &root;
    let mut index = 0;
    while index < words.len() {
        match resolve(node, &words[index], input) {
            Ok(next) => {
                node = next;
                index += 1;
            }
            Err(ParseError::Invalid { .. }) if node.action.is_some() => break,
            Err(error) => return Err(error),
        }
    }
    let action = node.action.ok_or(ParseError::Incomplete)?;
    let args = &words[index..];
    let expected = match action {
        Action::Address | Action::AccessList | Action::NatOverload | Action::Do | Action::Dot1q => {
            usize::MAX
        }
        Action::StaticRoute | Action::NoStaticRoute => 3,
        Action::AccessGroup => 2,
        Action::DhcpNetwork => 2,
        Action::Hostname
        | Action::Ping
        | Action::Vlan
        | Action::NoVlan
        | Action::VlanName
        | Action::NativeVlan
        | Action::SwitchportAccessVlan
        | Action::SwitchportTrunkAllowed
        | Action::DhcpPool
        | Action::DhcpDefaultRouter => 1,
        Action::RouterOspf => 1,
        Action::OspfNetwork => 4,
        Action::Interface
        | Action::Description
        | Action::AclPermit
        | Action::AclDeny
        | Action::AclRemark => usize::MAX,
        Action::NamedStandardAcl | Action::NamedExtendedAcl | Action::NoAclSequence => 1,
        _ => 0,
    };
    if expected > 0 && args.is_empty() || expected != usize::MAX && args.len() < expected {
        return Err(ParseError::Incomplete);
    }
    if expected != usize::MAX && args.len() > expected {
        return Err(invalid(args[expected].offset, "unexpected argument"));
    }
    let parse_ip = |i: usize| {
        args[i]
            .text
            .parse::<Ipv4Addr>()
            .map_err(|_| invalid(args[i].offset, "expected an IPv4 address"))
    };
    let parse_vlan = |value: &str, offset: usize| {
        value
            .parse::<u16>()
            .ok()
            .and_then(|value| VlanId::new(value).ok())
            .ok_or_else(|| invalid(offset, "expected a VLAN ID from 1 to 4094"))
    };
    use Action::*;
    let command = match action {
        NamedStandardAcl | NamedExtendedAcl => Command::EnterAccessList {
            name: args[0].text.into(),
            kind: if matches!(action, NamedStandardAcl) {
                rios_config::AclKind::Standard
            } else {
                rios_config::AclKind::Extended
            },
        },
        NoAclSequence => Command::RemoveAclEntry(
            args[0]
                .text
                .parse::<u32>()
                .map_err(|_| invalid(args[0].offset, "expected sequence number"))?,
        ),
        AclPermit | AclDeny => {
            let CliMode::AccessListConfiguration(_, kind) = mode else {
                return Err(invalid(0, "not in ACL configuration mode"));
            };
            Command::AddAclEntry {
                sequence: None,
                entry: acl::parse_entry(
                    args,
                    kind,
                    if matches!(action, AclPermit) {
                        AccessListAction::Permit
                    } else {
                        AccessListAction::Deny
                    },
                )?,
            }
        }
        AclRemark => Command::AddAclEntry {
            sequence: None,
            entry: rios_config::AclEntry::Remark(input[args[0].offset..].trim_end().into()),
        },
        Enable => Command::Enable,
        Disable => Command::Disable,
        Configure => Command::ConfigureTerminal,
        Do => {
            let offset = args[0].offset;
            let parsed =
                parse_input(&input[offset..], CliMode::PrivilegedExec, false).map_err(|error| {
                    match error {
                        ParseError::Invalid {
                            offset: inner,
                            reason,
                        } => invalid(offset + inner, reason),
                        ParseError::Ambiguous(_) => ParseError::Ambiguous(input.into()),
                        ParseError::Incomplete => ParseError::Incomplete,
                    }
                })?;
            let ParsedInput::Command(command) = parsed else {
                return Err(ParseError::Incomplete);
            };
            if !matches!(
                command,
                Command::ShowRunningConfig
                    | Command::ShowStartupConfig
                    | Command::ShowInterfaces
                    | Command::ShowInterfacesStatus
                    | Command::ShowIpInterfaceBrief
                    | Command::ShowIpRoute
                    | Command::ShowArp
                    | Command::ShowMacAddressTable
                    | Command::ShowVlanBrief
                    | Command::ShowIpOspfNeighbor
                    | Command::ShowIpOspfInterface
                    | Command::ShowIpOspfDatabase
                    | Command::ShowSpanningTree
                    | Command::ShowAccessLists
                    | Command::ShowIpDhcpBinding
                    | Command::ShowIpNatTranslations
                    | Command::SaveConfig
                    | Command::Ping(_)
            ) {
                return Err(invalid(offset, "command is not available after do"));
            }
            Command::Do(Box::new(command))
        }
        Hostname => Command::Hostname(args[0].text.into()),
        Interface => {
            if args
                .first()
                .is_some_and(|token| "range".starts_with(&token.text.to_ascii_lowercase()))
            {
                if args.len() < 2 {
                    return Err(ParseError::Incomplete);
                }
                let value = args[1..].iter().map(|token| token.text).collect::<String>();
                let (first, last) = parse_interface_range(&value, args[1].offset)?;
                return Ok(ParsedInput::Command(Command::EnterInterfaceRange {
                    first,
                    last,
                }));
            }
            if args.len() > 2 {
                return Err(invalid(args[2].offset, "unexpected argument"));
            }
            if args.len() == 2 && !args[0].text.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(invalid(args[1].offset, "unexpected interface suffix"));
            }
            let value = args.iter().map(|t| t.text).collect::<String>();
            let (name, _) =
                canonical_interface(&value).map_err(|e| invalid(args[0].offset, e.to_string()))?;
            Command::EnterInterface(name)
        }
        Description => Command::Description(input[args[0].offset..].trim_end().into()),
        NoDescription => Command::NoDescription,
        Address => {
            if args.len() == 1
                && !args[0].text.is_empty()
                && "dhcp".starts_with(&args[0].text.to_ascii_lowercase())
            {
                Command::SetIpv4Dhcp
            } else {
                if args.is_empty() {
                    return Err(ParseError::Incomplete);
                }
                if args.len() < 2 {
                    return Err(ParseError::Incomplete);
                }
                if args.len() > 2 {
                    return Err(invalid(args[2].offset, "unexpected argument"));
                }
                Command::SetIpv4Address(
                    Ipv4InterfaceConfig::from_mask(parse_ip(0)?, parse_ip(1)?)
                        .map_err(|e| invalid(args[1].offset, e.to_string()))?,
                )
            }
        }
        NoAddress => Command::NoIpv4Address,
        IpRouting => Command::IpRouting,
        NoIpRouting => Command::NoIpRouting,
        StaticRoute => {
            let address = parse_ip(0)?;
            let configured = Ipv4InterfaceConfig::from_mask(address, parse_ip(1)?)
                .map_err(|error| invalid(args[1].offset, error.to_string()))?;
            Command::SetStaticRoute {
                prefix: rios_ipv4::Ipv4Network::new(address, configured.prefix_len()).unwrap(),
                next_hop: parse_ip(2)?,
            }
        }
        NoStaticRoute => {
            let address = parse_ip(0)?;
            let configured = Ipv4InterfaceConfig::from_mask(address, parse_ip(1)?)
                .map_err(|error| invalid(args[1].offset, error.to_string()))?;
            Command::RemoveStaticRoute {
                prefix: rios_ipv4::Ipv4Network::new(address, configured.prefix_len()).unwrap(),
                next_hop: parse_ip(2)?,
            }
        }
        AccessList => {
            if args.len() < 3 {
                return Err(ParseError::Incomplete);
            }
            if parse_access_list_id(&args[0]).is_err() {
                let number = args[0]
                    .text
                    .parse::<u16>()
                    .map_err(|_| invalid(args[0].offset, "expected ACL number"))?;
                let kind = if (100..=199).contains(&number) || (2000..=2699).contains(&number) {
                    rios_config::AclKind::Extended
                } else if (1300..=1999).contains(&number) {
                    rios_config::AclKind::Standard
                } else {
                    return Err(invalid(args[0].offset, "invalid ACL number"));
                };
                let action = unique_choice(&args[1], &["permit", "deny"])?;
                return Ok(ParsedInput::Command(Command::AddNumberedAcl {
                    name: number.to_string(),
                    kind,
                    entry: acl::parse_entry(
                        &args[2..],
                        kind,
                        if action == "permit" {
                            AccessListAction::Permit
                        } else {
                            AccessListAction::Deny
                        },
                    )?,
                }));
            }
            let id = parse_access_list_id(&args[0])?;
            let action = unique_choice(&args[1], &["permit", "deny"])?;
            let (source, wildcard) = match args[2].text.to_ascii_lowercase().as_str() {
                "any" if args.len() == 3 => {
                    (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(255, 255, 255, 255))
                }
                "host" if args.len() == 4 => (parse_ip(3)?, Ipv4Addr::UNSPECIFIED),
                _ if args.len() == 4 => (parse_ip(2)?, parse_ip(3)?),
                _ if args.len() < 4 => return Err(ParseError::Incomplete),
                _ => return Err(invalid(args[4].offset, "unexpected argument")),
            };
            Command::AddStandardAccessList {
                id,
                entry: StandardAccessListEntry {
                    action: if action == "permit" {
                        AccessListAction::Permit
                    } else {
                        AccessListAction::Deny
                    },
                    source,
                    wildcard,
                },
            }
        }
        AccessGroup => {
            let direction = match unique_choice(&args[1], &["in", "out"])? {
                "in" => AccessListDirection::In,
                _ => AccessListDirection::Out,
            };
            match parse_access_list_id(&args[0]) {
                Ok(id) => Command::SetAccessGroup { id, direction },
                Err(_) => Command::SetNamedAccessGroup {
                    name: args[0].text.into(),
                    direction,
                },
            }
        }
        DhcpPool => Command::EnterDhcpPool(args[0].text.into()),
        DhcpNetwork => {
            let address = parse_ip(0)?;
            let configured = Ipv4InterfaceConfig::from_mask(address, parse_ip(1)?)
                .map_err(|error| invalid(args[1].offset, error.to_string()))?;
            Command::SetDhcpPoolNetwork(Ipv4Network::new(address, configured.prefix_len()).unwrap())
        }
        DhcpDefaultRouter => Command::SetDhcpDefaultRouter(parse_ip(0)?),
        NatInside => Command::SetNatRole(NatRole::Inside),
        NatOutside => Command::SetNatRole(NatRole::Outside),
        NatOverload => {
            if args.len() < 5 {
                return Err(ParseError::Incomplete);
            }
            if args.len() > 6 {
                return Err(invalid(args[6].offset, "unexpected argument"));
            }
            unique_choice(&args[0], &["list"])?;
            let access_list = parse_access_list_id(&args[1])?;
            unique_choice(&args[2], &["interface"])?;
            unique_choice(args.last().unwrap(), &["overload"])?;
            let value = args[3..args.len() - 1]
                .iter()
                .map(|token| token.text)
                .collect::<String>();
            let (outside_interface, _) = canonical_interface(&value)
                .map_err(|error| invalid(args[3].offset, error.to_string()))?;
            Command::SetNatOverload {
                access_list,
                outside_interface,
            }
        }
        Dot1q => {
            if args.len() > 2 {
                return Err(invalid(args[2].offset, "unexpected argument"));
            }
            if args.len() == 2 {
                unique_choice(&args[1], &["native"])?;
            }
            Command::SetDot1q {
                vlan: parse_vlan(args[0].text, args[0].offset)?,
                native: args.len() == 2,
            }
        }
        NativeVlan => Command::SetNativeVlan(parse_vlan(args[0].text, args[0].offset)?),
        Vlan => Command::EnterVlan(parse_vlan(args[0].text, args[0].offset)?),
        NoVlan => Command::RemoveVlan(parse_vlan(args[0].text, args[0].offset)?),
        VlanName => Command::NameVlan(args[0].text.into()),
        SwitchportAccessMode => Command::SetSwitchportMode(SwitchportMode::Access),
        SwitchportTrunkMode => Command::SetSwitchportMode(SwitchportMode::Trunk),
        SwitchportAccessVlan => Command::SetAccessVlan(parse_vlan(args[0].text, args[0].offset)?),
        SwitchportTrunkAllowed => Command::SetTrunkAllowedVlans(
            args[0]
                .text
                .split(',')
                .map(|value| parse_vlan(value, args[0].offset))
                .collect::<Result<_, _>>()?,
        ),
        RouterOspf => Command::EnterRouterOspf(
            args[0]
                .text
                .parse::<u16>()
                .ok()
                .filter(|id| *id != 0)
                .ok_or_else(|| invalid(args[0].offset, "expected a nonzero process ID"))?,
        ),
        OspfNetwork => {
            if !"area".starts_with(&args[2].text.to_ascii_lowercase()) {
                return Err(invalid(args[2].offset, "expected area"));
            }
            Command::AddOspfNetwork(OspfNetworkConfig {
                address: parse_ip(0)?,
                wildcard: parse_ip(1)?,
                area: args[3]
                    .text
                    .parse()
                    .map_err(|_| invalid(args[3].offset, "expected a numeric area ID"))?,
            })
        }
        OspfNeighbor => Command::ShowIpOspfNeighbor,
        OspfInterface => Command::ShowIpOspfInterface,
        OspfDatabase => Command::ShowIpOspfDatabase,
        SpanningTree => Command::ShowSpanningTree,
        ShowAccessLists => Command::ShowAccessLists,
        ShowDhcpBinding => Command::ShowIpDhcpBinding,
        ShowNatTranslations => Command::ShowIpNatTranslations,
        Shutdown => Command::Shutdown,
        NoShutdown => Command::NoShutdown,
        Switchport => Command::Switchport,
        NoSwitchport => Command::NoSwitchport,
        Running => Command::ShowRunningConfig,
        Startup => Command::ShowStartupConfig,
        Interfaces => Command::ShowInterfaces,
        InterfacesStatus => Command::ShowInterfacesStatus,
        Brief => Command::ShowIpInterfaceBrief,
        Save => Command::SaveConfig,
        Ping => Command::Ping(parse_ip(0)?),
        Exit => Command::Exit,
        End => Command::End,
        Routes => Command::ShowIpRoute,
        Arp => Command::ShowArp,
        MacTable => Command::ShowMacAddressTable,
        VlanBrief => Command::ShowVlanBrief,
        DebugPacket => Command::NetworkUnavailable(NetworkFeature::DebugPacket),
        DebugArp => Command::NetworkUnavailable(NetworkFeature::DebugArp),
        DebugIcmp => Command::NetworkUnavailable(NetworkFeature::DebugIcmp),
    };
    Ok(ParsedInput::Command(command))
}

fn shift_error(error: ParseError, base: usize, input: &str) -> ParseError {
    match error {
        ParseError::Invalid { offset, reason } => invalid(offset + base, reason),
        ParseError::Ambiguous(_) => ParseError::Ambiguous(input.into()),
        other => other,
    }
}

fn parse_interface_range(value: &str, offset: usize) -> Result<(String, String), ParseError> {
    let (first, last) = value
        .split_once('-')
        .filter(|(first, last)| !first.is_empty() && !last.is_empty())
        .ok_or_else(|| invalid(offset, "expected an interface range"))?;
    let (first, first_kind) =
        canonical_interface(first).map_err(|error| invalid(offset, error.to_string()))?;
    let last = if last
        .chars()
        .any(|character| character.is_ascii_alphabetic())
    {
        last.into()
    } else {
        let split = first.rfind('/').map_or_else(
            || {
                first
                    .find(|character: char| character.is_ascii_digit())
                    .unwrap()
            },
            |index| index + 1,
        );
        format!("{}{last}", &first[..split])
    };
    let (last, last_kind) =
        canonical_interface(&last).map_err(|error| invalid(offset, error.to_string()))?;
    let (first_stem, first_number) = interface_sequence(&first).unwrap();
    let (last_stem, last_number) = interface_sequence(&last).unwrap();
    if first_kind != last_kind || first_stem != last_stem || first_number > last_number {
        return Err(invalid(
            offset,
            "range endpoints must use one interface slot in ascending order",
        ));
    }
    Ok((first, last))
}

fn interface_sequence(name: &str) -> Option<(&str, u16)> {
    let split = name.rfind(|character: char| !character.is_ascii_digit())? + 1;
    Some((&name[..split], name[split..].parse().ok()?))
}

fn parse_access_list_id(token: &Token<'_>) -> Result<AccessListId, ParseError> {
    token
        .text
        .parse::<u8>()
        .ok()
        .and_then(AccessListId::new)
        .ok_or_else(|| {
            invalid(
                token.offset,
                "expected a standard access-list number from 1 to 99",
            )
        })
}

fn unique_choice<'a>(token: &Token<'_>, choices: &'a [&str]) -> Result<&'a str, ParseError> {
    let input = token.text.to_ascii_lowercase();
    let mut matches = choices
        .iter()
        .copied()
        .filter(|value| value.starts_with(&input));
    match (matches.next(), matches.next()) {
        (Some(value), None) => Ok(value),
        _ => Err(invalid(token.offset, "invalid or ambiguous argument")),
    }
}
/// One tree-derived contextual help or completion candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub word: String,
    pub help: String,
    pub start: usize,
}
/// Complete at the end of `input`; callers pass the buffer prefix before the cursor.
pub fn suggestions(
    input: &str,
    mode: CliMode,
    interfaces: &[String],
) -> Result<Vec<Suggestion>, ParseError> {
    let words = tokens(input);
    let trailing = input.chars().last().is_some_and(char::is_whitespace);
    let (complete, partial, start) = if trailing || words.is_empty() {
        (&words[..], "", input.len())
    } else {
        (
            &words[..words.len() - 1],
            words.last().unwrap().text,
            words.last().unwrap().offset,
        )
    };
    if matches!(mode, CliMode::AccessListConfiguration(_, _))
        && complete
            .first()
            .is_some_and(|token| token.text.bytes().all(|byte| byte.is_ascii_digit()))
    {
        let offset = words.get(1).map_or(input.len(), |token| token.offset);
        let mut result = suggestions(&input[offset..], mode, interfaces)
            .map_err(|error| shift_error(error, offset, input))?;
        for item in &mut result {
            item.start += offset;
        }
        return Ok(result);
    }
    let root = tree(mode);
    let mut node = &root;
    let mut used = 0;
    while used < complete.len() {
        match resolve(node, &complete[used], input) {
            Ok(next) => {
                node = next;
                used += 1;
            }
            Err(ParseError::Invalid { .. }) if node.action.is_some() => break,
            Err(error) => return Err(error),
        }
    }
    if matches!(node.action, Some(Action::Do)) {
        let offset = complete.get(used).map_or(start, |token| token.offset);
        let mut delegated = suggestions(&input[offset..], CliMode::PrivilegedExec, interfaces)?;
        for suggestion in &mut delegated {
            suggestion.start += offset;
        }
        return Ok(delegated);
    }
    let mut result = Vec::new();
    for child in &node.children {
        if child.word.starts_with(&partial.to_ascii_lowercase()) {
            result.push(Suggestion {
                word: child.word.into(),
                help: child.help.into(),
                start,
            });
        }
    }
    if !result.is_empty() {
        if node.action.is_some() && partial.is_empty() {
            result.push(Suggestion {
                word: "<cr>".into(),
                help: String::new(),
                start,
            });
        }
        result.sort_by(|a, b| a.word.cmp(&b.word));
        return Ok(result);
    }
    if let Some(action) = node.action {
        let args = &complete[used..];
        if matches!(action, Action::AclPermit | Action::AclDeny) {
            let CliMode::AccessListConfiguration(_, kind) = mode else {
                return Err(invalid(0, "not in ACL mode"));
            };
            let choices = match acl::entry(args, kind, AccessListAction::Permit, true) {
                Ok(_) => &["<cr>"][..],
                Err(acl::RuleError::Need(choices)) => choices,
                Err(acl::RuleError::Invalid(error)) => return Err(error),
            };
            return Ok(choices
                .iter()
                .filter(|word| {
                    word.starts_with('<') || word.starts_with(&partial.to_ascii_lowercase())
                })
                .map(|word| Suggestion {
                    word: (*word).into(),
                    help: String::new(),
                    start,
                })
                .collect());
        }

        if matches!(action, Action::Interface) {
            if args.is_empty() {
                for family in action.argument_help() {
                    if family
                        .to_ascii_lowercase()
                        .starts_with(&partial.to_ascii_lowercase())
                    {
                        result.push(Suggestion {
                            word: (*family).into(),
                            help: if *family == "range" {
                                "Select an interface range".into()
                            } else {
                                "Interface family".into()
                            },
                            start,
                        });
                    }
                }
                {
                    for name in interfaces {
                        let abbreviated = partial
                            .find(|c: char| c.is_ascii_digit())
                            .and_then(|i| {
                                let (f, n) = partial.split_at(i);
                                let digit = name.find(|c: char| c.is_ascii_digit())?;
                                Some(
                                    name[..digit]
                                        .to_ascii_lowercase()
                                        .starts_with(&f.to_ascii_lowercase())
                                        && name[digit..].starts_with(n),
                                )
                            })
                            .unwrap_or(false);
                        if name
                            .to_ascii_lowercase()
                            .starts_with(&partial.to_ascii_lowercase())
                            || abbreviated
                        {
                            result.push(Suggestion {
                                word: name.clone(),
                                help: "Existing interface".into(),
                                start,
                            });
                        }
                    }
                }
            } else if args.len() == 1 && "range".starts_with(&args[0].text.to_ascii_lowercase()) {
                result.push(Suggestion {
                    word: "<interface-range>".into(),
                    help: "Inclusive interface range".into(),
                    start,
                });
            } else if parse_configuration(input[..start].trim_end(), mode).is_ok() {
                if !partial.is_empty() {
                    return Err(invalid(start, "unexpected argument"));
                }
                result.push(Suggestion {
                    word: "<cr>".into(),
                    help: String::new(),
                    start,
                });
            } else if args.len() == 1
                && action.argument_help().iter().any(|f| {
                    f.to_ascii_lowercase()
                        .starts_with(&args[0].text.to_ascii_lowercase())
                })
            {
                for name in interfaces {
                    let Some(digit) = name.find(|c: char| c.is_ascii_digit()) else {
                        continue;
                    };
                    if name[..digit]
                        .to_ascii_lowercase()
                        .starts_with(&args[0].text.to_ascii_lowercase())
                        && name[digit..].starts_with(partial)
                    {
                        result.push(Suggestion {
                            word: name[digit..].into(),
                            help: "Existing interface number".into(),
                            start,
                        });
                    }
                }
                if result.is_empty() {
                    result.push(Suggestion {
                        word: "<number>".into(),
                        help: "Interface number".into(),
                        start,
                    });
                }
            } else {
                return Err(invalid(args[0].offset, "invalid interface"));
            }
        } else {
            let first_is_dhcp = matches!(action, Action::Address)
                && args
                    .first()
                    .is_some_and(|arg| "dhcp".starts_with(&arg.text.to_ascii_lowercase()));
            if matches!(
                action,
                Action::Address | Action::StaticRoute | Action::NoStaticRoute | Action::DhcpNetwork
            ) && !args.is_empty()
                && !first_is_dhcp
                && args[0].text.parse::<Ipv4Addr>().is_err()
            {
                return Err(invalid(args[0].offset, "expected an IPv4 address"));
            }
            let help = match action {
                Action::Dot1q if args.is_empty() => "<vlan-id>",
                Action::Dot1q if args.len() == 1 => {
                    parse_configuration(input[..start].trim_end(), mode)?;
                    if partial.is_empty() {
                        result.push(Suggestion {
                            word: "<cr>".into(),
                            help: String::new(),
                            start,
                        });
                    }
                    "native"
                }
                Action::Address if args.is_empty() => "dhcp|<address>",
                Action::Address if args.len() == 1 && !first_is_dhcp => "<mask>",
                Action::StaticRoute | Action::NoStaticRoute | Action::DhcpNetwork
                    if args.is_empty() =>
                {
                    "<address>"
                }
                Action::StaticRoute | Action::NoStaticRoute | Action::DhcpNetwork
                    if args.len() == 1 =>
                {
                    "<mask>"
                }
                Action::StaticRoute | Action::NoStaticRoute if args.len() == 2 => "<next-hop>",
                Action::AccessList | Action::AccessGroup if args.is_empty() => "<1-99>",
                Action::AccessList if args.len() == 1 => "permit|deny",
                Action::AccessList if args.len() == 2 => "<source>",
                Action::AccessList
                    if args.len() == 3 && !args[2].text.eq_ignore_ascii_case("any") =>
                {
                    "<wildcard>"
                }
                Action::AccessGroup if args.len() == 1 => "in|out",
                Action::NatOverload if args.is_empty() => "list",
                Action::NatOverload if args.len() == 1 => "<1-99>",
                Action::NatOverload if args.len() == 2 => "interface",
                Action::NatOverload if args.len() == 3 => "<interface>",
                Action::NatOverload if args.len() == 4 => "overload",
                Action::NamedStandardAcl | Action::NamedExtendedAcl | Action::NoAclSequence
                    if args.is_empty() =>
                {
                    action.argument_help()[0]
                }
                Action::AclRemark if args.is_empty() => "<text>",
                Action::Hostname
                | Action::Ping
                | Action::Vlan
                | Action::NoVlan
                | Action::VlanName
                | Action::NativeVlan
                | Action::SwitchportAccessVlan
                | Action::SwitchportTrunkAllowed
                | Action::RouterOspf
                | Action::OspfNetwork
                | Action::DhcpPool
                | Action::DhcpDefaultRouter
                    if args.is_empty() =>
                {
                    action.argument_help()[0]
                }
                Action::Description if args.is_empty() => "<text>",
                _ => "<cr>",
            };
            if help == "<cr>" {
                parse_configuration(input[..start].trim_end(), mode)?;
                if !partial.is_empty() && !matches!(action, Action::Description | Action::AclRemark)
                {
                    return Err(invalid(start, "unexpected argument"));
                }
            }
            result.push(Suggestion {
                word: help.into(),
                help: String::new(),
                start,
            });
        }
    }
    result.sort_by(|a, b| a.word.cmp(&b.word));
    Ok(result)
}
