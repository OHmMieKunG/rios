//! One rule grammar shared by ACL execution parsing and contextual help.
use super::*;
use rios_config::{AclEntry, AclKind, AclProtocol, AddressMatch, PortMatch};

pub(super) enum RuleError {
    Need(&'static [&'static str]),
    Invalid(ParseError),
}
impl From<ParseError> for RuleError {
    fn from(value: ParseError) -> Self {
        Self::Invalid(value)
    }
}
struct Cursor<'a> {
    args: &'a [Token<'a>],
    position: usize,
    help: bool,
}
impl<'a> Cursor<'a> {
    fn next(&mut self, help: &'static [&'static str]) -> Result<&'a Token<'a>, RuleError> {
        let token = self.args.get(self.position).ok_or(RuleError::Need(help))?;
        self.position += 1;
        Ok(token)
    }
    fn address(&mut self) -> Result<AddressMatch, RuleError> {
        let token = self.next(&["any", "host", "<address>"])?;
        if let Ok(choice) = unique_choice(token, &["any", "host"]) {
            if choice == "any" {
                return Ok(AddressMatch::ANY);
            }
            let host = self.next(&["<address>"])?;
            return Ok(AddressMatch {
                address: ip(host)?,
                wildcard: Ipv4Addr::UNSPECIFIED,
            });
        }
        let address = ip(token)?;
        let wildcard = ip(self.next(&["<wildcard>"])?)?;
        Ok(AddressMatch { address, wildcard })
    }
    fn ports(&mut self, source: bool) -> Result<PortMatch, RuleError> {
        let choices = &["eq", "range", "lt", "gt", "neq"];
        let Some(token) = self.args.get(self.position) else {
            if self.help {
                return Err(RuleError::Need(if source {
                    &["eq", "range", "lt", "gt", "neq", "any", "host", "<address>"]
                } else {
                    &["eq", "range", "lt", "gt", "neq", "log", "<cr>"]
                }));
            }
            return Ok(PortMatch::Any);
        };
        let Ok(operator) = unique_choice(token, choices) else {
            return Ok(PortMatch::Any);
        };
        self.position += 1;
        let first = self.next(&["<port>"])?;
        let first = first
            .text
            .parse::<u16>()
            .map_err(|_| invalid(first.offset, "expected port 0..65535"))?;
        Ok(match operator {
            "eq" => PortMatch::Eq(first),
            "lt" => PortMatch::Lt(first),
            "gt" => PortMatch::Gt(first),
            "neq" => PortMatch::Neq(first),
            _ => {
                let second = self.next(&["<high-port>"])?;
                let high = second
                    .text
                    .parse::<u16>()
                    .map_err(|_| invalid(second.offset, "expected port 0..65535"))?;
                if high < first {
                    return Err(invalid(second.offset, "port range must be ascending").into());
                }
                PortMatch::Range(first, high)
            }
        })
    }
}
fn ip(token: &Token<'_>) -> Result<Ipv4Addr, ParseError> {
    token
        .text
        .parse()
        .map_err(|_| invalid(token.offset, "expected IPv4 address"))
}
pub(super) fn entry(
    args: &[Token<'_>],
    kind: AclKind,
    action: AccessListAction,
    help: bool,
) -> Result<AclEntry, RuleError> {
    let mut cursor = Cursor {
        args,
        position: 0,
        help,
    };
    let protocol = if kind == AclKind::Standard {
        AclProtocol::Ip
    } else {
        match unique_choice(
            cursor.next(&["ip", "icmp", "tcp", "udp"])?,
            &["ip", "icmp", "tcp", "udp"],
        )? {
            "ip" => AclProtocol::Ip,
            "icmp" => AclProtocol::Icmp,
            "tcp" => AclProtocol::Tcp,
            _ => AclProtocol::Udp,
        }
    };
    let source = cursor.address()?;
    let transport = matches!(protocol, AclProtocol::Tcp | AclProtocol::Udp);
    let source_port = if transport {
        cursor.ports(true)?
    } else {
        PortMatch::Any
    };
    let destination = if kind == AclKind::Extended {
        cursor.address()?
    } else {
        AddressMatch::ANY
    };
    let destination_port = if transport {
        cursor.ports(false)?
    } else {
        PortMatch::Any
    };
    let log = if let Some(token) = args.get(cursor.position) {
        unique_choice(token, &["log"])?;
        cursor.position += 1;
        true
    } else {
        if help {
            return Err(RuleError::Need(&["log", "<cr>"]));
        }
        false
    };
    if let Some(extra) = args.get(cursor.position) {
        return Err(invalid(extra.offset, "unexpected argument").into());
    }
    Ok(AclEntry::Rule {
        action,
        protocol,
        source,
        source_port,
        destination,
        destination_port,
        log,
    })
}
pub(super) fn parse_entry(
    args: &[Token<'_>],
    kind: AclKind,
    action: AccessListAction,
) -> Result<AclEntry, ParseError> {
    entry(args, kind, action, false).map_err(|error| match error {
        RuleError::Need(_) => ParseError::Incomplete,
        RuleError::Invalid(error) => error,
    })
}
