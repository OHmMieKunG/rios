//! BGP header, OPEN capability TLVs, UPDATE framing and notifications.
use super::*;
impl BgpMessage {
    /// AS_PATH width follows the capabilities negotiated on this TCP connection.
    pub fn encode(&self, four_octet_as: bool) -> Result<Vec<u8>, BgpError> {
        let mut out = vec![255; 16];
        out.extend([0, 0, 0]);
        out[18] = match self {
            Self::Open(open) => {
                open.validate()?;
                let mut caps = Vec::new();
                for capability in &open.capabilities {
                    let (code, value) = match capability {
                        BgpCapability::FourOctetAs(asn) => (65, asn.to_be_bytes().to_vec()),
                        BgpCapability::Multiprotocol { afi, safi } => {
                            let mut b = afi.to_be_bytes().to_vec();
                            b.extend([0, *safi]);
                            (1, b)
                        }
                        BgpCapability::RouteRefresh => (2, Vec::new()),
                        BgpCapability::Unknown { code, value } => (*code, value.clone()),
                    };
                    if value.len() > 255 || caps.len() + 2 + value.len() > 253 {
                        return Err(BgpError::new(2, 4));
                    }
                    caps.extend([code, value.len() as u8]);
                    caps.extend(value);
                }
                out.push(4);
                out.extend(open.autonomous_system.to_be_bytes());
                out.extend(open.hold_time.to_be_bytes());
                out.extend(open.router_id.octets());
                if caps.is_empty() {
                    out.push(0);
                } else {
                    out.extend([(caps.len() + 2) as u8, 2, caps.len() as u8]);
                    out.extend(caps);
                }
                1
            }
            Self::Update(update) => {
                if !update.announced.is_empty() && update.attributes.is_none() {
                    return Err(BgpError::new(3, 3));
                }
                let withdrawn = encode_prefixes(&update.withdrawn)?;
                let attrs = update
                    .attributes
                    .as_ref()
                    .map(|a| a.encode(four_octet_as))
                    .transpose()?
                    .unwrap_or_default();
                out.extend((withdrawn.len() as u16).to_be_bytes());
                out.extend(withdrawn);
                out.extend(
                    u16::try_from(attrs.len())
                        .map_err(|_| BgpError::new(1, 2))?
                        .to_be_bytes(),
                );
                out.extend(attrs);
                out.extend(encode_prefixes(&update.announced)?);
                2
            }
            Self::Notification {
                code,
                subcode,
                data,
            } => {
                if data.len() > BGP_MAX_MESSAGE - 21 {
                    return Err(BgpError::new(1, 2));
                }
                out.extend([*code, *subcode]);
                out.extend(data);
                3
            }
            Self::Keepalive => 4,
        };
        if out.len() > BGP_MAX_MESSAGE {
            return Err(BgpError::new(1, 2));
        }
        let length = out.len() as u16;
        out[16..18].copy_from_slice(&length.to_be_bytes());
        Ok(out)
    }
    /// Decode exactly one complete frame, with bounds checked before field access.
    pub fn decode(bytes: &[u8], four_octet_as: bool) -> Result<Self, BgpError> {
        if message_length(bytes)? != bytes.len() {
            return Err(BgpError::new(1, 2));
        }
        let b = &bytes[19..];
        match bytes[18] {
            1 => {
                if b.len() < 10 || usize::from(b[9]) + 10 != b.len() {
                    return Err(BgpError::new(1, 2));
                }
                if b[0] != 4 {
                    return Err(BgpError::new(2, 1));
                }
                let mut caps = Vec::new();
                let mut rest = &b[10..];
                while !rest.is_empty() {
                    if rest.len() < 2 {
                        return Err(BgpError::new(2, 4));
                    }
                    let length = usize::from(rest[1]);
                    let mut value = rest.get(2..2 + length).ok_or(BgpError::new(2, 4))?;
                    if rest[0] != 2 {
                        return Err(BgpError::new(2, 4));
                    }
                    while !value.is_empty() {
                        if value.len() < 2 {
                            return Err(BgpError::new(2, 4));
                        }
                        let size = usize::from(value[1]);
                        let content = value.get(2..2 + size).ok_or(BgpError::new(2, 4))?;
                        caps.push(match value[0] {
                            65 if size == 4 => BgpCapability::FourOctetAs(u32_at(content, 0)),
                            1 if size == 4 => BgpCapability::Multiprotocol {
                                afi: u16_at(content, 0),
                                safi: content[3],
                            },
                            2 if size == 0 => BgpCapability::RouteRefresh,
                            1 | 2 | 65 => return Err(BgpError::new(2, 4)),
                            code => BgpCapability::Unknown {
                                code,
                                value: content.to_vec(),
                            },
                        });
                        value = &value[2 + size..];
                    }
                    rest = &rest[2 + length..];
                }
                let open = BgpOpen {
                    autonomous_system: u16_at(b, 1),
                    hold_time: u16_at(b, 3),
                    router_id: ip(&b[5..9]),
                    capabilities: caps,
                };
                open.validate()?;
                Ok(Self::Open(open))
            }
            2 => {
                if b.len() < 4 {
                    return Err(BgpError::new(3, 1));
                }
                let count = usize::from(u16_at(b, 0));
                let withdrawn = decode_prefixes(b.get(2..2 + count).ok_or(BgpError::new(3, 1))?)?;
                let rest = b
                    .get(2 + count..)
                    .filter(|b| b.len() >= 2)
                    .ok_or(BgpError::new(3, 1))?;
                let count = usize::from(u16_at(rest, 0));
                let attrs = rest.get(2..2 + count).ok_or(BgpError::new(3, 1))?;
                let announced = decode_prefixes(&rest[2 + count..])?;
                let attributes = if attrs.is_empty() {
                    None
                } else {
                    Some(BgpAttributes::decode(attrs, four_octet_as)?)
                };
                if !announced.is_empty() && attributes.is_none() {
                    return Err(BgpError::new(3, 3));
                }
                Ok(Self::Update(BgpUpdate {
                    withdrawn,
                    attributes,
                    announced,
                }))
            }
            3 => {
                if b.len() < 2 {
                    return Err(BgpError::new(1, 2));
                }
                Ok(Self::Notification {
                    code: b[0],
                    subcode: b[1],
                    data: b[2..].to_vec(),
                })
            }
            4 if b.is_empty() => Ok(Self::Keepalive),
            _ => Err(BgpError::new(1, 2)),
        }
    }
}
