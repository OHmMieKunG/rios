use rios_ipv4::{Ipv4Network, checksum};
use rios_simulator::{InterfaceId, SimTime};
use std::{collections::BTreeSet, net::Ipv4Addr};

/// OSPF AllSPFRouters multicast address.
pub const OSPF_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
/// Default OSPF hello interval in virtual milliseconds.
pub const HELLO_INTERVAL_MS: u64 = 10_000;
/// Default OSPF neighbor dead interval in virtual milliseconds.
pub const DEAD_INTERVAL_MS: u64 = 40_000;

/// OSPF neighbor states retained for protocol-correct progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfNeighborState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

/// One live OSPF neighbor learned on an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfNeighbor {
    pub router_id: Ipv4Addr,
    pub address: Ipv4Addr,
    pub interface: InterfaceId,
    pub state: OspfNeighborState,
    pub dead_at: SimTime,
}

/// Simplified router LSA used by the single-area SPF implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    pub router_id: Ipv4Addr,
    pub sequence: u32,
    pub networks: BTreeSet<Ipv4Network>,
    pub neighbors: BTreeSet<Ipv4Addr>,
}

/// Supported OSPFv2 packet bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfPacket {
    Hello {
        router_id: Ipv4Addr,
        area: u32,
        mask: Ipv4Addr,
        neighbors: BTreeSet<Ipv4Addr>,
    },
    LinkStateUpdate {
        router_id: Ipv4Addr,
        area: u32,
        lsas: Vec<RouterLsa>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OspfPacketError {
    #[error("OSPF packet is truncated or malformed")]
    Malformed,
    #[error("unsupported OSPF packet")]
    Unsupported,
    #[error("invalid OSPF checksum")]
    InvalidChecksum,
}

impl OspfPacket {
    /// Encode an OSPFv2 header and supported packet body with checksum.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, router_id, area, body) = match self {
            Self::Hello {
                router_id,
                area,
                mask,
                neighbors,
            } => {
                let mut body = Vec::with_capacity(20 + neighbors.len() * 4);
                body.extend_from_slice(&mask.octets());
                body.extend_from_slice(&(HELLO_INTERVAL_MS as u16 / 1000).to_be_bytes());
                body.push(0x02);
                body.push(1);
                body.extend_from_slice(&(DEAD_INTERVAL_MS as u32 / 1000).to_be_bytes());
                body.extend_from_slice(&[0; 8]);
                for neighbor in neighbors {
                    body.extend_from_slice(&neighbor.octets());
                }
                (1, *router_id, *area, body)
            }
            Self::LinkStateUpdate {
                router_id,
                area,
                lsas,
            } => {
                let mut body = Vec::new();
                body.extend_from_slice(&(lsas.len() as u32).to_be_bytes());
                for lsa in lsas {
                    body.extend_from_slice(&lsa.router_id.octets());
                    body.extend_from_slice(&lsa.sequence.to_be_bytes());
                    body.extend_from_slice(&(lsa.networks.len() as u16).to_be_bytes());
                    body.extend_from_slice(&(lsa.neighbors.len() as u16).to_be_bytes());
                    for network in &lsa.networks {
                        body.extend_from_slice(&network.address().octets());
                        body.push(network.prefix_len());
                    }
                    for neighbor in &lsa.neighbors {
                        body.extend_from_slice(&neighbor.octets());
                    }
                }
                (4, *router_id, *area, body)
            }
        };
        let mut bytes = vec![0; 24];
        bytes[0] = 2;
        bytes[1] = kind;
        bytes[2..4].copy_from_slice(&((24 + body.len()) as u16).to_be_bytes());
        bytes[4..8].copy_from_slice(&router_id.octets());
        bytes[8..12].copy_from_slice(&area.to_be_bytes());
        bytes.extend_from_slice(&body);
        let value = checksum(&bytes);
        bytes[12..14].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Decode and validate one supported OSPFv2 packet.
    pub fn decode(bytes: &[u8]) -> Result<Self, OspfPacketError> {
        if bytes.len() < 24 || bytes[0] != 2 {
            return Err(OspfPacketError::Malformed);
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if length != bytes.len() || checksum(bytes) != 0 {
            return Err(OspfPacketError::InvalidChecksum);
        }
        let router_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let area = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let body = &bytes[24..];
        match bytes[1] {
            1 => {
                if body.len() < 20 || !(body.len() - 20).is_multiple_of(4) {
                    return Err(OspfPacketError::Malformed);
                }
                let mask = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                let neighbors = body[20..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                    .collect();
                Ok(Self::Hello {
                    router_id,
                    area,
                    mask,
                    neighbors,
                })
            }
            4 => {
                if body.len() < 4 {
                    return Err(OspfPacketError::Malformed);
                }
                let count = usize::try_from(u32::from_be_bytes(body[0..4].try_into().unwrap()))
                    .map_err(|_| OspfPacketError::Malformed)?;
                let mut offset = 4;
                let mut lsas = Vec::with_capacity(count);
                for _ in 0..count {
                    if body.len() < offset + 12 {
                        return Err(OspfPacketError::Malformed);
                    }
                    let id = Ipv4Addr::new(
                        body[offset],
                        body[offset + 1],
                        body[offset + 2],
                        body[offset + 3],
                    );
                    let sequence =
                        u32::from_be_bytes(body[offset + 4..offset + 8].try_into().unwrap());
                    let networks = usize::from(u16::from_be_bytes(
                        body[offset + 8..offset + 10].try_into().unwrap(),
                    ));
                    let neighbors = usize::from(u16::from_be_bytes(
                        body[offset + 10..offset + 12].try_into().unwrap(),
                    ));
                    offset += 12;
                    if body.len() < offset + networks * 5 + neighbors * 4 {
                        return Err(OspfPacketError::Malformed);
                    }
                    let mut prefixes = BTreeSet::new();
                    for _ in 0..networks {
                        prefixes.insert(
                            Ipv4Network::new(
                                Ipv4Addr::new(
                                    body[offset],
                                    body[offset + 1],
                                    body[offset + 2],
                                    body[offset + 3],
                                ),
                                body[offset + 4],
                            )
                            .map_err(|_| OspfPacketError::Malformed)?,
                        );
                        offset += 5;
                    }
                    let mut adjacency = BTreeSet::new();
                    for _ in 0..neighbors {
                        adjacency.insert(Ipv4Addr::new(
                            body[offset],
                            body[offset + 1],
                            body[offset + 2],
                            body[offset + 3],
                        ));
                        offset += 4;
                    }
                    lsas.push(RouterLsa {
                        router_id: id,
                        sequence,
                        networks: prefixes,
                        neighbors: adjacency,
                    });
                }
                if offset != body.len() {
                    return Err(OspfPacketError::Malformed);
                }
                Ok(Self::LinkStateUpdate {
                    router_id,
                    area,
                    lsas,
                })
            }
            _ => Err(OspfPacketError::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ospf_packets_round_trip() {
        let hello = OspfPacket::Hello {
            router_id: "1.1.1.1".parse().unwrap(),
            area: 0,
            mask: "255.255.255.252".parse().unwrap(),
            neighbors: ["2.2.2.2".parse().unwrap()].into(),
        };
        assert_eq!(OspfPacket::decode(&hello.encode()).unwrap(), hello);
        let lsa = RouterLsa {
            router_id: "1.1.1.1".parse().unwrap(),
            sequence: 7,
            networks: [Ipv4Network::new("10.0.0.0".parse().unwrap(), 24).unwrap()].into(),
            neighbors: ["2.2.2.2".parse().unwrap()].into(),
        };
        let update = OspfPacket::LinkStateUpdate {
            router_id: "1.1.1.1".parse().unwrap(),
            area: 0,
            lsas: vec![lsa],
        };
        assert_eq!(OspfPacket::decode(&update.encode()).unwrap(), update);
    }
}
