//! IPv6 packets, addressing, ICMPv6 and Neighbor Discovery, independent of devices and CLI.
#![forbid(unsafe_code)]
mod address;
mod icmp;
mod nd;
mod packet;
pub use address::*;
pub use icmp::*;
pub use nd::*;
pub use packet::*;
