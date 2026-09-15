//! Dynamic routing protocol state and wire messages, independent of devices and CLI.
#![forbid(unsafe_code)]

mod ospf;
pub use ospf::*;

mod ospf_wire;
pub use ospf_wire::*;

mod ospf_spf;
pub use ospf_spf::*;

mod ospf_exchange;
pub use ospf_exchange::*;

mod lsa_checksum;

mod ospfv3;
pub use ospfv3::*;

mod ospf_election;
pub use ospf_election::*;
