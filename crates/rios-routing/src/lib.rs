//! Dynamic routing protocol state and wire messages, independent of devices and CLI.
#![forbid(unsafe_code)]

mod ospf;
pub use ospf::*;

mod ospf_wire;
pub use ospf_wire::*;
