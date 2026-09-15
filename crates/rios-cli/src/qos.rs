//! Typed MQC commands shared by all frontends.
use rios_config::QosRate;
use std::collections::BTreeSet;
/// One validated syntactic QoS edit; device APIs enforce configuration constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QosCommand {
    EnterClass { name: String, match_all: bool },
    RemoveClass(String),
    Dscp(BTreeSet<u8>),
    Precedence(BTreeSet<u8>),
    MatchAcl { name: String, present: bool },
    EnterPolicy(String),
    RemovePolicy(String),
    EnterPolicyClass(String),
    RemovePolicyClass(String),
    Bandwidth(Option<u64>),
    Priority(Option<QosRate>),
    Police(Option<QosRate>),
    Shape(Option<QosRate>),
    BindOutput { name: String, present: bool },
    ShowInterface(Option<String>),
}
