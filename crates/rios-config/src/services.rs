//! Installed simulated host applications, configured by lab inventory rather than IOS text.
use serde::{Deserialize, Serialize};

/// A service consumes packets through the device's simulated transport stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ServiceConfig {
    UdpEcho {
        #[serde(default = "echo_port")]
        port: u16,
    },
    TcpEcho {
        #[serde(default = "echo_port")]
        port: u16,
    },
    Http {
        #[serde(default = "http_port")]
        port: u16,
        #[serde(default = "http_body")]
        body: String,
    },
}
fn echo_port() -> u16 {
    7
}
fn http_port() -> u16 {
    80
}
fn http_body() -> String {
    "RIOS simulated HTTP server\n".into()
}
impl ServiceConfig {
    /// Configured transport port.
    pub fn port(&self) -> u16 {
        match self {
            Self::UdpEcho { port } | Self::TcpEcho { port } | Self::Http { port, .. } => *port,
        }
    }
    /// Whether this application accepts TCP streams.
    pub fn is_tcp(&self) -> bool {
        !matches!(self, Self::UdpEcho { .. })
    }
}
