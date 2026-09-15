//! BGP operational output rendered from session and selected path state.
use super::*;
use std::fmt::Write;
impl Device {
    /// Render peer session state and accepted prefix counts.
    pub fn show_ip_bgp_summary(&self) -> String {
        let mut out = format!(
            "BGP router identifier {}, local AS number {}\nNeighbor        AS          State/PfxRcd\n",
            self.bgp
                .router_id
                .map_or_else(|| "unassigned".into(), |id| id.to_string()),
            self.bgp.local_as.unwrap_or(0)
        );
        for peer in self.bgp_neighbors() {
            let value = if peer.state == BgpState::Established {
                peer.prefixes.to_string()
            } else {
                format!("{:?}", peer.state)
            };
            let _ = writeln!(out, "{:<15} {:<11} {value}", peer.address, peer.remote_as);
        }
        out
    }
    /// Render neighbor identity, session uptime and last notification.
    pub fn show_ip_bgp_neighbors(&self, now: SimTime) -> String {
        let mut out = String::new();
        for peer in self.bgp_neighbors() {
            let _ = writeln!(
                out,
                "BGP neighbor is {}, remote AS {}\n  State {:?}, router ID {}\n  {} received prefixes, established for {} seconds",
                peer.address,
                peer.remote_as,
                peer.state,
                peer.router_id
                    .map_or_else(|| "unassigned".into(), |id| id.to_string()),
                peer.prefixes,
                peer.established_since
                    .map_or(0, |since| now.0.saturating_sub(since.0) / 1_000_000)
            );
            if let Some(error) = peer.last_error {
                let _ = writeln!(out, "  Last notification {}/{}", error.code, error.subcode);
            }
        }
        out
    }
    /// Render selected BGP paths and their attributes.
    pub fn show_ip_bgp(&self) -> String {
        let mut out = String::from(
            "Status: * valid, > best\n   Network              Next Hop        Metric LocPrf Path\n",
        );
        for path in self.bgp.best.values() {
            let a = &path.attributes;
            let _ = write!(
                out,
                "*> {:<20} {:<15} {:>6} {:>6}",
                format!("{}/{}", path.prefix.address(), path.prefix.prefix_len()),
                a.next_hop,
                a.med.unwrap_or(0),
                a.local_preference.unwrap_or(100)
            );
            for segment in &a.as_path {
                for asn in segment.members() {
                    let _ = write!(out, " {asn}");
                }
            }
            let _ = writeln!(
                out,
                " {}",
                match a.origin {
                    BgpOrigin::Igp => "i",
                    BgpOrigin::Egp => "e",
                    BgpOrigin::Incomplete => "?",
                }
            );
        }
        out
    }
}
