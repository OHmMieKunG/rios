//! End-to-end Phase 2 frame delivery without OS interfaces or protocol emulation.
use rios_config::AdminState;
use rios_ethernet::{EtherType, EthernetFrame};
use rios_topology::{EventOutcome, Topology};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut lab =
        Topology::from_yaml(include_str!("../../../examples/two-routers.yaml"))?.build()?;
    let a = lab.endpoint("R1:gi0/0")?;
    let b = lab.endpoint("R2:gi0/0")?;
    for endpoint in [a, b] {
        lab.with_device_mut(endpoint.device, |d| {
            d.set_admin_state(endpoint.interface, AdminState::Up)
        })??;
    }
    let source = lab.device(a.device)?.interfaces()[&a.interface].mac_address;
    let destination = lab.device(b.device)?.interfaces()[&b.interface].mac_address;
    lab.set_tracing(true);
    lab.transmit(
        a,
        EthernetFrame {
            source,
            destination,
            ethertype: EtherType::Other(0x88b5),
            payload: b"RIOS virtual Ethernet".to_vec(),
        },
    )?;
    let Some(EventOutcome::FrameReceived { interface, frame }) = lab.step()? else {
        return Err("frame was not delivered".into());
    };
    assert_eq!(interface, b);
    assert_eq!(frame.payload, b"RIOS virtual Ethernet");
    for trace in lab.take_trace() {
        println!(
            "[{}] {} {:?} {} bytes",
            trace.time,
            lab.endpoint_name(trace.interface),
            trace.action,
            trace.length
        );
    }
    println!(
        "{} received {} at {}",
        lab.endpoint_name(interface),
        String::from_utf8_lossy(&frame.payload),
        lab.now()
    );
    Ok(())
}
