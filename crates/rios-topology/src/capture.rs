//! Streaming PCAPNG observation. File errors never change simulated packet handling.
use crate::{Lab, LabError, TraceAction};
use rios_ethernet::EthernetFrame;
use rios_simulator::{DeviceId, InterfaceRef, SimTime};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

/// Scope of a capture, resolved to stable identities before opening the file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CaptureFilter {
    #[default]
    All,
    Device(DeviceId),
    Interface(InterfaceRef),
}
impl CaptureFilter {
    fn matches(self, interface: InterfaceRef) -> bool {
        match self {
            Self::All => true,
            Self::Device(device) => interface.device == device,
            Self::Interface(port) => interface == port,
        }
    }
}
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Capture {
    writer: PcapNg<BufWriter<File>>,
    filter: CaptureFilter,
    failure: Option<String>,
}
#[derive(Debug)]
struct PcapNg<W: Write> {
    writer: W,
    interfaces: BTreeMap<InterfaceRef, u32>,
    bytes: u64,
}
impl<W: Write> PcapNg<W> {
    fn new(writer: W) -> io::Result<Self> {
        let mut capture = Self {
            writer,
            interfaces: BTreeMap::new(),
            bytes: 0,
        };
        let mut header = Vec::new();
        header.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&u64::MAX.to_le_bytes());
        capture.block(0x0a0d0d0a, &header)?;
        Ok(capture)
    }
    fn block(&mut self, kind: u32, body: &[u8]) -> io::Result<()> {
        let length = u32::try_from(body.len() + 12).map_err(io::Error::other)?;
        if self.bytes.saturating_add(u64::from(length)) > MAX_CAPTURE_BYTES {
            return Err(io::Error::other("capture reached the 1 GiB limit"));
        }
        self.writer.write_all(&kind.to_le_bytes())?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(body)?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.bytes += u64::from(length);
        Ok(())
    }
    fn packet(
        &mut self,
        port: InterfaceRef,
        name: &str,
        time: SimTime,
        action: TraceAction,
        frame: &EthernetFrame,
    ) -> io::Result<()> {
        let id = match self.interfaces.get(&port) {
            Some(id) => *id,
            None => {
                let id = u32::try_from(self.interfaces.len()).map_err(io::Error::other)?;
                let mut body = vec![1, 0, 0, 0]; // LINKTYPE_ETHERNET, reserved.
                body.extend_from_slice(&0u32.to_le_bytes()); // Unlimited snapshot length.
                option(&mut body, 2, name.as_bytes())?;
                option(&mut body, 9, &[6])?; // Decimal microseconds.
                option(&mut body, 0, &[])?;
                self.block(1, &body)?;
                self.interfaces.insert(port, id);
                id
            }
        };
        let data = frame.encode().map_err(io::Error::other)?;
        let length = u32::try_from(data.len()).map_err(io::Error::other)?;
        let mut body = Vec::with_capacity(data.len() + 40);
        for word in [id, (time.0 >> 32) as u32, time.0 as u32, length, length] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        body.extend_from_slice(&data);
        pad(&mut body);
        let flags = if action == TraceAction::Rx { 1u32 } else { 2 };
        option(&mut body, 2, &flags.to_le_bytes())?;
        option(&mut body, 0, &[])?;
        self.block(6, &body)
    }
}
fn pad(body: &mut Vec<u8>) {
    body.resize(body.len().next_multiple_of(4), 0);
}
fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) -> io::Result<()> {
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(io::Error::other)?
            .to_le_bytes(),
    );
    body.extend_from_slice(value);
    pad(body);
    Ok(())
}
impl Lab {
    /// Start a streaming capture. Existing files are never overwritten.
    pub fn start_capture(&mut self, path: &Path, filter: CaptureFilter) -> Result<(), LabError> {
        if self.capture.is_some() {
            return Err(LabError::Capture(
                "capture already running; stop it first".into(),
            ));
        }
        match filter {
            CaptureFilter::All => {}
            CaptureFilter::Device(device) => {
                self.device(device)?;
            }
            CaptureFilter::Interface(port) => {
                if !self
                    .device(port.device)?
                    .interfaces()
                    .contains_key(&port.interface)
                {
                    return Err(LabError::UnknownEndpoint(format!("{port:?}")));
                }
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| LabError::Capture(error.to_string()))?;
        let writer = PcapNg::new(BufWriter::new(file))
            .map_err(|error| LabError::Capture(error.to_string()))?;
        self.capture = Some(Capture {
            writer,
            filter,
            failure: None,
        });
        Ok(())
    }
    /// Flush and close capture, reporting any earlier observation failure.
    pub fn stop_capture(&mut self) -> Result<(), LabError> {
        let Some(mut capture) = self.capture.take() else {
            return Err(LabError::Capture("no capture is running".into()));
        };
        let flush = capture.writer.writer.flush();
        if let Some(error) = capture.failure {
            return Err(LabError::Capture(error));
        }
        flush.map_err(|error| LabError::Capture(error.to_string()))
    }
    /// First capture error, if any; forwarding continues independently.
    pub fn capture_error(&self) -> Option<&str> {
        self.capture
            .as_ref()
            .and_then(|capture| capture.failure.as_deref())
    }
    pub(crate) fn capture_frame(
        &mut self,
        port: InterfaceRef,
        action: TraceAction,
        frame: &EthernetFrame,
    ) {
        if !matches!(action, TraceAction::Tx | TraceAction::Rx) {
            return;
        }
        let Some(capture) = &self.capture else {
            return;
        };
        if capture.failure.is_some() || !capture.filter.matches(port) {
            return;
        }
        // Capture physical wire frames only, avoiding duplicate synthetic SVI observations.
        if !self
            .devices
            .get(&port.device)
            .and_then(|d| d.interfaces().get(&port.interface))
            .is_some_and(|interface| interface.kind.is_ethernet())
        {
            return;
        }
        let name = self.endpoint_name(port);
        let now = self.now();
        if let Some(capture) = &mut self.capture
            && let Err(error) = capture.writer.packet(port, &name, now, action, frame)
        {
            capture.failure = Some(error.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_ethernet::{EtherType, MacAddress};
    use rios_simulator::InterfaceId;
    #[test]
    fn blocks_have_matching_lengths_and_exact_frame_and_timestamp() {
        let mut writer = PcapNg::new(Vec::new()).unwrap();
        let port = InterfaceRef {
            device: DeviceId(1),
            interface: InterfaceId(1),
        };
        let frame = EthernetFrame {
            source: MacAddress([2; 6]),
            destination: MacAddress::BROADCAST,
            ethertype: EtherType::Arp,
            payload: vec![3; 28],
        };
        writer
            .packet(
                port,
                "R1:Gi0/0",
                SimTime(0x123456789),
                TraceAction::Tx,
                &frame,
            )
            .unwrap();
        let bytes = writer.writer;
        let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let mut offset = 0;
        let mut types = Vec::new();
        while offset < bytes.len() {
            let kind = word(offset);
            let length = word(offset + 4) as usize;
            assert_eq!(length % 4, 0);
            assert_eq!(word(offset + length - 4) as usize, length);
            types.push(kind);
            if kind == 6 {
                assert_eq!(
                    (u64::from(word(offset + 12)) << 32) | u64::from(word(offset + 16)),
                    0x123456789
                );
                let size = word(offset + 20) as usize;
                assert_eq!(
                    EthernetFrame::decode(&bytes[offset + 28..offset + 28 + size]).unwrap(),
                    frame
                );
            }
            offset += length;
        }
        assert_eq!(types, [0x0a0d0d0a, 1, 6]);
    }
}
