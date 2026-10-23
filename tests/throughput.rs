//! Synthetic ASR benchmark: no USB devices, firmware writes or network requests.
use anyhow::{Result, ensure};
use sha1::{Digest, Sha1};
use std::{
    collections::VecDeque,
    io::{Cursor, Read},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use zalivka::{
    asr,
    mux::{self, PacketTransport, Session},
    wire,
};

#[derive(Default)]
struct Counts {
    payload: Vec<u8>,
    packets: usize,
    tiny_packets: usize,
    idle_polls: usize,
    bursts: usize,
    zlp_writes: usize,
}

struct SimulatedUsb {
    input: VecDeque<Vec<u8>>,
    counts: Arc<Mutex<Counts>>,
    idle_wait: Duration,
    queued_model: bool,
}

fn tcp(service: u16, port: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut header = vec![0; 20];
    header[..2].copy_from_slice(&service.to_be_bytes());
    header[2..4].copy_from_slice(&port.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    header[14..16].copy_from_slice(&1024u16.to_be_bytes());
    header.extend_from_slice(data);
    mux::encode_packet(6, 2, 0, 0, &header).unwrap()
}

impl SimulatedUsb {
    fn accept(&mut self, bytes: &[u8], wait: bool) -> Result<()> {
        let protocol = u32::from_be_bytes(bytes[..4].try_into()?);
        if protocol == 0 {
            let mut response = 2u32.to_be_bytes().to_vec();
            response.extend([0; 8]);
            self.input
                .push_back(mux::encode_packet(0, 0, 0, 0, &response)?);
            return Ok(());
        }
        if protocol != 6 {
            return Ok(());
        }
        let packet = mux::decode_packet(bytes, 2)?;
        let t = packet.payload;
        let port = u16::from_be_bytes(t[..2].try_into()?);
        let service = u16::from_be_bytes(t[2..4].try_into()?);
        let seq = u32::from_be_bytes(t[4..8].try_into()?);
        if t[13] == 2 {
            self.input.push_back(tcp(service, port, 0, 1, 0x12, &[]));
            if service == 12345 {
                let commands = [
                    wire::dict([
                        ("Command", "Initiate".into()),
                        ("Checksum Chunks", true.into()),
                    ]),
                    wire::dict([("Command", "Payload".into())]),
                ];
                let data: Vec<u8> = commands
                    .iter()
                    .flat_map(|m| wire::xml(m).unwrap())
                    .collect();
                self.input.push_back(tcp(service, port, 1, 1, 0x10, &data));
            }
        } else if service == 12345 && t.len() > 20 {
            // Fixed host-call overhead models a synchronous USB transfer. It
            // is not a measurement of this user's USB hardware or Apple driver.
            if wait {
                thread::sleep(Duration::from_micros(250));
            }
            let mut counts = self.counts.lock().unwrap();
            counts.payload.extend_from_slice(&t[20..]);
            counts.packets += 1;
            counts.zlp_writes += usize::from(bytes.len().is_multiple_of(512));
            counts.tiny_packets += usize::from(t.len() - 20 <= 20);
            self.input.push_back(tcp(
                service,
                port,
                1,
                seq.wrapping_add((t.len() - 20) as u32),
                0x10,
                &[],
            ));
        }
        Ok(())
    }
}

impl PacketTransport for SimulatedUsb {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.accept(bytes, true)
    }

    fn write_packets(&mut self, packets: &[Vec<u8>], cancelled: &AtomicBool) -> Result<()> {
        self.counts.lock().unwrap().bursts += 1;
        // Idealized scheduling model: queued requests share one fixed host
        // round trip. No USB bus time, driver behavior or Mac processing is
        // simulated. Compare modes within this model, never against hardware.
        if self.queued_model {
            thread::sleep(Duration::from_micros(250));
        }
        for packet in packets {
            ensure!(!cancelled.load(Ordering::Acquire), "session cancelled");
            self.accept(packet, !self.queued_model)?;
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        if let Some(bytes) = self.input.pop_front() {
            return Ok(bytes);
        }
        self.counts.lock().unwrap().idle_polls += 1;
        if !self.idle_wait.is_zero() {
            thread::sleep(self.idle_wait);
        }
        Ok(vec![])
    }
}

#[test]
#[ignore = "synthetic performance benchmark; does not access physical USB"]
fn asr_throughput_with_idle_mux_readers() -> Result<()> {
    let image: Vec<u8> = (0..16 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    for (idle_ms, readers, queued_model) in [
        (5, 0, false),
        (5, 2, false),
        (0, 0, false),
        (0, 2, false),
        (5, 0, true),
        (5, 2, true),
        (0, 0, true),
        (0, 2, true),
    ] {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let session = Session::new(SimulatedUsb {
            input: VecDeque::new(),
            counts: counts.clone(),
            idle_wait: Duration::from_millis(idle_ms),
            queued_model,
        })?;
        let mut stream = session.connect(12345)?;
        let mut threads = vec![];
        for service in [62078, 1082].into_iter().take(readers) {
            let mut idle = session.connect(service)?;
            threads.push(thread::spawn(move || {
                let mut byte = [0];
                while idle.read(&mut byte).is_ok() {}
            }));
        }
        let started = Instant::now();
        let result = asr::transfer(&mut stream, &mut Cursor::new(&image), image.len() as u64);
        let elapsed = started.elapsed().as_secs_f64();
        session.cancel();
        for thread in threads {
            thread.join().unwrap();
        }
        result?;
        let counts = counts.lock().unwrap();
        let mut sent = Cursor::new(&counts.payload);
        wire::receive_xml(&mut sent)?;
        let mut payload = &counts.payload[sent.position() as usize..];
        for block in image.chunks(131072) {
            ensure!(&payload[..block.len()] == block, "ASR payload changed");
            payload = &payload[block.len()..];
            ensure!(
                &payload[..20] == Sha1::digest(block).as_slice(),
                "ASR checksum changed"
            );
            payload = &payload[20..];
        }
        ensure!(payload.is_empty(), "extra ASR payload bytes");
        println!(
            "ASR_BENCH {}",
            serde_json::json!({
            "idle_readers": readers, "idle_poll_milliseconds": idle_ms,
            "image_bytes": image.len(), "seconds": elapsed,
                "MiB_per_second": image.len() as f64 / 1048576.0 / elapsed,
                "mux_data_packets": counts.packets, "tiny_data_packets": counts.tiny_packets,
                "modeled_usb_writes": counts.packets + counts.zlp_writes,
                "modeled_zlp_writes": counts.zlp_writes, "modeled_endpoint_packet_size": 512,
                "delays_include_zlp": false,
                "idle_polls": counts.idle_polls,
                "queued_model": queued_model, "mux_bursts": counts.bursts,
                "overhead_microseconds": 250,
                "model": "fixed host round trip, no USB bus or device processing", "payload_and_checksums_verified": true,
                "real_usb": false,
            })
        );
    }
    Ok(())
}
