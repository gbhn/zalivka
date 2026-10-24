use super::*;
use crate::wire::{dict, get, receive};
use plist::Value;
use std::{hint::black_box, io::Cursor, time::Instant};

fn previous_file_data(out: &mut Vec<u8>, data: &[u8]) {
    let value = dict([("FileData", Value::Data(data.to_vec()))]);
    let mut frame = vec![0; 4];
    value.to_writer_binary(&mut frame).unwrap();
    let length = frame.len() - 4;
    frame[..4].copy_from_slice(&(length as u32).to_be_bytes());
    out.extend_from_slice(&frame);
}

fn borrowed_file_data(out: &mut Vec<u8>, data: &[u8]) {
    wire::append_binary(out, &FileData { bytes: data }).unwrap();
}

fn copied_file_data(out: &mut Vec<u8>, value: &mut Value, data: &[u8]) {
    let Value::Data(payload) = &mut value.as_dictionary_mut().unwrap()["FileData"] else {
        unreachable!()
    };
    payload.clear();
    payload.extend_from_slice(data);
    wire::append_binary(out, value).unwrap();
}

#[test]
fn borrowed_file_data_preserves_wire_bytes_and_independent_plist_offsets() {
    let sizes = [8192, 1, 15, 16, 255, 256, 8191, 0, 8192];
    let image: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let mut expected = Vec::new();
    let mut actual = Vec::new();
    for size in sizes {
        previous_file_data(&mut expected, &image[..size]);
        borrowed_file_data(&mut actual, &image[..size]);
    }
    assert_eq!(actual, expected);
    let mut input = Cursor::new(actual);
    for size in sizes {
        let frame = receive(&mut input).unwrap();
        assert_eq!(
            get(&frame, &["FileData"]).unwrap().as_data().unwrap(),
            &image[..size]
        );
    }
    assert_eq!(input.position(), input.get_ref().len() as u64);
}

#[test]
#[ignore = "CPU-only FileData preparation benchmark; no USB or network"]
fn file_data_preparation_throughput() {
    let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let blocks = 512 * 1024 * 1024 / data.len();
    for round in 0..3 {
        // Alternate order to avoid attributing warm-up to the new path.
        for borrow in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let mut out = Vec::with_capacity(128 * 1024 + 8192);
            let mut value = dict([("FileData", Value::Data(Vec::with_capacity(8192)))]);
            let started = Instant::now();
            for _ in 0..blocks {
                if borrow {
                    borrowed_file_data(&mut out, black_box(&data));
                } else {
                    copied_file_data(&mut out, &mut value, black_box(&data));
                }
                if out.len() >= 128 * 1024 {
                    black_box(&out);
                    out.clear();
                }
            }
            black_box(&out);
            let seconds = started.elapsed().as_secs_f64();
            println!(
                "FILEDATA_PREPARATION_BENCH {}",
                serde_json::json!({
                    "round": round, "borrowed_payload": borrow, "payload_bytes": blocks * data.len(),
                    "seconds": seconds, "MiB_per_second": 512.0 / seconds,
                    "real_usb": false, "simulated_delay": false,
                })
            );
        }
    }
}
