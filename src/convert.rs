#![allow(unused)]
use std::ptr;

use crate::network::{AcceptEvent, NetworkEvent};
use anyhow::Result;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{FEntry, FExit, KProbe},
};
use aya_log::EbpfLogger;
use bpfx_common::raw::*;
use tokio::sync::mpsc;

// Read and convert the raw event structs to structured and then send to channel..
pub async fn convert_network_events() -> Result<()> {
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/bpfx-ebpf"
    ))?;

    EbpfLogger::init(&mut bpf)?;

    // for programs in bpf.programs() {
    //     println!("{}", programs.0);
    // }
    //
    // for (name, _) in bpf.maps() {
    //     println!("  {name}");
    // }

    let btf = Btf::from_sys_fs()?;

    // let prog: &mut KProbe = bpf.program_mut("inet_csk_accept").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("inet_csk_accept", 0)?;

    let prog: &mut FExit = bpf.program_mut("tcp_close").unwrap().try_into()?;
    prog.load("tcp_close", &btf)?;
    prog.attach()?;

    println!("[INFO] Running..");

    if bpf.map("EVENTS").is_none() {
        println!("EVENTS not found");
    }
    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("Faild to get map"))?;

    let mut ring_buffer = RingBuf::try_from(events_map)?;

    // let mut ring_buf = RingBuf::try_from(
    //     bpf.take_map("EVENTS")
    //         .unwrap_or(return Err(anyhow::anyhow!("Faild to get map"))),
    // )
    // .unwrap();

    loop {
        if let Some(events) = ring_buffer.next() {
            let ptr = events.as_ptr();
            let event = unsafe { ptr::read(ptr as *const PendingConnect) };
            match event.protocol {
                RawProtocol::Tcp => {}

                RawProtocol::Udp => {}
            }
        }
    }

    Ok(())
}
