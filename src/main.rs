#![allow(unused)]
use bpfx::convert::convert_network_events;
use std::os::fd::{self, FromRawFd};

#[tokio::main]
async fn main() {
    convert_network_events().await.unwrap();
    // println!("Hello, world!");
}
