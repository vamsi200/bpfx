#![no_main]
#![no_std]
#![allow(unused)]
#![allow(non_camel_case_types)]

use crate::bindings::{dentry, file, in6_addr, path, sockaddr};
use crate::bindings::{sock, socket, task_struct};
use crate::raw::{PendingConnect, RawConnectEvent, RawEventHeader};
use aya_ebpf::bindings::bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET;
use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::r#gen::{
    bpf_d_path, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read_kernel_str,
    bpf_probe_read_str, bpf_probe_read_user_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user,
};
use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf::programs::{fentry, tracepoint};
use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf_macros::{fentry, map};
use aya_log_ebpf::info;
use core::ffi::c_int;
use core::panic::PanicInfo;
use core::ptr::null;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub _pad: [u8; 8],
}

pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[inline(always)]
fn collect_process_ctx() -> (u64, u32, u32, i32, u32, u32, [u8; TASK_COMM_LEN]) {
    unsafe {
        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let tid = tgid as u32;
        let timestamp = bpf_ktime_get_ns();
        let uid_gid = bpf_get_current_uid_gid();
        let uid = uid_gid as u32;
        let gid = (uid_gid >> 32) as u32;
        let task = bpf_get_current_task_btf() as *const task_struct;
        let parent_ptr = bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent)).unwrap();
        let ppid = bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0);
        let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        (timestamp, pid, tid, ppid, uid, gid, comm)
    }
}

#[inline(always)]
fn build_event_header() -> RawEventHeader {
    unsafe {
        let (timestamp, pid, tid, ppid, uid, gid, comm) = collect_process_ctx();
        RawEventHeader {
            timestamp_ns: timestamp,
            pid,
            tid,
            ppid,
            uid,
            gid,
            comm,
        }
    }
}

#[inline(always)]
fn sock_daddr(sock: *const sock) -> u32 {
    unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!(
            (*sock)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr
        ))
        .unwrap_or(0)
    }
}

#[inline(always)]
fn sock_rcv_saddr(sock: *const sock) -> u32 {
    unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!(
            (*sock)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr
        ))
        .unwrap_or(0)
    }
}

#[inline(always)]
fn sock_dport(sock: *const sock) -> u16 {
    unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!(
            (*sock)
                .__sk_common
                .__bindgen_anon_3
                .__bindgen_anon_1
                .skc_dport
        ))
        .unwrap_or(0)
    }
}

#[inline(always)]
fn sock_num(sock: *const sock) -> u16 {
    unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!(
            (*sock)
                .__sk_common
                .__bindgen_anon_3
                .__bindgen_anon_1
                .skc_num
        ))
        .unwrap_or(0)
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<RawConnectEvent>(0) {
            Some(ev) => ev,
            None => return Ok(0),
        };

        let sock_addr_ptr: u64 = ctx.read_at(24).unwrap_or(0);
        let family: u16 = match bpf_probe_read_user(sock_addr_ptr as *const u16) {
            Ok(f) => f,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        if family != AF_INET && family != AF_INET6 {
            event.discard(0);
            return Ok(0);
        }

        //let sock_fd: u64 = ctx.read_at(16).unwrap_or(0);
        let mut addr_buf = [0u8; 16];
        let mut port: u16 = 0;

        if family == AF_INET {
            let sa: SockAddrIn = match bpf_probe_read_user(sock_addr_ptr as *const SockAddrIn) {
                Ok(v) => v,
                Err(_) => {
                    event.discard(0);
                    return Ok(0);
                }
            };
            port = u16::from_be(sa.sin_port);
            addr_buf[..4].copy_from_slice(&sa.sin_addr);
        } else {
            let sa: SockaddrIn6 = match bpf_probe_read_user(sock_addr_ptr as *const SockaddrIn6) {
                Ok(v) => v,
                Err(_) => {
                    event.discard(0);
                    return Ok(0);
                }
            };
            port = u16::from_be(sa.sin6_port);
            addr_buf[..16].copy_from_slice(&sa.sin6_addr);
        }

        event.write(RawConnectEvent {
            header: build_event_header(),
            family,
        });
        event.submit(0);
    }
    Ok(0)
}

#[fentry]
fn try_tcp_v4_connect(ctx: FEntryContext) -> i32 {
    match unsafe { tcp_v4_connect(ctx) } {
        Ok(v) => v,
        Err(e) => 0,
    }
}

fn try_tcp_v4_connect_impl(ctx: FEntryContext, protocol: u8) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let sock: *const sock = ctx.arg(0);
        let tid = bpf_get_current_pid_tgid() as u32;

        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&sock_daddr(sock).to_ne_bytes());
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&sock_rcv_saddr(sock).to_ne_bytes());

        event.write(PendingConnect {
            protocol,
            tid,
            src_port: sock_num(sock),
            dst_port: sock_dport(sock),
            src_addr,
            dst_addr,
        });

        event.submit(0);
    }
    Ok(0)
}

fn tcp_v4_connect(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        try_tcp_v4_connect_impl(ctx, 1);
    }
    Ok(0)
}

#[fentry]
pub fn tcp_v6_connect(ctx: FEntryContext) -> i32 {
    match unsafe { try_tcp_v6_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_tcp_v6_connect(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe { try_v6_connect_impl(ctx, 1) }
}

#[inline(always)]
fn read_v6_addr(sock: *const sock, field_ptr: *const in6_addr) -> Result<[u8; 16], i32> {
    unsafe {
        match bpf_probe_read_kernel(field_ptr) {
            Ok(i) => Ok(i.in6_u.u6_addr8),
            Err(_) => Err(0),
        }
    }
}

#[inline(always)]
fn try_v6_connect_impl(ctx: FEntryContext, protocol: u8) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };
        let sock: *const sock = ctx.arg(0);
        let tid = bpf_get_current_pid_tgid() as u32;

        let daddr = match read_v6_addr(sock, core::ptr::addr_of!((*sock).__sk_common.skc_v6_daddr))
        {
            Ok(a) => a,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };
        let src_addr = match read_v6_addr(
            sock,
            core::ptr::addr_of!((*sock).__sk_common.skc_v6_rcv_saddr),
        ) {
            Ok(a) => a,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        event.write(PendingConnect {
            protocol,
            tid,
            src_port: sock_num(sock),
            dst_port: sock_dport(sock),
            src_addr,
            dst_addr: daddr,
        });
        event.submit(0);
    }
    Ok(0)
}

#[fentry]
pub fn udp_connect(ctx: FEntryContext) -> i32 {
    match unsafe { try_udp_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp_connect(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        try_tcp_v4_connect_impl(ctx, 2);
    }
    Ok(0)
}

#[fentry]
pub fn udp6_connect(ctx: FEntryContext) -> i32 {
    match unsafe { try_udp6_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp6_connect(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe { try_v6_connect_impl(ctx, 2) }
}
