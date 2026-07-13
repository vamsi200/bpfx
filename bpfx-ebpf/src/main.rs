#![no_main]
#![no_std]
#![allow(unused)]
#![allow(non_camel_case_types)]

pub mod bindings;
use crate::bindings::tcp_ca_event::CA_EVENT_ECN_IS_CE;
use crate::bindings::{dentry, file, in6_addr, path, sockaddr};
use crate::bindings::{sock, socket, task_struct};
use aya_ebpf::bindings::bpf_core_relo_kind::BPF_CORE_FIELD_BYTE_OFFSET;
use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::r#gen::{
    bpf_d_path, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read_kernel_str,
    bpf_probe_read_str, bpf_probe_read_user_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf::programs::{FExitContext, RetProbeContext};
use aya_ebpf::programs::{fentry, tracepoint};
use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf_macros::{fentry, map};
use aya_ebpf_macros::{fexit, kretprobe};
use aya_log_ebpf::info;
use bpfx_common::raw::{
    EventType, PendingConnect, RawEventHeader, RawFileCloseEvent, RawFileOpenEvent,
    RawProcessExitEvent, RawProcessStartEvent,
};
use bpfx_common::raw::{IpVersion, RawProtocol};
use core::ffi::c_int;
use core::panic::PanicInfo;
use core::ptr::null;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

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
fn collect_process_ctx() -> (u64, u32, u32, u32, u32, u32, [u8; TASK_COMM_LEN]) {
    unsafe {
        let tgid = bpf_get_current_pid_tgid();
        let pid = (tgid >> 32) as u32;
        let tid = tgid as u32;
        let timestamp = bpf_ktime_get_ns();
        let uid_gid = bpf_get_current_uid_gid();
        let uid = uid_gid as u32;
        let gid = (uid_gid >> 32) as u32;
        let task = bpf_get_current_task_btf() as *const task_struct;
        let parent_ptr = match bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent)) {
            Ok(p) => p,
            Err(_) => core::ptr::null(),
        };

        let ppid = if parent_ptr.is_null() {
            0 // not a good idea
        } else {
            bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0) as u32
        };

        let ppid = bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0) as u32;
        let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        (timestamp, pid, tid, ppid, uid, gid, comm)
    }
}

#[inline(always)]
fn build_event_header(event_type: EventType) -> RawEventHeader {
    unsafe {
        let (timestamp, pid, tid, ppid, uid, gid, comm) = collect_process_ctx();
        RawEventHeader {
            event_type,
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

trait SockProvider {
    unsafe fn sock(&self) -> *const sock;
}

impl SockProvider for FExitContext {
    unsafe fn sock(&self) -> *const sock {
        unsafe { self.arg(0) }
    }
}

impl SockProvider for RetProbeContext {
    unsafe fn sock(&self) -> *const sock {
        unsafe { self.ret().unwrap_or(core::ptr::null()) }
    }
}

#[inline(always)]
fn emit_v4<C: SockProvider>(ctx: C, protocol: u8, event_type: EventType) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let sock = ctx.sock();
        if sock.is_null() {
            event.discard(0);
            return Ok(0);
        }

        let tid = bpf_get_current_pid_tgid() as u32;

        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&sock_daddr(sock).to_ne_bytes());
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&sock_rcv_saddr(sock).to_ne_bytes());

        event.write(PendingConnect {
            header: build_event_header(event_type),
            protocol: RawProtocol::try_from(protocol).unwrap(),
            tid,
            src_port: sock_num(sock),
            dst_port: sock_dport(sock),
            ip_version: IpVersion::V4,
            src_addr,
            dst_addr,
        });

        event.submit(0);
    }
    Ok(0)
}

#[inline(always)]
fn emit_v6<C: SockProvider>(ctx: C, protocol: u8, event_type: EventType) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let sock = ctx.sock();
        if sock.is_null() {
            event.discard(0);
            return Ok(0);
        }

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
            header: build_event_header(event_type),
            protocol: RawProtocol::try_from(protocol).unwrap(),
            tid,
            src_port: sock_num(sock),
            dst_port: sock_dport(sock),
            ip_version: IpVersion::V6,
            src_addr,
            dst_addr: daddr,
        });
        event.submit(0);
    }

    Ok(0)
}

//ConnectEvent for TCP and UDP - v4
#[fexit]
pub fn tcp_v4_connect(ctx: FExitContext) -> i32 {
    match unsafe { try_tcp_v4_connect(ctx) } {
        Ok(v) => v,
        Err(e) => 0,
    }
}

fn try_tcp_v4_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        emit_v4(ctx, 1, EventType::Connect);
    }
    Ok(0)
}

// AcceptEvent for TCP(Only)
#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> i32 {
    match unsafe { try_inet_csk_accept_impl(ctx) } {
        Ok(v) => v,
        Err(e) => 0,
    }
}

fn try_inet_csk_accept_impl(ctx: RetProbeContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = match ctx.ret::<*const sock>() {
            Some(s) => {
                if !s.is_null() {
                    s
                } else {
                    return Ok(0);
                }
            }
            None => {
                return Ok(0);
            }
        };

        let family = match bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) {
            Ok(val) => val,
            Err(e) => {
                return Ok(0);
            }
        };

        info!(&ctx, "Family - {}", family);

        match family {
            AF_INET => emit_v4(ctx, 1, EventType::Accept)?,
            AF_INET6 => emit_v6(ctx, 1, EventType::Accept)?,
            _ => {
                return Ok(0);
            }
        };
    }
    Ok(0)
}

// CloseEvent for TCP - v4 and v6
#[fexit]
pub fn tcp_close(ctx: FExitContext) -> i32 {
    match unsafe { try_tcp_close(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_tcp_close(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = unsafe { ctx.arg(0) };
        let family = match bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) {
            Ok(val) => val,
            Err(e) => {
                return Ok(0);
            }
        };

        match family {
            AF_INET => emit_v4(ctx, 1, EventType::Close)?,
            AF_INET6 => emit_v6(ctx, 1, EventType::Close)?,
            _ => return Ok(0),
        };
    }
    Ok(0)
}

#[fexit]
pub fn udp_destroy_sock(ctx: FExitContext) -> i32 {
    match unsafe { try_udp_destroy_sock(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp_destroy_sock(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = unsafe { ctx.arg(0) };
        let family = match bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) {
            Ok(val) => val,
            Err(e) => {
                return Ok(0);
            }
        };

        match family {
            AF_INET => emit_v4(ctx, 2, EventType::Close)?,
            AF_INET6 => emit_v6(ctx, 2, EventType::Close)?,
            _ => return Ok(0),
        };
    }
    Ok(0)
}

//ConnectEvent for TCP and UDP - v6
#[fexit]
pub fn tcp_v6_connect(ctx: FExitContext) -> i32 {
    match unsafe { try_tcp_v6_connect(ctx) } {
        Ok(v) => v,
        Err(e) => 0,
    }
}

fn try_tcp_v6_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe { emit_v6(ctx, 1, EventType::Connect) }
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

#[fexit]
pub fn udp_connect(ctx: FExitContext) -> i32 {
    match unsafe { try_udp_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        emit_v4(ctx, 2, EventType::Connect);
    }
    Ok(0)
}

#[fexit]
pub fn udpv6_connect(ctx: FExitContext) -> i32 {
    match unsafe { try_udpv6_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udpv6_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe { emit_v6(ctx, 2, EventType::Connect) }
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> i32 {
    match unsafe { try_sched_process_exec(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawProcessStartEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let data_loc: u32 = match ctx.read_at(8) {
            Ok(v) => v,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };

        let offset = (data_loc & 0xffff) as usize;
        let len = (data_loc >> 16) as usize;
        let p = (ctx.as_ptr() as *const u8).add(offset);

        let mut filename = [0u8; 256];

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            p as *const _,
        );

        events.write(RawProcessStartEvent {
            header: build_event_header(EventType::ProcessStart),
            filename: filename,
        });

        events.submit(0);
    }

    Ok(0)
}

#[fentry]
fn do_group_exit(ctx: FEntryContext) -> i32 {
    match unsafe { try_do_group_exit(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_do_group_exit(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawProcessExitEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let exit_code: i32 = ctx.arg(0);
        events.write(RawProcessExitEvent {
            header: build_event_header(EventType::ProcessExit),
            exit_code,
        });

        events.submit(0);
    }
    Ok(0)
}

#[tracepoint]
fn sys_connect_exit(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_connect_exit(ctx) } {
        Ok(v) => v,
        Err(_) => -1,
    }
}

fn try_sys_connect_exit(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe { Ok(ctx.read_at(16).unwrap_or(-1)) }
}

#[tracepoint]
fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match unsafe { try_sys_enter_openat(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut event: RingBufEntry<RawFileOpenEvent> = match EVENTS.reserve::<RawFileOpenEvent>(0)
        {
            Some(s) => s,
            None => return Ok(0),
        };

        let dfd: i32 = match ctx.read_at(16) {
            Ok(fd) => fd,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        let file_name_ptr: u64 = match ctx.read_at(24) {
            Ok(fname) => fname,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        let mut path = [0u8; 256];

        bpf_probe_read_user_str_bytes(file_name_ptr as *const _, &mut path);

        let flags: u32 = match ctx.read_at(32) {
            Ok(fl) => fl,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        event.write(RawFileOpenEvent {
            header: build_event_header(EventType::FileOpen),
            flags,
            path,
        });

        event.submit(0);
    }
    Ok(0)
}

#[fentry]
pub fn filp_close(ctx: FEntryContext) -> i32 {
    match try_flip_close(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

pub fn try_flip_close(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileCloseEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let file: *const file = ctx.arg(0);

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let mut path = [0u8; 256];
        let f_path: *const path = &(*file).__bindgen_anon_1.f_path;
        let dentry: *const dentry = (*f_path).dentry;
        let name_ptr = (*dentry).__bindgen_anon_1.d_name.name;

        bpf_d_path(
            f_path as *mut _,
            path.as_mut_ptr() as *mut i8,
            path.len() as u32,
        );

        events.write(RawFileCloseEvent {
            header: build_event_header(EventType::FileClose),
            path,
        });

        events.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
