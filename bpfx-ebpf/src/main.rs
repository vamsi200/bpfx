#![no_main]
#![no_std]
#![allow(non_camel_case_types)]

pub mod bindings;

use crate::bindings::{dentry, file, in6_addr, inode, renamedata};
use crate::bindings::{sock, socket, task_struct};
use aya_ebpf::helpers::r#gen::{
    bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read_kernel_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{FEntryContext, TracePointContext};
use aya_ebpf::programs::{FExitContext, RetProbeContext};
use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf_macros::{fentry, map};
use aya_ebpf_macros::{fexit, kretprobe};
use bpfx_common::raw::*;
use bpfx_common::raw::{IpVersion, RawProtocol};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static CONFIG: HashMap<u32, FileModeFilter> = HashMap::with_max_entries(1, 0);

#[map]
static TEMP: PerCpuArray<RawFileRenameEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FILTER: HashMap<u32, FilterKey> = HashMap::with_max_entries(5, 0);

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
            0 //WARN:not a good idea
        } else {
            bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0) as u32
        };

        let comm = bpf_get_current_comm().unwrap_or([0u8; TASK_COMM_LEN]);
        (timestamp, pid, tid, ppid, uid, gid, comm)
    }
}

#[inline(always)]
fn build_event_header(event_type: EventType) -> RawEventHeader {
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

#[inline(always)]
fn emit_v4(
    sock: *const sock,
    retval: Option<i32>,
    protocol: u8,
    event_type: EventType,
) -> Result<i32, i32> {
    let mut event = match EVENTS.reserve::<PendingConnect>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    let header = build_event_header(event_type);
    if filter_events(FilterOwner::Network, &header) {
        event.discard(0);
        return Ok(0);
    }

    let tid = bpf_get_current_pid_tgid() as u32;

    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&sock_daddr(sock).to_ne_bytes());
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&sock_rcv_saddr(sock).to_ne_bytes());

    event.write(PendingConnect {
        header,
        protocol: RawProtocol::try_from(protocol).unwrap(), // unwrap is fine here.
        tid,
        src_port: sock_num(sock),
        dst_port: sock_dport(sock),
        ip_version: IpVersion::V4,
        src_addr,
        dst_addr,
        retval,
    });

    event.submit(0);
    Ok(0)
}

#[inline(always)]
fn emit_v6(
    sock: *const sock,
    retval: Option<i32>,
    protocol: u8,
    event_type: EventType,
) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let header = build_event_header(event_type);
        if filter_events(FilterOwner::Network, &header) {
            event.discard(0);
            return Ok(0);
        }

        let tid = bpf_get_current_pid_tgid() as u32;

        let daddr = match read_v6_addr(core::ptr::addr_of!((*sock).__sk_common.skc_v6_daddr)) {
            Ok(a) => a,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };
        let src_addr = match read_v6_addr(core::ptr::addr_of!((*sock).__sk_common.skc_v6_rcv_saddr))
        {
            Ok(a) => a,
            Err(_) => {
                event.discard(0);
                return Ok(0);
            }
        };

        event.write(PendingConnect {
            header,
            protocol: RawProtocol::try_from(protocol).unwrap(),
            tid,
            src_port: sock_num(sock),
            dst_port: sock_dport(sock),
            ip_version: IpVersion::V6,
            src_addr,
            dst_addr: daddr,
            retval,
        });
        event.submit(0);
    }

    Ok(0)
}

//ConnectEvent for TCP and UDP - v4
#[fexit]
pub fn tcp_v4_connect(ctx: FExitContext) -> i32 {
    match { try_tcp_v4_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_tcp_v4_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = ctx.arg(0);
        if sock.is_null() {
            return Ok(0);
        }
        emit_v4(sock, Some(ctx.arg(3)), 1, EventType::Connect)?;
    }
    Ok(0)
}

// AcceptEvent for TCP(Only)
#[kretprobe]
pub fn inet_csk_accept(ctx: RetProbeContext) -> i32 {
    match { try_inet_csk_accept_impl(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
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
            Err(_) => {
                return Ok(0);
            }
        };

        match family {
            AF_INET => emit_v4(sock, None, 1, EventType::Accept)?,
            AF_INET6 => emit_v6(sock, None, 1, EventType::Accept)?,
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
    match { try_tcp_close(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_tcp_close(ctx: FExitContext) -> Result<i32, i32> {
    let sock: *const sock = unsafe { ctx.arg(0) };
    let family = match unsafe { bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) } {
        Ok(val) => val,
        Err(_) => {
            return Ok(0);
        }
    };

    match family {
        AF_INET => emit_v4(sock, None, 1, EventType::Close)?,
        AF_INET6 => emit_v6(sock, None, 1, EventType::Close)?,
        _ => return Ok(0),
    };

    Ok(0)
}

#[fexit]
pub fn udp_destroy_sock(ctx: FExitContext) -> i32 {
    match { try_udp_destroy_sock(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp_destroy_sock(ctx: FExitContext) -> Result<i32, i32> {
    let sock: *const sock = unsafe { ctx.arg(0) };
    if sock.is_null() {
        return Ok(0);
    }
    let family = match unsafe { bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) } {
        Ok(val) => val,
        Err(_) => {
            return Ok(0);
        }
    };

    match family {
        AF_INET => emit_v4(sock, None, 2, EventType::Close)?,
        AF_INET6 => emit_v6(sock, None, 2, EventType::Close)?,
        _ => return Ok(0),
    };
    Ok(0)
}

//ConnectEvent for TCP and UDP - v6
#[fexit]
pub fn tcp_v6_connect(ctx: FExitContext) -> i32 {
    match { try_tcp_v6_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_tcp_v6_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = ctx.arg(0);
        if sock.is_null() {
            return Ok(0);
        }
        emit_v6(sock, Some(ctx.arg(3)), 1, EventType::Connect)
    }
}

#[inline(always)]
fn read_v6_addr(field_ptr: *const in6_addr) -> Result<[u8; 16], i32> {
    unsafe {
        match bpf_probe_read_kernel(field_ptr) {
            Ok(i) => Ok(i.in6_u.u6_addr8),
            Err(_) => Err(0),
        }
    }
}

#[fexit]
pub fn udp_connect(ctx: FExitContext) -> i32 {
    match { try_udp_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udp_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = ctx.arg(0);
        if sock.is_null() {
            return Ok(0);
        }
        emit_v4(sock, Some(ctx.arg(3)), 2, EventType::Connect)?;
    }
    Ok(0)
}

#[fexit]
pub fn udpv6_connect(ctx: FExitContext) -> i32 {
    match { try_udpv6_connect(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_udpv6_connect(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let sock: *const sock = ctx.arg(0);
        if sock.is_null() {
            return Ok(0);
        }
        emit_v6(sock, Some(ctx.arg(3)), 2, EventType::Connect)
    }
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> i32 {
    match { try_sched_process_exec(ctx) } {
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

        let header = build_event_header(EventType::ProcessStart);
        if filter_events(FilterOwner::Process, &header) {
            events.discard(0);
            return Ok(0);
        }

        let data_loc: u32 = match ctx.read_at(8) {
            Ok(v) => v,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };

        let offset = (data_loc & 0xffff) as usize;
        let p = (ctx.as_ptr() as *const u8).add(offset);

        let mut filename = [0u8; 256];

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            p as *const _,
        );

        events.write(RawProcessStartEvent {
            header,
            filename: filename,
        });

        events.submit(0);
    }

    Ok(0)
}

#[fentry]
fn do_group_exit(ctx: FEntryContext) -> i32 {
    match { try_do_group_exit(ctx) } {
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

        let header = build_event_header(EventType::ProcessExit);
        if filter_events(FilterOwner::Process, &header) {
            events.discard(0);
            return Ok(0);
        }

        let exit_code: i32 = ctx.arg(0);
        events.write(RawProcessExitEvent { header, exit_code });

        events.submit(0);
    }
    Ok(0)
}

// #[tracepoint]
// fn sys_connect_exit(ctx: TracePointContext) -> i32 {
//     match unsafe { try_sys_connect_exit(ctx) } {
//         Ok(v) => v,
//         Err(_) => -1,
//     }
// }
//
// fn try_sys_connect_exit(ctx: TracePointContext) -> Result<i32, i32> {
//     unsafe { Ok(ctx.read_at(16).unwrap_or(-1)) }
// }

#[fexit]
fn vfs_open(ctx: FExitContext) -> i32 {
    match { try_vfs_open(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_open(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut event = match EVENTS.reserve::<RawFileOpenEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileOpen);

        if filter_events(FilterOwner::File, &header) {
            event.discard(0);
            return Ok(0);
        }

        let file: *const file = ctx.arg(1);

        if file.is_null() {
            event.discard(0);
            return Ok(0);
        }

        let output = capture_file(file);

        if !output.0 {
            event.discard(0);
            return Ok(0);
        }

        let dentry = (*file).__bindgen_anon_1.f_path.dentry;
        let name = (*dentry).__bindgen_anon_1.d_name.name;

        let mut filename = [0u8; 256];

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name as *const _,
        );

        event.write(RawFileOpenEvent {
            header,
            filename,
            file_mode: output.1,
            retval: ctx.arg(2),
        });

        event.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn filp_close(ctx: FExitContext) -> i32 {
    match try_flip_close(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

pub fn try_flip_close(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileCloseEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileClose);

        if filter_events(FilterOwner::File, &header) {
            events.discard(0);
            return Ok(0);
        }

        let file: *const file = ctx.arg(0);

        let output = capture_file(file);

        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let dentry = (*file).__bindgen_anon_1.f_path.dentry;
        let name = (*dentry).__bindgen_anon_1.d_name.name;

        let mut filename = [0u8; 256];

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name as *const _,
        );

        events.write(RawFileCloseEvent {
            header,
            filename,
            file_mode: output.1,
            retval: ctx.arg(2),
        });

        events.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> i32 {
    match { try_sched_process_fork(ctx) } {
        Ok(e) => e,
        Err(_) => 0,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawProcessForkEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::ProcessFork);
        if filter_events(FilterOwner::Process, &header) {
            events.discard(0);
            return Ok(0);
        }

        let data_loc: u32 = match ctx.read_at(16) {
            Ok(e) => e,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };

        let child_pid: u32 = match ctx.read_at(20) {
            Ok(v) => v,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };

        let offset = (data_loc & 0xffff) as usize;
        let ptr = (ctx.as_ptr() as *const u8).add(offset);

        let mut child_comm = [0u8; TASK_COMM_LEN];
        bpf_probe_read_kernel_str(
            child_comm.as_mut_ptr() as *mut _,
            child_comm.len() as u32,
            ptr as *const _,
        );

        events.write(RawProcessForkEvent {
            parent: header,
            child_pid,
            child_comm,
        });

        events.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn vfs_read(ctx: FExitContext) -> i32 {
    match { try_vfs_read(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

const S_IFMT: u16 = 0o170000;
const S_IFIFO: u16 = 0o010000;
const S_IFCHR: u16 = 0o020000;
const S_IFDIR: u16 = 0o040000;
const S_IFBLK: u16 = 0o060000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFSOCK: u16 = 0o140000;

#[inline(always)]
fn capture_file(file: *const file) -> (bool, FileModeFilter) {
    unsafe {
        let file_mode = FileModeFilter { mode: 0 };

        let config = match CONFIG.get(&0) {
            Some(v) => v,
            None => return (false, file_mode),
        };

        let ty = match (*(*file).f_inode).i_mode & S_IFMT {
            S_IFREG => FILE_REG,
            S_IFDIR => FILE_DIR,
            S_IFCHR => FILE_CHR,
            S_IFBLK => FILE_BLK,
            S_IFIFO => FILE_FIFO,
            S_IFLNK => FILE_LNK,
            S_IFSOCK => FILE_SOCK,
            _ => 0,
        };

        ((config.mode & ty) != 0, FileModeFilter { mode: ty })
    }
}

fn try_vfs_read(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileReadEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileRead);

        if filter_events(FilterOwner::File, &header) {
            events.discard(0);
            return Ok(0);
        }

        let file: *const file = ctx.arg(0);
        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let output = capture_file(file);
        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        let mut filename = [0u8; 256];

        let dentry = (*file).__bindgen_anon_1.f_path.dentry;
        let name = (*dentry).__bindgen_anon_1.d_name.name;

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name as *const _,
        );
        events.write(RawFileReadEvent {
            header,
            filename,
            file_mode: output.1,
            retval: ctx.arg(4),
        });

        events.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn vfs_write(ctx: FExitContext) -> i32 {
    match { try_vfs_write(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_write(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileWriteEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileWrite);

        if filter_events(FilterOwner::File, &header) {
            events.discard(0);
            return Ok(0);
        }

        let file: *const file = ctx.arg(0);

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let output = capture_file(file);
        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        let mut filename = [0u8; 256];

        let dentry = (*file).__bindgen_anon_1.f_path.dentry;
        let name = (*dentry).__bindgen_anon_1.d_name.name;

        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name as *const _,
        );

        events.write(RawFileWriteEvent {
            header,
            filename,
            file_mode: output.1,
            retval: ctx.arg(4),
        });

        events.submit(0);
    }
    Ok(0)
}

#[inline(always)]
fn capture_inode(inode: *const inode) -> (bool, FileModeFilter) {
    unsafe {
        let file_mode = FileModeFilter { mode: 0 };
        let config = match CONFIG.get(&0) {
            Some(v) => v,
            None => return (false, file_mode),
        };

        let ty = match (*inode).i_mode & S_IFMT {
            S_IFREG => FILE_REG,
            S_IFDIR => FILE_DIR,
            S_IFCHR => FILE_CHR,
            S_IFBLK => FILE_BLK,
            S_IFIFO => FILE_FIFO,
            S_IFLNK => FILE_LNK,
            S_IFSOCK => FILE_SOCK,
            _ => 0,
        };

        ((config.mode & ty) != 0, FileModeFilter { mode: ty })
    }
}

#[fexit]
pub fn vfs_unlink(ctx: FExitContext) -> i32 {
    match { try_vfs_unlink(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_unlink(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileDeleteEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileDelete);

        if filter_events(FilterOwner::File, &header) {
            events.discard(0);
            return Ok(0);
        }

        let dentry: *const dentry = ctx.arg(2);
        let inode = (*dentry).d_inode;

        let output = capture_inode(inode);
        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        let name = (*dentry).__bindgen_anon_1.d_name.name;
        let mut filename = [0u8; 256];
        bpf_probe_read_kernel_str(
            filename.as_mut_ptr() as *mut _,
            filename.len() as u32,
            name as *const _,
        );

        events.write(RawFileDeleteEvent {
            header,
            filename,
            file_mode: output.1,
            retval: ctx.arg(4),
        });

        events.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn vfs_rename_retval(ctx: FExitContext) -> i32 {
    match { try_vfs_rename_retval(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_rename_retval(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileRtrEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        events.write(RawFileRtrEvent {
            header: build_event_header(EventType::PendingFileRename),
            retval: ctx.arg(1),
        });

        events.submit(0);
    }
    Ok(0)
}

#[fentry]
pub fn vfs_rename(ctx: FEntryContext) -> i32 {
    match { try_vfs_rename(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_rename(ctx: FEntryContext) -> Result<i32, i32> {
    unsafe {
        let header = build_event_header(EventType::FileRename);

        if filter_events(FilterOwner::File, &header) {
            return Ok(0);
        }

        let renamedata: *const renamedata = ctx.arg(0);
        let old_dentry = (*renamedata).old_dentry;
        let new_dentry = (*renamedata).new_dentry;

        let old_inode = (*old_dentry).d_inode;

        let output = capture_inode(old_inode);

        if !output.0 {
            return Ok(0);
        }

        let old_filename = (*old_dentry).__bindgen_anon_1.d_name.name;
        let new_filename = (*new_dentry).__bindgen_anon_1.d_name.name;

        let event = match TEMP.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Ok(0),
        };

        event.header = header;
        event.file_mode = output.1;

        bpf_probe_read_kernel_str(
            event.old_filename.as_mut_ptr() as *mut _,
            event.old_filename.len() as u32,
            old_filename as *const _,
        );

        bpf_probe_read_kernel_str(
            event.new_filename.as_mut_ptr() as *mut _,
            event.new_filename.len() as u32,
            new_filename as *const _,
        );

        let mut events = match EVENTS.reserve::<RawFileRenameEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        events.write(*event);

        events.submit(0);
    }
    Ok(0)
}

#[fexit]
pub fn inet_bind(ctx: FExitContext) -> i32 {
    match { try_inet_bind(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_inet_bind(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let socket: *const socket = ctx.arg(0);
        let sock = (*socket).sk;

        if sock.is_null() || socket.is_null() {
            return Ok(0);
        }

        let family = match bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) {
            Ok(val) => val,
            Err(_) => {
                return Ok(0);
            }
        };

        match family {
            AF_INET => emit_v4(sock, Some(ctx.arg(3)), 1, EventType::Bind)?,
            AF_INET6 => emit_v6(sock, Some(ctx.arg(3)), 1, EventType::Bind)?,
            _ => {
                return Ok(0);
            }
        };
    }
    Ok(0)
}

#[fexit]
pub fn inet_listen(ctx: FExitContext) -> i32 {
    match { try_inet_listen(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_inet_listen(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let socket: *const socket = ctx.arg(0);
        let sock = (*socket).sk;

        if sock.is_null() || socket.is_null() {
            return Ok(0);
        }

        let family = match bpf_probe_read_kernel::<u16>(&(*sock).__sk_common.skc_family) {
            Ok(val) => val,
            Err(_) => {
                return Ok(0);
            }
        };

        match family {
            AF_INET => emit_v4(sock, Some(ctx.arg(2)), 1, EventType::Listen)?,
            AF_INET6 => emit_v6(sock, Some(ctx.arg(2)), 1, EventType::Listen)?,
            _ => {
                return Ok(0);
            }
        };
    }
    Ok(0)
}

fn filter_events(filter_owner: FilterOwner, header: &RawEventHeader) -> bool {
    unsafe {
        if let Some(key) = FILTER.get(&(filter_owner as u32)) {
            match *key {
                FilterKey::None => {
                    return false;
                }
                FilterKey::Pid(pid) => {
                    if header.pid != pid {
                        return true;
                    }
                }
                FilterKey::Tid(tid) => {
                    if header.tid != tid {
                        return true;
                    }
                }
                FilterKey::Uid(uid) => {
                    if header.uid != uid {
                        return true;
                    }
                }
                FilterKey::Ppid(ppid) => {
                    if header.ppid != ppid {
                        return true;
                    }
                }
                FilterKey::Gid(gid) => {
                    if header.gid != gid {
                        return true;
                    }
                }
                _ => {
                    return false;
                }
            }
        }
        false
    }
}

#[fexit]
pub fn vm_mmap_pgoff(ctx: FExitContext) -> i32 {
    match { try_vm_mmap_pgoff(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vm_mmap_pgoff(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawMemoryMapEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::MemoryMap);

        if filter_events(FilterOwner::Memory, &header) {
            events.discard(0);
            return Ok(0);
        }

        events.write(RawMemoryMapEvent {
            header,
            requested_address: ctx.arg(1),
            length: ctx.arg(2),
            protection: ctx.arg(3),
            flags: ctx.arg(4),
            mapped_address: ctx.arg(6),
        });

        events.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn __vm_munmap(ctx: FExitContext) -> i32 {
    match { try_vm_munmap(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vm_munmap(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawMemoryUnmapEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        events.write(RawMemoryUnmapEvent {
            header: build_event_header(EventType::MemoryUnMap),
            requested_address: ctx.arg(0),
            length: ctx.arg(1),
            mapped_address: ctx.arg(3),
        });

        events.submit(0);
    }

    Ok(0)
}

use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic_handler(_: &PanicInfo) -> ! {
    loop {}
}
