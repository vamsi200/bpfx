#![no_main]
#![no_std]
#![allow(non_camel_case_types)]

pub mod bindings;

use crate::bindings::{
    dentry, file, fop_flags_t, in6_addr, inode, kernfs_open_file, mount, path, renamedata,
};
use crate::bindings::{sock, socket, task_struct};
use aya_ebpf::helpers::r#gen::{
    bpf_d_path, bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_probe_read_kernel_str,
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_kernel_buf,
};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::maps::{HashMap, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{FEntryContext, LsmContext, TracePointContext};
use aya_ebpf::programs::{FExitContext, RetProbeContext};
use aya_ebpf::{EbpfContext, TASK_COMM_LEN};
use aya_ebpf_macros::{fentry, lsm, map};
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

#[map]
static FILE_PATH_MAP: HashMap<u64, RawFilePath> = HashMap::with_max_entries(4 * 1024, 0);

#[map]
static PATH_BUF: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingUnlink {
    dentry: u64,
    path: [u8; 256],
    file_mode: FileModeFilter,
}

#[map]
static UNLINK_PENDING: HashMap<u64, PendingUnlink> = HashMap::with_max_entries(4096, 0);

#[map]
static UNLINK_TEMP: PerCpuArray<PendingUnlink> = PerCpuArray::with_max_entries(1, 0);

#[map]
static UNLINK_NAME_TEMP: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

use aya_ebpf::helpers::r#gen::bpf_snprintf;

#[map]
static UNLINK_PARENT_TEMP: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static MKDIR_PATH_MAP: LruHashMap<u64, RawFilePath> = LruHashMap::with_max_entries(4096, 0);

#[map]
static PATH_TEMP: PerCpuArray<[u8; 512]> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawRmdirContext {
    pub file_path: [u8; 256],
    pub inode: u64,
    pub mode: u16,
    pub _padding: [u8; 6],
}

#[map]
static RMDIR_PATH_MAP: LruHashMap<u64, RawRmdirContext> = LruHashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingTruncate {
    dentry: u64,
    file: u64,
    file_path: [u8; 256],
}

#[map]
static TRUNCATE_PENDING: HashMap<u64, PendingTruncate> = HashMap::with_max_entries(4096, 0);

#[map]
static TRUNCATE_TEMP: PerCpuArray<PendingTruncate> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FTRUNCATE_ACTIVE: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingChown {
    path_addr: u64,
    file_path: [u8; 256],
}

#[map]
static CHOWN_PENDING: HashMap<u64, PendingChown> = HashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingChmod {
    path_addr: u64,
    file_path: [u8; 256],
}

#[map]
static CHMOD_PENDING: HashMap<u64, PendingChmod> = HashMap::with_max_entries(4096, 0);

static UNLINK_PATH_FMT: [u8; 6] = *b"%s/%s\0";
static UNLINK_ROOT_FMT: [u8; 5] = *b"%s%s\0";

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

        let ppid = if task.is_null() {
            0
        } else {
            match bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent)) {
                Ok(parent) if !parent.is_null() => {
                    bpf_probe_read_kernel(core::ptr::addr_of!((*parent).tgid)).unwrap_or(0) as u32
                }
                _ => 0,
            }
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
    let mut events = match EVENTS.reserve::<PendingConnect>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    let header = build_event_header(event_type);
    if filter_events(FilterOwner::Network, &header, None, None) {
        events.discard(0);
        return Ok(0);
    }

    let tid = bpf_get_current_pid_tgid() as u32;

    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&sock_daddr(sock).to_ne_bytes());
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&sock_rcv_saddr(sock).to_ne_bytes());

    events.write(PendingConnect {
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

    events.submit(0);
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
        let mut events = match EVENTS.reserve::<PendingConnect>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let header = build_event_header(event_type);
        if filter_events(FilterOwner::Network, &header, None, None) {
            events.discard(0);
            return Ok(0);
        }

        let tid = bpf_get_current_pid_tgid() as u32;

        let daddr = match read_v6_addr(core::ptr::addr_of!((*sock).__sk_common.skc_v6_daddr)) {
            Ok(a) => a,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };
        let src_addr = match read_v6_addr(core::ptr::addr_of!((*sock).__sk_common.skc_v6_rcv_saddr))
        {
            Ok(a) => a,
            Err(_) => {
                events.discard(0);
                return Ok(0);
            }
        };

        events.write(PendingConnect {
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
        events.submit(0);
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
        if filter_events(FilterOwner::Process, &header, None, None) {
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

        events.write(RawProcessStartEvent { header, filename });

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
        if filter_events(FilterOwner::Process, &header, None, None) {
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

#[lsm]
fn file_open(ctx: LsmContext) -> i32 {
    match { try_file_open(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    unsafe {
        let file: *const file = ctx.arg(0);
        if file.is_null() {
            return Ok(0);
        }

        let path_buf = match PATH_BUF.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Ok(0),
        };

        let path =
            core::ptr::addr_of!((*file).__bindgen_anon_1.f_path) as *mut aya_ebpf::bindings::path;

        path_buf.fill(0);
        let ret = bpf_d_path(path, path_buf.as_mut_ptr() as *mut _, path_buf.len() as u32);

        if ret < 0 {
            return Ok(0);
        }

        let key = file as u64;

        let value = RawFilePath {
            filepath: *path_buf,
        };

        let _ = FILE_PATH_MAP.insert(&key, &value, 0);
    }

    Ok(0)
}

const FMODE_CREATED: u32 = 0x100000;
const MAX_ERRNO: u64 = 4095;

#[fexit]
fn do_filp_open(ctx: FExitContext) -> i32 {
    match try_do_filp_open(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_do_filp_open(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileCreateEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let file: *const file = ctx.arg(3);
        let key = file as u64;

        if file.is_null() || key >= u64::MAX - MAX_ERRNO + 1 {
            events.discard(0);
            return Ok(0);
        }

        if (*file).f_mode & FMODE_CREATED == 0 {
            events.discard(0);
            return Ok(0);
        }

        let output = capture_file(file);

        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        let header = build_event_header(EventType::FileCreate);

        let file_path = match FILE_PATH_MAP.get(&key) {
            Some(val) => val.filepath,
            None => {
                events.discard(0);
                return Ok(0);
            }
        };

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            events.discard(0);
            return Ok(0);
        }

        events.write(RawFileCreateEvent {
            header,
            file_path,
            file_mode: output.1,
            inode: (*(*file).f_inode).i_ino,
            retval: 0,
            flags: (*file).f_flags,
        });

        events.submit(0);
    }

    Ok(0)
}

#[inline(always)]
fn resolve_path(
    parent: *const path,
    target: *const dentry,
    buf: &mut [u8; 256],
) -> Result<usize, i32> {
    unsafe {
        if parent.is_null() || target.is_null() {
            return Err(-22);
        }

        // PATH_TEMP is 512 bytes.
        let path_temp = match PATH_TEMP.get_ptr_mut(0) {
            Some(p) => &mut *p,
            None => return Err(-12),
        };
        let ptr = path_temp.as_mut_ptr();

        // Constant-size zeroing: everything past the path stays 0.
        *path_temp = [0u8; 512];

        let name = bpf_probe_read_kernel(core::ptr::addr_of!((*target).__bindgen_anon_1.d_name))
            .map_err(|_| -14)?;
        let nlen_raw = name.__bindgen_anon_1.__bindgen_anon_1.len;
        if nlen_raw == 0 || nlen_raw > 253 {
            return Err(-36);
        }
        let nlen = (nlen_raw & 0xff) as u32;

        // Parent path, right-aligned in path_temp[256-n .. 256), NUL at path_temp[255].
        let n = bpf_d_path(parent as *mut _, ptr as *mut _, 256);
        if n < 2 || n > 256 {
            return Err(-36);
        }
        let n = (n as u32) & 0x1ff;
        let start = 256 - n; // 0..=254

        let len: u32;
        if n == 2 {
            // Parent is "/" - reuse the NUL slot.
            let dst = core::slice::from_raw_parts_mut(ptr.add(255), nlen as usize);
            bpf_probe_read_kernel_buf(name.name, dst).map_err(|_| -14)?;
            len = 1 + nlen;
        } else {
            *ptr.add(255) = b'/';
            let dst = core::slice::from_raw_parts_mut(ptr.add(256), nlen as usize);
            bpf_probe_read_kernel_buf(name.name, dst).map_err(|_| -14)?;
            len = n + nlen;
        }

        // Keep at least one trailing NUL inside the 256-byte window.
        if len > 255 {
            return Err(-36);
        }

        // Constant 256-byte copy: source extent is start (<= 254) + 256 = 510 < 512,
        bpf_probe_read_kernel_buf(ptr.add((start & 0xff) as usize).cast_const(), buf)
            .map_err(|_| -14)?;

        Ok(len as usize)
    }
}

#[lsm(hook = "path_mkdir", sleepable)]
pub fn path_mkdir(ctx: LsmContext) -> i32 {
    let _ = try_path_mkdir(&ctx);
    0
}

fn try_path_mkdir(ctx: &LsmContext) -> Result<i32, i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();

        let _ = MKDIR_PATH_MAP.remove(&key);

        let parent: *const path = ctx.arg(0);
        let target: *const dentry = ctx.arg(1);

        let path_buf = match PATH_BUF.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Ok(0),
        };

        if resolve_path(parent, target, path_buf).is_err() {
            return Ok(0);
        }

        let value = RawFilePath {
            filepath: *path_buf,
        };

        let _ = MKDIR_PATH_MAP.insert(&key, &value, 0);
    }

    Ok(0)
}

#[fexit]
fn vfs_mkdir(ctx: FExitContext) -> i32 {
    match try_vfs_mkdir(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_mkdir(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();

        let file_path = match MKDIR_PATH_MAP.get(&key) {
            Some(value) => value.filepath,
            None => return Ok(0),
        };

        let _ = MKDIR_PATH_MAP.remove(&key);

        let result: *const dentry = ctx.arg(4);

        if result.is_null() {
            return Ok(0);
        }

        let (inode, mode, retval) = if result as u64 >= u64::MAX - 4094 {
            let retval = result as i64 as i32;
            let mode: u16 = ctx.arg(3);

            (0u64, mode, retval)
        } else {
            let inode = (*result).d_inode;

            if inode.is_null() {
                return Ok(0);
            }

            ((*inode).i_ino, (*inode).i_mode, 0i32)
        };

        let header = build_event_header(EventType::Mkdir);

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            return Ok(0);
        }

        let mut events = match EVENTS.reserve::<RawMkdirEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        events.write(RawMkdirEvent {
            header,
            file_path,
            inode,
            mode,
            retval,
        });

        events.submit(0);
    }

    Ok(0)
}

#[lsm(hook = "path_rmdir", sleepable)]
pub fn path_rmdir(ctx: LsmContext) -> i32 {
    let _ = try_path_rmdir(&ctx);
    0
}

fn try_path_rmdir(ctx: &LsmContext) -> Result<i32, i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();

        let _ = RMDIR_PATH_MAP.remove(&key);

        let parent: *const path = ctx.arg(0);
        let target: *const dentry = ctx.arg(1);

        if parent.is_null() || target.is_null() {
            return Ok(0);
        }

        let inode =
            bpf_probe_read_kernel(core::ptr::addr_of!((*target).d_inode)).map_err(|_| -14)?;

        if inode.is_null() {
            return Ok(0);
        }

        let ino = bpf_probe_read_kernel(core::ptr::addr_of!((*inode).i_ino)).map_err(|_| -14)?;

        let mode = bpf_probe_read_kernel(core::ptr::addr_of!((*inode).i_mode)).map_err(|_| -14)?;

        let path_buf = match PATH_BUF.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return Ok(0),
        };

        if resolve_path(parent, target, path_buf).is_err() {
            return Ok(0);
        }

        let value = RawRmdirContext {
            file_path: *path_buf,
            inode: ino,
            mode,
            _padding: [0; 6],
        };

        let _ = RMDIR_PATH_MAP.insert(&key, &value, 0);
    }

    Ok(0)
}

#[fexit]
fn vfs_rmdir(ctx: FExitContext) -> i32 {
    match try_vfs_rmdir(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_vfs_rmdir(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();

        let value = match RMDIR_PATH_MAP.get(&key) {
            Some(value) => *value,
            None => return Ok(0),
        };

        let _ = RMDIR_PATH_MAP.remove(&key);

        let retval: i32 = ctx.arg(3);

        let header = build_event_header(EventType::Rmdir);

        if filter_events(FilterOwner::File, &header, Some(&value.file_path), None) {
            return Ok(0);
        }

        let mut events = match EVENTS.reserve::<RawRmdirEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        events.write(RawRmdirEvent {
            header,
            file_path: value.file_path,
            inode: value.inode,
            mode: value.mode,
            retval,
        });

        events.submit(0);
    }

    Ok(0)
}

#[fexit]
fn do_truncate(ctx: FExitContext) -> i32 {
    match { try_do_truncate(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_do_truncate(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileTruncateEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };
    }

    Ok(0)
}

#[fexit]
fn security_path_rmdir_exit(ctx: FExitContext) -> i32 {
    unsafe {
        let retval: i32 = ctx.arg(2);

        if retval != 0 {
            let key = bpf_get_current_pid_tgid();
            let _ = RMDIR_PATH_MAP.remove(&key);
        }

        0
    }
}

#[fexit]
fn vfs_open(ctx: FExitContext) -> i32 {
    match { try_vfs_open(ctx) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[fexit]
fn vfs_fsync_range_exit(ctx: FExitContext) -> i32 {
    let _ = try_vfs_fsync_range_exit(&ctx);
    0
}

#[inline(always)]
fn try_vfs_fsync_range_exit(ctx: &FExitContext) -> Result<(), i32> {
    unsafe {
        let filp: *const file = ctx.arg(0);
        if filp.is_null() {
            return Ok(());
        }

        let inode_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*filp).f_inode)).map_err(|_| -14)?;
        if inode_ptr.is_null() {
            return Ok(());
        }

        let inode =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_ino)).map_err(|_| -14)? as u64;
        let mode: u16 =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_mode)).map_err(|_| -14)?;

        let start: i64 = ctx.arg(1);
        let end: i64 = ctx.arg(2);
        let datasync: i32 = ctx.arg(3);
        let retval: i32 = ctx.arg(4);
        let header = build_event_header(EventType::FileSync);

        if filter_events(FilterOwner::File, &header, None, None) {
            return Ok(());
        }

        let Some(mut entry) = EVENTS.reserve::<RawFileSyncEvent>(0) else {
            return Ok(());
        };

        entry.write(RawFileSyncEvent {
            header,
            file_path: [0; 256],
            inode,
            start,
            end,
            datasync,
            retval,
            mode,
        });
        entry.submit(0);
    }

    Ok(())
}

fn try_vfs_open(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileOpenEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileOpen);

        let file: *const file = ctx.arg(1);

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let output = capture_file(file);

        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        let flags = (*file).f_flags;
        let key = file as u64;

        let file_path = if let Some(val) = FILE_PATH_MAP.get(&key) {
            val.filepath
        } else {
            events.discard(0);
            return Ok(0);
        };

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            events.discard(0);
            return Ok(0);
        }

        events.write(RawFileOpenEvent {
            header,
            file_path,
            file_mode: output.1,
            inode: (*(*file).f_inode).i_ino,
            retval: ctx.arg(2),
            flags,
        });
        events.submit(0);
    }

    Ok(0)
}

#[fexit]
pub fn __fput(ctx: FExitContext) -> i32 {
    match try_fput(ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn try_fput(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let file: *const file = ctx.arg(0);
        let key = file as u64;
        let _ = FILE_PATH_MAP.remove(&key);
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

fn try_flip_close(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let mut events = match EVENTS.reserve::<RawFileCloseEvent>(0) {
            Some(s) => s,
            None => return Ok(0),
        };

        let header = build_event_header(EventType::FileClose);

        let file: *const file = ctx.arg(0);

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let flags = (*file).f_flags;

        let output = capture_file(file);

        if !output.0 {
            events.discard(0);
            return Ok(0);
        }

        if file.is_null() {
            events.discard(0);
            return Ok(0);
        }

        let key = file as u64;
        let file_path = if let Some(val) = FILE_PATH_MAP.get(&key) {
            val.filepath
        } else {
            events.discard(0);
            return Ok(0);
        };

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            events.discard(0);
            return Ok(0);
        }

        events.write(RawFileCloseEvent {
            header,
            file_path,
            file_mode: output.1,
            inode: (*(*file).f_inode).i_ino,
            retval: ctx.arg(2),
            flags,
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
        if filter_events(FilterOwner::Process, &header, None, None) {
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

#[fentry]
fn vfs_truncate_enter(ctx: FEntryContext) -> i32 {
    let _ = try_vfs_truncate_enter(&ctx);
    0
}

#[inline(always)]
fn try_vfs_truncate_enter(ctx: &FEntryContext) -> Result<(), i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();
        let _ = TRUNCATE_PENDING.remove(&key);

        let target: *const path = ctx.arg(0);
        if target.is_null() {
            return Ok(());
        }

        let target_dentry =
            bpf_probe_read_kernel(core::ptr::addr_of!((*target).dentry)).map_err(|_| -14)?;
        if target_dentry.is_null() {
            return Ok(());
        }

        let temp = PATH_TEMP.get_ptr_mut(0).ok_or(-12)?;
        let temp_ptr = (*temp).as_mut_ptr();

        let len = bpf_d_path(target.cast_mut().cast(), temp_ptr.cast(), 256);
        if len <= 0 || len > 256 {
            return Ok(());
        }

        save_truncate_path(key, target_dentry, 0, temp_ptr, len as usize)
    }
}

#[inline(always)]
unsafe fn save_truncate_path(
    key: u64,
    target: *const dentry,
    file_addr: u64,
    source: *const u8,
    len: usize,
) -> Result<(), i32> {
    unsafe {
        let pending = &mut *TRUNCATE_TEMP.get_ptr_mut(0).ok_or(-12)?;
        pending.dentry = target as u64;
        pending.file = file_addr;
        pending.file_path = [0; 256];

        // Both callers bound len to 1..=256. Copy through the NUL and
        // keep the remaining bytes zero for exact path filtering.
        let dst = core::slice::from_raw_parts_mut(pending.file_path.as_mut_ptr(), len);
        bpf_probe_read_kernel_buf(source, dst).map_err(|_| -14)?;

        let _ = TRUNCATE_PENDING.insert(&key, pending, 0);
        Ok(())
    }
}

#[fexit]
fn do_truncate_exit(ctx: FExitContext) -> i32 {
    let _ = try_do_truncate_exit(&ctx);
    0
}

#[inline(always)]
fn try_do_truncate_exit(ctx: &FExitContext) -> Result<(), i32> {
    unsafe {
        let target: *const dentry = ctx.arg(1);
        if target.is_null() {
            return Ok(());
        }

        let filp: *const file = ctx.arg(4);
        let file_path = if filp.is_null() {
            let key = bpf_get_current_pid_tgid();
            let Some(pending) = TRUNCATE_PENDING.get(&key) else {
                return Ok(());
            };

            if pending.dentry != target as u64 {
                return Ok(());
            }

            let file_path = pending.file_path;
            let _ = TRUNCATE_PENDING.remove(&key);
            file_path
        } else {
            [0u8; 256]
        };

        let inode_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*target).d_inode)).map_err(|_| -14)?;
        if inode_ptr.is_null() {
            return Ok(());
        }

        let inode =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_ino)).map_err(|_| -14)? as u64;
        let mode: u16 =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_mode)).map_err(|_| -14)?;
        let requested_size: i64 = ctx.arg(2);
        let retval: i32 = ctx.arg(5);
        let header = build_event_header(EventType::Truncate);

        let filter_path = if filp.is_null() {
            Some(&file_path)
        } else {
            None
        };

        if filter_events(FilterOwner::File, &header, filter_path, None) {
            return Ok(());
        }

        let Some(mut entry) = EVENTS.reserve::<RawFileTruncateEvent>(0) else {
            return Ok(());
        };

        entry.write(RawFileTruncateEvent {
            header,
            file_path,
            inode,
            mode,
            requested_size,
            retval,
        });
        entry.submit(0);

        Ok(())
    }
}

#[fexit]
fn vfs_truncate_exit(_ctx: FExitContext) -> i32 {
    let key = bpf_get_current_pid_tgid();
    let _ = TRUNCATE_PENDING.remove(&key);
    0
}

#[fexit]
fn do_ftruncate_cleanup(ctx: FExitContext) -> i32 {
    unsafe {
        let key = bpf_get_current_pid_tgid();
        let filp: *const file = ctx.arg(0);

        unsafe {
            if let Some(pending) = TRUNCATE_PENDING.get(&key) {
                if pending.file == filp as u64 {
                    let _ = TRUNCATE_PENDING.remove(&key);
                }
            }
        }

        let _ = FTRUNCATE_ACTIVE.remove(&key);
        0
    }
}

#[lsm(hook = "path_chown", sleepable)]
pub fn path_chown(ctx: LsmContext) -> i32 {
    unsafe {
        let previous_ret: i32 = ctx.arg(3);

        let key = bpf_get_current_pid_tgid();
        let _ = CHOWN_PENDING.remove(&key);

        if previous_ret == 0 {
            let _ = try_capture_path_chown(&ctx, key);
        }

        previous_ret
    }
}

#[inline(always)]
fn try_capture_path_chown(ctx: &LsmContext, key: u64) -> Result<(), i32> {
    unsafe {
        let target: *const path = ctx.arg(0);
        if target.is_null() {
            return Ok(());
        }

        let temp = PATH_TEMP.get_ptr_mut(0).ok_or(-12)?;
        let temp_ptr = (*temp).as_mut_ptr();

        let len = bpf_d_path(target.cast_mut().cast(), temp_ptr.cast(), 256);
        if len <= 0 || len > 256 {
            return Ok(());
        }

        let path_buf = &mut *PATH_BUF.get_ptr_mut(0).ok_or(-12)?;
        *path_buf = [0; 256];

        // Copy the NUL too, keeping the remaining bytes zero for path filters.
        let dst = core::slice::from_raw_parts_mut(path_buf.as_mut_ptr(), len as usize);
        bpf_probe_read_kernel_buf(temp_ptr.cast_const(), dst).map_err(|_| -14)?;

        let pending = PendingChown {
            path_addr: target as u64,
            file_path: *path_buf,
        };

        let _ = CHOWN_PENDING.insert(&key, &pending, 0);
        Ok(())
    }
}

#[fexit]
fn chown_common_exit(ctx: FExitContext) -> i32 {
    let _ = try_chown_common_exit(&ctx);
    0
}

#[inline(always)]
fn try_chown_common_exit(ctx: &FExitContext) -> Result<(), i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();
        let target: *const path = ctx.arg(0);

        let mut file_path = [0u8; 256];
        let mut has_path = false;

        if let Some(pending) = CHOWN_PENDING.get(&key) {
            if !target.is_null() && pending.path_addr == target as u64 {
                file_path = pending.file_path;
                has_path = true;
            }
            let _ = CHOWN_PENDING.remove(&key);
        }

        if target.is_null() {
            return Ok(());
        }

        let dentry_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*target).dentry)).map_err(|_| -14)?;
        if dentry_ptr.is_null() {
            return Ok(());
        }

        let inode_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*dentry_ptr).d_inode)).map_err(|_| -14)?;
        if inode_ptr.is_null() {
            return Ok(());
        }

        let inode =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_ino)).map_err(|_| -14)? as u64;

        let requested_uid: u32 = ctx.arg(1);
        let requested_gid: u32 = ctx.arg(2);
        let retval: i32 = ctx.arg(3);
        let header = build_event_header(EventType::FileChown);
        let filter_path = if has_path { Some(&file_path) } else { None };

        if filter_events(FilterOwner::File, &header, filter_path, None) {
            return Ok(());
        }

        let Some(mut entry) = EVENTS.reserve::<RawFileChownEvent>(0) else {
            return Ok(());
        };

        entry.write(RawFileChownEvent {
            header,
            file_path,
            inode,
            requested_uid,
            requested_gid,
            retval,
        });
        entry.submit(0);
    }

    Ok(())
}

#[lsm(hook = "path_chmod", sleepable)]
pub fn path_chmod(ctx: LsmContext) -> i32 {
    unsafe {
        let previous_ret: i32 = ctx.arg(2);
        let key = bpf_get_current_pid_tgid();

        let _ = CHMOD_PENDING.remove(&key);
        if previous_ret == 0 {
            let _ = try_capture_path_chmod(&ctx, key);
        }

        previous_ret
    }
}

#[inline(always)]
fn try_capture_path_chmod(ctx: &LsmContext, key: u64) -> Result<(), i32> {
    unsafe {
        let target: *const path = ctx.arg(0);
        if target.is_null() {
            return Ok(());
        }

        let scratch = PATH_TEMP.get_ptr_mut(0).ok_or(-12)?;
        let scratch_ptr = (*scratch).as_mut_ptr();

        let len = bpf_d_path(target.cast_mut().cast(), scratch_ptr.cast(), 256);
        if len <= 0 || len > 256 {
            return Ok(());
        }

        let path_buf = &mut *PATH_BUF.get_ptr_mut(0).ok_or(-12)?;
        *path_buf = [0; 256];

        // Copy through the NUL and leave the rest zeroed for exact-path filters.
        let dst = core::slice::from_raw_parts_mut(path_buf.as_mut_ptr(), len as usize);
        bpf_probe_read_kernel_buf(scratch_ptr.cast_const(), dst).map_err(|_| -14)?;

        let pending = PendingChmod {
            path_addr: target as u64,
            file_path: *path_buf,
        };

        let _ = CHMOD_PENDING.insert(&key, &pending, 0);
        Ok(())
    }
}

#[fexit]
fn chmod_common_exit(ctx: FExitContext) -> i32 {
    let _ = try_chmod_common_exit(&ctx);
    0
}

#[inline(always)]
fn try_chmod_common_exit(ctx: &FExitContext) -> Result<(), i32> {
    unsafe {
        let key = bpf_get_current_pid_tgid();
        let target: *const path = ctx.arg(0);

        let mut file_path = [0u8; 256];
        let mut has_path = false;

        if let Some(pending) = CHMOD_PENDING.get(&key) {
            if !target.is_null() && pending.path_addr == target as u64 {
                file_path = pending.file_path;
                has_path = true;
            }
            let _ = CHMOD_PENDING.remove(&key);
        }

        if target.is_null() {
            return Ok(());
        }

        let dentry_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*target).dentry)).map_err(|_| -14)?;
        if dentry_ptr.is_null() {
            return Ok(());
        }

        let inode_ptr =
            bpf_probe_read_kernel(core::ptr::addr_of!((*dentry_ptr).d_inode)).map_err(|_| -14)?;
        if inode_ptr.is_null() {
            return Ok(());
        }

        let inode =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_ino)).map_err(|_| -14)? as u64;
        let inode_mode: u16 =
            bpf_probe_read_kernel(core::ptr::addr_of!((*inode_ptr).i_mode)).map_err(|_| -14)?;

        let mode: u16 = ctx.arg(1);
        let requested_mode = mode & 0o7777;
        let retval: i32 = ctx.arg(2);
        let header = build_event_header(EventType::FileChmod);
        let filter_path = if has_path { Some(&file_path) } else { None };

        if filter_events(FilterOwner::File, &header, filter_path, None) {
            return Ok(());
        }

        let Some(mut entry) = EVENTS.reserve::<RawFileChmodEvent>(0) else {
            return Ok(());
        };

        entry.write(RawFileChmodEvent {
            header,
            file_path,
            inode,
            requested_mode,
            inode_mode,
            retval,
        });
        entry.submit(0);

        Ok(())
    }
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

        let key = file as u64;
        let file_path = if let Some(val) = FILE_PATH_MAP.get(&key) {
            val.filepath
        } else {
            events.discard(0);
            return Ok(0);
        };

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            events.discard(0);
            return Ok(0);
        }

        let flags = (*file).f_flags;
        events.write(RawFileReadEvent {
            header,
            file_path,
            file_mode: output.1,
            inode: (*(*file).f_inode).i_ino,
            retval: ctx.arg(4),
            flags,
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

        let key = file as u64;
        let file_path = if let Some(val) = FILE_PATH_MAP.get(&key) {
            val.filepath
        } else {
            events.discard(0);
            return Ok(0);
        };

        if filter_events(FilterOwner::File, &header, Some(&file_path), None) {
            events.discard(0);
            return Ok(0);
        }

        let flags = (*file).f_flags;

        events.write(RawFileWriteEvent {
            header,
            file_path,
            file_mode: output.1,
            inode: (*(*file).f_inode).i_ino,
            retval: ctx.arg(4),
            flags,
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

#[lsm(hook = "path_unlink", sleepable)]
pub fn path_unlink(ctx: LsmContext) -> i32 {
    unsafe {
        let ret: i32 = ctx.arg(2);

        if ret != 0 {
            return ret;
        }

        let tid = bpf_get_current_pid_tgid();

        let _ = UNLINK_PENDING.remove(&tid);

        let dir: *const aya_ebpf::bindings::path = ctx.arg(0);
        let target: *const dentry = ctx.arg(1);

        if dir.is_null() || target.is_null() {
            return ret;
        }

        let inode = (*target).d_inode;

        if inode.is_null() {
            return ret;
        }

        let (capture, file_mode) = capture_inode(inode);

        if !capture {
            return ret;
        }

        let pending = match UNLINK_TEMP.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return ret,
        };

        let parent = match UNLINK_PARENT_TEMP.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return ret,
        };

        let name = match UNLINK_NAME_TEMP.get_ptr_mut(0) {
            Some(ptr) => &mut *ptr,
            None => return ret,
        };

        pending.dentry = target as u64;
        pending.file_mode = file_mode;

        pending.path.fill(0);

        // Resolve the parent directory.
        // bpf_d_path returns the length including NUL.
        let parent_n = bpf_d_path(dir as *mut _, parent.as_mut_ptr() as *mut _, 256);

        if parent_n <= 1 || parent_n > 256 {
            return ret;
        }

        let name_ptr = match bpf_probe_read_kernel(core::ptr::addr_of!(
            (*target).__bindgen_anon_1.d_name.name
        )) {
            Ok(ptr) => ptr,
            Err(_) => return ret,
        };

        if name_ptr.is_null() {
            return ret;
        }

        let name_n =
            bpf_probe_read_kernel_str(name.as_mut_ptr() as *mut _, 256, name_ptr as *const _);

        if name_n <= 1 || name_n > 256 {
            return ret;
        }

        //  Reject truncation before formatting.
        //  parent_n and name_n both include their
        //  terminating NUL bytes.
        let parent_len = parent_n as usize - 1;
        let name_len = name_n as usize - 1;

        // Root already contains '/'.
        // "/" + "file" => "/file"

        // Other parents require a separator:
        // "/tmp" + "/" + "file" => "/tmp/file"
        let is_root = parent_len == 1;

        let separator_len = if is_root { 0usize } else { 1usize };

        let required = parent_len + separator_len + name_len + 1;

        if required > 256 {
            return ret;
        }

        // bpf_snprintf expects an array of u64 arguments.
        // For %s, each argument is a pointer to a
        // NUL-terminated string.
        let mut args = [parent.as_ptr() as u64, name.as_ptr() as u64];

        let (fmt, fmt_len) = if is_root {
            (UNLINK_ROOT_FMT.as_ptr(), 5usize)
        } else {
            (UNLINK_PATH_FMT.as_ptr(), 6usize)
        };

        let _ = fmt_len;

        let written = bpf_snprintf(
            pending.path.as_mut_ptr() as *mut _,
            256,
            fmt as *const _,
            args.as_mut_ptr(),
            core::mem::size_of_val(&args) as u32,
        );

        if written <= 0 || written > 256 {
            return ret;
        }

        if written as usize != required {
            return ret;
        }

        let _ = UNLINK_PENDING.insert(&tid, pending, 0);

        ret
    }
}

#[fexit]
pub fn vfs_unlink(ctx: FExitContext) -> i32 {
    match try_vfs_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_vfs_unlink(ctx: FExitContext) -> Result<i32, i32> {
    unsafe {
        let tid = bpf_get_current_pid_tgid();
        let target: *const dentry = ctx.arg(2);

        let result = try_emit_unlink(ctx, tid, target);

        let _ = UNLINK_PENDING.remove(&tid);
        result
    }
}

fn try_emit_unlink(ctx: FExitContext, tid: u64, target: *const dentry) -> Result<i32, i32> {
    unsafe {
        if target.is_null() {
            return Ok(0);
        }

        let retval: i32 = ctx.arg(4);

        if retval != 0 {
            return Ok(0);
        }

        let pending = match UNLINK_PENDING.get(&tid) {
            Some(p) if p.dentry == target as u64 => p,
            _ => return Ok(0),
        };

        let header = build_event_header(EventType::FileDelete);

        if filter_events(FilterOwner::File, &header, Some(&pending.path), None) {
            return Ok(0);
        }

        let mut events = match EVENTS.reserve::<RawFileDeleteEvent>(0) {
            Some(e) => e,
            None => return Ok(0),
        };

        let event = events.as_mut_ptr().cast::<RawFileDeleteEvent>();

        core::ptr::addr_of_mut!((*event).header).write(header);

        core::ptr::copy_nonoverlapping(
            pending.path.as_ptr(),
            core::ptr::addr_of_mut!((*event).file_path).cast::<u8>(),
            256,
        );

        core::ptr::addr_of_mut!((*event).file_mode).write(pending.file_mode);

        core::ptr::addr_of_mut!((*event).retval).write(retval);

        events.submit(0);

        Ok(0)
    }
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

        if filter_events(
            FilterOwner::File,
            &header,
            Some(&event.old_filename),
            Some(&event.new_filename),
        ) {
            return Ok(0);
        }

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

/// Returns true when an event must be discarded.
/// `path` and `secondary_path` are NUL-padded kernel byte buffers.
/// For rename events, either the old or the new name can match.
#[inline(always)]
fn filter_events(
    filter_owner: FilterOwner,
    header: &RawEventHeader,
    path: Option<&[u8; 256]>,
    secondary_path: Option<&[u8; 256]>,
) -> bool {
    unsafe {
        let filter_owner = filter_owner as u32;
        let key = match FILTER.get(&filter_owner) {
            Some(key) => key,
            None => return false,
        };

        match key {
            FilterKey::None => false,
            FilterKey::Path(expected) => {
                if filter_owner != (FilterOwner::File as u32) {
                    return true;
                }

                let first_matches = match path {
                    Some(actual) => path_matches(expected, actual),
                    None => false,
                };
                let second_matches = match secondary_path {
                    Some(actual) => path_matches(expected, actual),
                    None => false,
                };
                !(first_matches || second_matches)
            }
            FilterKey::Pid(pid) => header.pid != *pid,
            FilterKey::Tid(tid) => header.tid != *tid,
            FilterKey::Ppid(ppid) => header.ppid != *ppid,
            FilterKey::Uid(uid) => header.uid != *uid,
            FilterKey::Gid(gid) => header.gid != *gid,
            _ => false,
        }
    }
}

/// Exact comparison of two fixed-size NUL-padded path buffers.
/// Avoids a 256-byte stack copy of the map value.
#[inline(always)]
fn path_matches(expected: &[u8; 256], actual: &[u8; 256]) -> bool {
    for i in 0..256 {
        if expected[i] != actual[i] {
            return false;
        }
        if expected[i] == 0 {
            return true;
        }
    }
    true
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

        if filter_events(FilterOwner::Memory, &header, None, None) {
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
