#[cfg(test)]
mod bpfx_probe_checks {
    use crate::Bpfx;
    use crate::core::{TCP_ACCEPT, TCP_CLOSE, TCP_CONNECT, UDP_CLOSE, UDP_CONNECT};
    use crate::core::{
        attach_fentry, attach_fexit, attach_kprobe, attach_lsm_probe, attach_tracepoint,
    };

    #[test]
    fn network_probes_attach() {
        let bpfx = Bpfx::new().unwrap();
        let mut bpf = bpfx.bpf;
        let btf = bpfx.btf;
        let mut failures = Vec::new();

        for (program, target) in TCP_CONNECT {
            if let Err(err) = attach_fexit(&mut bpf, &btf, program, target) {
                failures.push(format!("TCP CONNECT -> {}: {:#}", target, err));
            }
        }

        for (program, target) in TCP_ACCEPT {
            if let Err(err) = attach_kprobe(&mut bpf, program, target) {
                failures.push(format!("TCP ACCEPT -> {}: {:#}", target, err));
            }
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, TCP_CLOSE.0, TCP_CLOSE.1) {
            failures.push(format!("TCP CLOSE -> {}: {:#}", TCP_CLOSE.1, err));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "inet_bind", "inet_bind") {
            failures.push(format!("TCP BIND -> inet_bind: {:#}", err));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "inet_listen", "inet_listen") {
            failures.push(format!("TCP LISTEN -> inet_listen: {:#}", err));
        }

        for (program, target) in UDP_CONNECT {
            if let Err(err) = attach_fexit(&mut bpf, &btf, program, target) {
                failures.push(format!("UDP CONNECT -> {}: {:#}", target, err));
            }
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, UDP_CLOSE.0, UDP_CLOSE.1) {
            failures.push(format!("UDP CLOSE -> {}: {:#}", UDP_CLOSE.1, err));
        }

        if failures.is_empty() {
            println!("all network probes attached successfully");
        } else {
            panic!(
                "{} network probe(s) failed:\n\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }

    #[test]
    fn process_probes_attach() {
        let bpfx = Bpfx::new().unwrap();
        let mut bpf = bpfx.bpf;
        let btf = bpfx.btf;

        let mut failures = Vec::new();

        if let Err(err) = attach_tracepoint(
            &mut bpf,
            "sched_process_exec",
            "sched",
            "sched_process_exec",
        ) {
            failures.push(format!("PROCESS START -> sched_process_exec: {err:#}"));
        }

        if let Err(err) = attach_tracepoint(
            &mut bpf,
            "sched_process_fork",
            "sched",
            "sched_process_fork",
        ) {
            failures.push(format!("PROCESS FORK -> sched_process_fork: {err:#}"));
        }

        if let Err(err) = attach_fentry(&mut bpf, &btf, "do_group_exit", "do_group_exit") {
            failures.push(format!("PROCESS EXIT -> do_group_exit: {err:#}"));
        }

        if failures.is_empty() {
            println!("all process probes attached successfully");
        } else {
            panic!(
                "{} process probe(s) failed:\n\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }

    #[test]
    fn memory_probes_attach() {
        let bpfx = Bpfx::new().unwrap();
        let mut bpf = bpfx.bpf;
        let btf = bpfx.btf;

        let mut failures = Vec::new();

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vm_mmap_pgoff", "vm_mmap_pgoff") {
            failures.push(format!("MEMORY MMAP -> vm_mmap_pgoff: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "__vm_munmap", "__vm_munmap") {
            failures.push(format!("MEMORY UNMAP -> __vm_munmap: {err:#}"));
        }

        if failures.is_empty() {
            println!("all memory probes attached successfully");
        } else {
            panic!(
                "{} memory probe(s) failed:\n\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }
    #[test]
    fn file_probes_attach() {
        let bpfx = Bpfx::new().unwrap();
        let mut bpf = bpfx.bpf;
        let btf = bpfx.btf;

        let mut failures = Vec::new();

        if let Err(err) = attach_lsm_probe(&mut bpf, &btf) {
            failures.push(format!("FILE LSM: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "__fput", "__fput") {
            failures.push(format!("FILE CLOSE/RELEASE -> __fput: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vfs_open", "vfs_open") {
            failures.push(format!("FILE OPEN -> vfs_open: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "filp_close", "filp_close") {
            failures.push(format!("FILE CLOSE -> filp_close: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vfs_read", "vfs_read") {
            failures.push(format!("FILE READ -> vfs_read: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vfs_write", "vfs_write") {
            failures.push(format!("FILE WRITE -> vfs_write: {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vfs_unlink", "vfs_unlink") {
            failures.push(format!("FILE DELETE -> vfs_unlink: {err:#}"));
        }

        if let Err(err) = attach_fentry(&mut bpf, &btf, "vfs_rename", "vfs_rename") {
            failures.push(format!("FILE RENAME -> vfs_rename (fentry): {err:#}"));
        }

        if let Err(err) = attach_fexit(&mut bpf, &btf, "vfs_rename_retval", "vfs_rename") {
            failures.push(format!("FILE RENAME -> vfs_rename (fexit): {err:#}"));
        }

        if failures.is_empty() {
            println!("all file probes attached successfully");
        } else {
            panic!(
                "{} file probe(s) failed:\n\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }
}
