use aya::{Ebpf, include_bytes_aligned, maps::RingBuf, programs::TracePoint};
use log::{info, warn};
use tokio::time::Duration;

const MAX_EVENTS_PER_TICK: usize = 512;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SyscallEvent {
    pid: u32,
    syscall_id: i64,
}

pub async fn init_ebpf() -> anyhow::Result<Ebpf> {
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/asystracer"
    )))?;

    {
        let program: &mut TracePoint = ebpf
            .program_mut("sys_enter")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sys_enter' not found in object"))?
            .try_into()?;
        program.load()?;
        program.attach("raw_syscalls", "sys_enter")?;
    }

    info!("Attached tracepoint raw_syscalls/sys_enter");

    Ok(ebpf)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut ebpf = init_ebpf().await?;

    info!("Listening for syscalls… Press Ctrl-C to stop.\n");

    let map = ebpf
        .map_mut("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("map 'EVENTS' not found"))?;
    let mut ring_buf = RingBuf::try_from(map)?;

    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down.");
                break;
            }

            _ = tokio::time::sleep(Duration::from_micros(500)) => {
                let mut count = 0;

                while let Some(item) = ring_buf.next() {
                    count += 1;

                    let data: &[u8] = &*item;

                    if data.len() < std::mem::size_of::<SyscallEvent>() {
                        warn!("Undersized event ({} bytes), skipping", data.len());
                        continue;
                    }

                    let event: SyscallEvent = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const SyscallEvent)
                    };

                    println!(
                        "pid={:<8} syscall_id={:<6}  ({})",
                        event.pid,
                        event.syscall_id,
                        syscall_name(event.syscall_id),
                    );

                    if count >= MAX_EVENTS_PER_TICK {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn syscall_name(id: i64) -> &'static str {
    match id {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        21 => "access",
        22 => "pipe",
        24 => "sched_yield",
        32 => "dup",
        33 => "dup2",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        87 => "unlink",
        89 => "readlink",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        158 => "arch_prctl",
        186 => "gettid",
        202 => "futex",
        218 => "set_tid_address",
        228 => "clock_gettime",
        231 => "exit_group",
        257 => "openat",
        262 => "newfstatat",
        318 => "getrandom",
        _ => "?",
    }
}
