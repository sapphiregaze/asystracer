#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_id: i64,
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint(category = "syscalls", name = "trace_sys_enter")]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(never)]
fn try_sys_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let syscall_id: i64 = unsafe { ctx.read_at(8)? };

    let tgid_pid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (tgid_pid >> 32) as u32;

    let mut entry = match EVENTS.reserve::<SyscallEvent>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    unsafe {
        let ptr = entry.as_mut_ptr();
        addr_of_mut!((*ptr).pid).write(pid);
        addr_of_mut!((*ptr).syscall_id).write(syscall_id);
    }

    entry.submit(0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
