extern crate libc;
extern crate nix;
use nix::sys::ptrace::{ptrace, ptrace_setoptions};
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;

use std::env;
use std::io::Write;
use std::io;
use std::mem;
use std::ptr;

const CMD_NAME: &'static str = "procout";

fn main() {
    std::process::exit(match run() {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("{}: {}", CMD_NAME, err);
            1
        }
    });
}

fn run() -> Result<(), String> {
    match env::args().nth(1).and_then(|x| x.parse().ok()) {
        Some(pid) => procout(nix::unistd::Pid::from_raw(pid)),
        None => Err(String::from("specify pid")),
    }
}

fn procout(pid: nix::unistd::Pid) -> Result<(), String> {
    ptrace(ptrace::PTRACE_ATTACH, pid, ptr::null_mut(), ptr::null_mut()).map_err(|e| format!("failed to ptrace attach {} ({})", pid, e))?;
    ptrace_setoptions(pid, ptrace::PTRACE_O_TRACESYSGOOD).map_err(|e| format!("failed to ptrace setoptions {} ({})", pid, e))?;
    let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
    let regs_ptr: *mut libc::user_regs_struct = &mut regs;
    let mut is_enter_stop: bool = false;
    let mut prev_orig_rax: u64 = 0;
    loop {
        match waitpid(pid, None) {
            Err(_) | Ok(WaitStatus::Exited(_, _)) => break,
            Ok(WaitStatus::PtraceSyscall(_)) => {
                ptrace(ptrace::PTRACE_GETREGS, pid, ptr::null_mut(), regs_ptr as *mut libc::c_void)
                    .map_err(|e| format!("failed to ptrace getregs {} ({})", pid, e))?;
                is_enter_stop = if prev_orig_rax == regs.orig_rax { !is_enter_stop } else { true };
                prev_orig_rax = regs.orig_rax;
                if regs.orig_rax == libc::SYS_write as u64 && is_enter_stop {
                    output(peek_bytes(pid, regs.rsi, regs.rdx), regs.rdi)?;
                }
            }
            _ => {}
        }
        ptrace(ptrace::PTRACE_SYSCALL, pid, ptr::null_mut(), ptr::null_mut()).map_err(|e| format!("failed to ptrace syscall {} ({})", pid, e))?;
    }
    Ok(())
}

fn peek_bytes(pid: nix::unistd::Pid, addr: u64, size: u64) -> Vec<u8> {
    let mut vec = (0..(size + 7) / 8)
        .filter_map(|i| {
            ptrace(ptrace::PTRACE_PEEKDATA, pid, (addr + 8 * i) as *mut libc::c_void, ptr::null_mut())
                .map(|l| unsafe { mem::transmute(l) })
                .ok()
        })
        .collect::<Vec<[u8; 8]>>()
        .concat();
    vec.truncate(size as usize);
    vec
}

fn output(bs: Vec<u8>, fd: u64) -> Result<(), String> {
    match fd {
        1 => {
            io::stdout().write_all(bs.as_slice()).map_err(|_| "failed to write to stdout")?;
            io::stdout().flush().map_err(|_| "failed to flush stdout")?;
        }
        2 => {
            io::stderr().write_all(bs.as_slice()).map_err(|_| "failed to write to stderr")?;
            io::stderr().flush().map_err(|_| "failed to flush stderr")?;
        }
        _ => {
            // sometimes want to print for debug?
        }
    }
    Ok(())
}
