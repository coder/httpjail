//! Restrict native strong-jail payloads to IPv4/IPv6 and netlink sockets,
//! permitting only connected AF_UNIX stream socketpairs for local thread IPC.
//! This prevents host pathname Unix socket IPC and VM VSOCK egress, neither
//! of which can be filtered by the namespace's IP nftables chains.

use std::io;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const LD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

// seccomp_data: syscall number @0, architecture @4, first argument @16.
// Unknown ABIs are killed instead of allowing 32-bit socketcall bypasses.
#[cfg(target_arch = "x86_64")]
static FILTER: [libc::sock_filter; 25] = [
    ins(LD, 0, 0, 4),
    ins(JEQ, 1, 0, 0xc000_003e), // AUDIT_ARCH_X86_64
    ins(RET, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ins(LD, 0, 0, 0),
    ins(
        (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
        0,
        1,
        0x4000_0000,
    ), // x32
    ins(RET, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ins(JEQ, 5, 0, libc::SYS_socket as u32),
    ins(JEQ, 10, 0, libc::SYS_socketpair as u32),
    ins(JEQ, 2, 0, libc::SYS_io_uring_setup as u32),
    ins(JEQ, 1, 0, libc::SYS_io_uring_enter as u32),
    ins(JEQ, 0, 6, libc::SYS_io_uring_register as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(LD, 0, 0, 16),
    ins(JEQ, 3, 0, libc::AF_INET as u32),
    ins(JEQ, 2, 0, libc::AF_INET6 as u32),
    ins(JEQ, 1, 0, libc::AF_NETLINK as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ALLOW),
    ins(LD, 0, 0, 16), // socketpair domain
    ins(JEQ, 0, 3, libc::AF_UNIX as u32),
    ins(LD, 0, 0, 24), // socketpair type (without CLOEXEC/NONBLOCK)
    ins(
        (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
        0,
        0,
        0xf,
    ),
    ins(JEQ, 1, 0, libc::SOCK_STREAM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ALLOW),
];

#[cfg(target_arch = "aarch64")]
static FILTER: [libc::sock_filter; 23] = [
    ins(LD, 0, 0, 4),
    ins(JEQ, 1, 0, 0xc000_00b7), // AUDIT_ARCH_AARCH64
    ins(RET, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ins(LD, 0, 0, 0),
    ins(JEQ, 5, 0, libc::SYS_socket as u32),
    ins(JEQ, 10, 0, libc::SYS_socketpair as u32),
    ins(JEQ, 2, 0, libc::SYS_io_uring_setup as u32),
    ins(JEQ, 1, 0, libc::SYS_io_uring_enter as u32),
    ins(JEQ, 0, 6, libc::SYS_io_uring_register as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(LD, 0, 0, 16),
    ins(JEQ, 3, 0, libc::AF_INET as u32),
    ins(JEQ, 2, 0, libc::AF_INET6 as u32),
    ins(JEQ, 1, 0, libc::AF_NETLINK as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ALLOW),
    ins(LD, 0, 0, 16), // socketpair domain
    ins(JEQ, 0, 3, libc::AF_UNIX as u32),
    ins(LD, 0, 0, 24), // socketpair type (without CLOEXEC/NONBLOCK)
    ins(
        (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
        0,
        0,
        0xf,
    ),
    ins(JEQ, 1, 0, libc::SOCK_STREAM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ins(RET, 0, 0, libc::SECCOMP_RET_ALLOW),
];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn block_unix_sockets() -> io::Result<()> {
    let program = libc::sock_fprog {
        len: FILTER.len() as u16,
        filter: FILTER.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: Called in a child pre_exec hook. Only raw syscalls and static
    // BPF instructions are used here; no locks or allocation after fork.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;

    fn verdict(syscall: u32, domain: u32, socket_type: u32) -> u32 {
        let mut accumulator = 0;
        let mut pc = 0;
        for _ in 0..FILTER.len() {
            let instruction = FILTER[pc];
            if instruction.code == LD {
                accumulator = match instruction.k {
                    0 => syscall,
                    4 => FILTER[1].k, // native architecture
                    16 => domain,
                    24 => socket_type,
                    _ => panic!("invalid BPF load"),
                };
                pc += 1;
            } else if instruction.code == JEQ {
                pc += 1 + if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                } as usize;
            } else if instruction.code == (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16 {
                pc += 1 + if accumulator >= instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                } as usize;
            } else if instruction.code == (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16 {
                accumulator &= instruction.k;
                pc += 1;
            } else if instruction.code == RET {
                return instruction.k;
            } else {
                panic!("invalid BPF instruction");
            }
        }
        panic!("BPF program failed to return");
    }

    #[test]
    fn filter_allows_ordinary_exec_and_ip_but_denies_ipc() {
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        assert_eq!(
            verdict(libc::SYS_execve as u32, 0, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            verdict(libc::SYS_socket as u32, libc::AF_INET as u32, 0),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            verdict(libc::SYS_socket as u32, libc::AF_UNIX as u32, 0),
            denied
        );
        assert_eq!(
            verdict(libc::SYS_socket as u32, libc::AF_VSOCK as u32, 0),
            denied
        );
        assert_eq!(
            verdict(
                libc::SYS_socketpair as u32,
                libc::AF_UNIX as u32,
                libc::SOCK_DGRAM as u32
            ),
            denied
        );
        assert_eq!(
            verdict(
                libc::SYS_socketpair as u32,
                libc::AF_UNIX as u32,
                libc::SOCK_STREAM as u32 | libc::SOCK_CLOEXEC as u32
            ),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(verdict(libc::SYS_io_uring_setup as u32, 0, 0), denied);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn block_unix_sockets() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported seccomp architecture",
    ))
}
