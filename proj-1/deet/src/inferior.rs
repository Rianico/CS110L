use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::mem::size_of;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;

use crate::debugger::BreakPoint;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

const INT_INST: u8 = 0xcc;
const INT_INST_BYTE_SIZE: u8 = 1;
/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
        // TODO: implement me!
        let child = unsafe {
            Command::new(target)
                .pre_exec(|| child_traceme())
                .args(args)
                .spawn()
                .ok()?
        };
        let inferior = Inferior { child };
        match inferior.wait(None) {
            Ok(Status::Stopped(_, _)) => Some(inferior),
            Ok(Status::Exited(exit_code)) => panic!(
                "start debugging child process {} failed, exit code {:?}.",
                inferior.child.id(),
                exit_code
            ),
            Ok(Status::Signaled(signal)) => panic!(
                "start debugging child process {} failed, signal {:?}.",
                inferior.child.id(),
                signal
            ),
            _ => unreachable!(),
        }
    }

    pub fn setup_break_points(&mut self, break_points: &mut HashMap<usize, BreakPoint>) {
        break_points.iter_mut().for_each(|(addr, point)| {
            let origin_byte = self.write_byte(*addr, INT_INST).unwrap();
            point.store_origin_byte(origin_byte);
        });
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    pub fn cont(&self) -> Result<Status, nix::Error> {
        let _ = ptrace::cont(self.pid(), None);
        match self.wait(None) {
            sig_trap_ok @ Ok(Status::Stopped(Signal::SIGTRAP, _)) => {
                println!("Child stopped(signal {}).", Signal::SIGTRAP);
                sig_trap_ok
            }
            stop_ok @ Ok(Status::Stopped(signal, _)) => {
                println!("Child stopped(signal {signal}).");
                stop_ok
            }
            exit_ok @ Ok(Status::Exited(exit_code)) => {
                println!("Child exited (status {})", exit_code);
                exit_ok
            }
            signal_ok @ Ok(Status::Signaled(signal)) => {
                println!("Child process status: {signal}");
                signal_ok
            }
            err @ Err(nix::Error::Sys(Errno::ECHILD)) => {
                println!("No child process");
                err
            }
            _ => unreachable!(),
        }
    }

    pub fn rewind_intr_rip(&self) -> Result<(), nix::Error> {
        let mut usr_regs = ptrace::getregs(self.pid())?;
        usr_regs.rip -= INT_INST_BYTE_SIZE as u64;
        ptrace::setregs(self.pid(), usr_regs)
    }

    pub fn single_step(&self) -> Result<Status, nix::Error> {
        let _ = ptrace::step(self.pid(), None);
        self.wait(None)
    }

    pub fn kill(&self) -> Result<Status, nix::Error> {
        let _ = ptrace::kill(self.pid());
        match self.wait(None) {
            kill_ok @ Ok(Status::Signaled(_)) => {
                println!("Killing running inferior (pid {})", self.pid());
                kill_ok
            }
            v @ _ => v,
        }
    }

    pub fn rip(&self) -> Result<usize, nix::Error> {
        ptrace::getregs(self.pid()).map(|v| v.rip as usize)
    }

    pub fn rbp(&self) -> Result<usize, nix::Error> {
        ptrace::getregs(self.pid()).map(|v| v.rbp as usize)
    }

    pub fn read_mem_content<T: Into<usize>>(&self, addr: T) -> Result<usize, nix::Error> {
        ptrace::read(self.pid(), addr.into() as ptrace::AddressType).map(|v| v as usize)
    }

    fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = addr & (-(size_of::<usize>() as isize) as usize);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }

    pub fn setup_int_inst(&mut self, addr: usize) -> Result<(), nix::Error> {
        let _ = self.write_byte(addr, INT_INST)?;
        Ok(())
    }

    pub fn recover_origin_byte(&mut self, addr: usize, val: u8) -> Result<(), nix::Error> {
        let _ = self.write_byte(addr, val)?;
        Ok(())
    }
}
