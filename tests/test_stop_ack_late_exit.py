"""Real manager stop seam; spec: plans/2026-09-19-stop-ack-late-exit.md."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class StopRace(unittest.TestCase):
    def test_existing_waiter_observes_exit_without_signal(self):
        source = (ROOT / 'src/process.rs').read_text()
        start = source.index('pub(crate) fn poll_for_exit(')
        end = source.index('/// Result of a fork operation.', start)
        waiter = source[start:end]
        harness = r'''use std::time::{Duration,Instant};
use std::process::{Command,Stdio,Child};
type Pid=i32;
const UNKNOWN_EXIT_CODE:i32=-1;
const FAST_POLL_COUNT:u32=10;
const FAST_POLL_INTERVAL:Duration=Duration::from_millis(10);
thread_local! { static CHILD: std::cell::RefCell<Option<Child>>=const {std::cell::RefCell::new(None)}; }
fn try_wait(_:Pid)->Option<i32> { CHILD.with(|c| match c.borrow_mut().as_mut() {Some(c)=>match c.try_wait() {Ok(Some(s))=>s.code(),Ok(None)=>None,Err(e)=>panic!("wait failed: {e}")},None=>None}) }
fn is_alive(pid:Pid)->bool {try_wait(pid).is_none()}
WAITER
fn main()->std::io::Result<()> {
 let mut child=Command::new("/bin/cat").stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
 let input=child.stdin.take();let pid=child.id() as i32;
 CHILD.with(|c|*c.borrow_mut()=Some(child));
 // An open pipe keeps the child live; the existing waiter must time out.
 assert!(poll_for_exit(pid,Duration::from_millis(1)).is_none());
 // EOF, not a signal or another stop request, releases the real child.
 drop(input);
 assert_eq!(poll_for_exit(pid,Duration::from_secs(2)),Some(0));
 CHILD.with(|c| match c.borrow_mut().take() {Some(mut c)=>c.wait().map(|_|()),None=>Ok(())})?;
 Ok(())
}
'''.replace('WAITER', waiter)
        with tempfile.TemporaryDirectory(prefix='smol-stop-wait-') as directory:
            p = pathlib.Path(directory)
            (p/'test.rs').write_text(harness)
            subprocess.run(['rustc','--edition=2021','-D','warnings',str(p/'test.rs'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True,timeout=5)

    def test_real_stop_seam(self):
        source = (ROOT / 'src/agent/manager.rs').read_text()
        start = source.index('    fn stop_vm_process(\n')
        end = source.index('    /// Remove PID file', start)
        method = source[start:end]
        harness = r'''
extern crate self as tracing;
#[macro_export] macro_rules! debug { ($($t:tt)*) => {}; }
#[macro_export] macro_rules! warn { ($($t:tt)*) => {}; }
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)] struct Error(String);
impl Error { fn agent(_: &str, message: impl ToString) -> Self { Self(message.to_string()) } }
impl std::fmt::Display for Error { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f,"{}",self.0) } }
#[derive(Default)] struct State { alive: bool, identity: bool, late: bool, ack: bool, signals: usize, waits: usize, handshakes: usize, rebound: bool }
thread_local! { static STATE: std::cell::RefCell<State> = Default::default(); }
struct AgentClient;
impl AgentClient {
 fn connect_with_short_timeout(_: &std::path::Path) -> Result<Self> { Ok(Self) }
 fn shutdown(&mut self) -> Result<()> { STATE.with(|s| { let mut s=s.borrow_mut(); s.handshakes+=1; if s.ack { Ok(()) } else { Err(Error("original acknowledgment EOF".into())) } }) }
}
mod process {
 use super::*;
 pub type Pid = i32;
 pub const VM_SIGKILL_TIMEOUT: Duration = Duration::from_secs(3);
 pub fn is_alive(_: Pid) -> bool { STATE.with(|s| s.borrow().alive) }
 pub fn is_our_process_strict(_: Pid, start: Option<u64>) -> bool { STATE.with(|s| s.borrow().identity && start==Some(42)) }
 pub fn cmdline_contains(_: Pid, _: &str) -> bool { false }
 pub fn poll_for_exit(_: Pid, timeout: Duration) -> Option<i32> { assert_eq!(timeout, AGENT_STOP_TIMEOUT); STATE.with(|s| { let mut s=s.borrow_mut(); s.waits+=1; if s.late { s.alive=s.rebound; Some(0) } else { None } }) }
 pub fn stop_vm_process(_: Pid, _: Duration, _: Duration) -> Result<()> { STATE.with(|s| {let mut s=s.borrow_mut();s.signals+=1;s.alive=false;}); Ok(()) }
}
const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(2);
mod manager {
 use super::*;
 pub struct Manager { pub vsock_socket: std::path::PathBuf }
 impl Manager {
 fn boot_config_path(&self) -> std::path::PathBuf { self.vsock_socket.clone() }
METHOD
 pub fn exercise(&self, paused: bool, start: Option<u64>) -> Result<()> { self.stop_vm_process(7,start,paused) }
 }
}
fn main() {
 let m=manager::Manager {vsock_socket:"/isolated/socket".into()};
 // First observation alive; bounded existing waiter observes exit, with no signal.
 STATE.with(|s| *s.borrow_mut()=State {alive:true, identity:true, late:true,..Default::default()});
 assert!(m.exercise(false,Some(42)).is_ok(), "late exit should reconcile");
 STATE.with(|s| {let s=s.borrow();assert_eq!(s.waits,1);assert_eq!(s.signals,0);assert_eq!(s.handshakes,1);});
 for (identity,start,late,rebound) in [(true,Some(42),false,false),(false,Some(42),true,false),(true,None,true,false),(true,Some(42),true,true)] {
  STATE.with(|s| *s.borrow_mut()=State {alive:true,identity,late,rebound,..Default::default()});
  let result=m.exercise(false,start); assert!(result.is_err());
  assert!(result.err().is_some_and(|e|e.0.contains("original acknowledgment EOF")));
  STATE.with(|s| assert_eq!(s.borrow().signals,0));
 }
 STATE.with(|s| *s.borrow_mut()=State::default());
 assert!(m.exercise(false,None).is_ok());
 STATE.with(|s| assert_eq!(s.borrow().signals,0));
 // Successful acknowledgment and existing paused guest behavior stay intact.
 for paused in [false,true] {
  STATE.with(|s| *s.borrow_mut()=State {alive:true,identity:true,ack:!paused,..Default::default()});
  assert!(m.exercise(paused,Some(42)).is_ok());
  STATE.with(|s| {let s=s.borrow();assert_eq!(s.signals,1);assert_eq!(s.waits,0);assert_eq!(s.handshakes,usize::from(!paused));});
 }
}
'''.replace('METHOD', method)
        with tempfile.TemporaryDirectory(prefix='smol-stop-test-') as directory:
            p = pathlib.Path(directory)
            (p/'test.rs').write_text(harness)
            subprocess.run(['rustc','--edition=2021','-A','unused_variables','-A','dead_code',str(p/'test.rs'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__ == '__main__':
    unittest.main()
