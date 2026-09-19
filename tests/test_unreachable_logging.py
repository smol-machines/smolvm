"""Actual reconciliation logging; plans/2026-09-19-live-unreachable-diagnostic.md."""
from pathlib import Path
import subprocess,tempfile,unittest
class Logging(unittest.TestCase):
 def test_actual_reconciliation_logs(self):
  s=(Path(__file__).resolve().parents[1]/'src/cli/vm_common.rs').read_text();s=s[s.index('fn mark_unreachable_if_zombie('):s.index('/// Print command output and exit')]
  harness=r'''
extern crate self as smolvm;
extern crate self as tracing;
#[macro_export] macro_rules! warn { (machine = %$name:expr, error = %$error:expr, $msg:literal $(,)?) => {logs(format!("warn {} {} {}",$name,$error,$msg))}; (machine = %$name:expr, $msg:literal $(,)?) => {logs(format!("warn {} {}",$name,$msg))}; }
#[macro_export] macro_rules! debug { (machine = %$name:expr, $msg:literal $(,)?) => {logs(format!("debug {} {}",$name,$msg))}; }
thread_local!{static LOG:std::cell::RefCell<Vec<String>>=Default::default();static MODE:std::cell::Cell<u8>=const{std::cell::Cell::new(0)};}
fn logs(s:String){LOG.with(|l|l.borrow_mut().push(s));}
#[derive(PartialEq)] enum RecordState{Running,Unreachable,Stopped}
struct Record{state:RecordState}
impl Record{fn is_process_alive(&self)->bool{MODE.with(|m|m.get()!=5)}}
struct SmolvmConfig{record:Record}
impl SmolvmConfig{fn load()->Result<Self,&'static str>{if MODE.with(|m|m.get()==1){Err("load failed")}else{Ok(Self{record:Record{state:if MODE.with(|m|m.get()==4){RecordState::Stopped}else{RecordState::Running}}})}}fn get_vm(&self,_:&str)->Option<&Record>{if MODE.with(|m|m.get()==2){None}else{Some(&self.record)}}fn update_vm(&mut self,_:&str,f:impl FnOnce(&mut Record))->Option<Result<(),&'static str>>{if MODE.with(|m|m.get()==7){None}else if MODE.with(|m|m.get()==3){Some(Err("update failed"))}else{f(&mut self.record);Some(Ok(()))}}}
pub mod agent{pub mod state_probe{pub(crate) fn is_frozen_fork_base(_:&str,_:&crate::Record)->bool{crate::MODE.with(|m|m.get()==6)}}}
FUNCTION
fn main(){for mode in 0..8{MODE.with(|m|m.set(mode));LOG.with(|l|l.borrow_mut().clear());mark_unreachable_if_zombie("heavy");let logs=LOG.with(|l|l.borrow().join("\n"));match mode{0=>assert!(logs.contains("debug heavy marked"),"{logs}"),1=>assert!(logs.contains("warn heavy load failed"),"{logs}"),2|7=>assert!(logs.contains("warn heavy")&&logs.contains("missing"),"{logs}"),3=>assert!(logs.contains("warn heavy update failed")&&!logs.contains("debug"),"{logs}"),_=>assert!(logs.is_empty(),"{logs}")}}}
'''.replace('FUNCTION',s)
  with tempfile.TemporaryDirectory(prefix='smol-log-') as d:
   p=Path(d);(p/'test.rs').write_text(harness);subprocess.run(['rustc','--edition=2021','-D','warnings',str(p/'test.rs'),'-o',str(p/'test')],check=True);subprocess.run([str(p/'test')],check=True,timeout=5)
if __name__=='__main__':unittest.main()
