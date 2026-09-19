"""Actual CLI seam; intent: plans/2026-09-19-live-unreachable-diagnostic.md."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class Diagnostic(unittest.TestCase):
 def test_actual_connection_failure_diagnostics(self):
  source=(ROOT/'src/cli/vm_common.rs').read_text();start=source.index('pub fn ensure_running_and_connect(');end=source.index('/// CLI wrapper around',start);function=source[start:end]
  harness=r'''
extern crate self as smolvm;
use std::path::Path;
#[derive(Debug)] pub struct Error(String);
pub type Result<T>=std::result::Result<T,Error>;
impl Error {fn agent(_: &str,s:impl ToString)->Self{Self(s.to_string())} fn vm_not_found(s:&str)->Self{Self(format!("not found {s}"))}}
#[derive(Clone,Copy,PartialEq)] enum RecordState {Frozen,Running,Stopped}
#[derive(Clone)] struct Record{state:RecordState,live:bool,pid:Option<u32>}
impl Record{fn is_process_alive(&self)->bool{self.live}}
#[derive(Default)] struct Fixture{record:Option<Record>,connected:bool,db_error:bool,marks:usize,connections:usize}
thread_local!{static F:std::cell::RefCell<Fixture>=Default::default();}
#[derive(Debug)] pub struct AgentManager;
impl AgentManager{fn try_connect_existing(&self)->Option<()>{F.with(|f|f.borrow().connected.then_some(()))} fn vsock_socket(&self)->&Path{Path::new("unused")}}
fn get_vm_manager(_: &Option<String>)->Result<AgentManager>{Ok(AgentManager)}
fn vm_label(n:&Option<String>)->String{match n {Some(n)=>n.clone(),None=>"default".into()}}
struct SmolvmDb;
impl SmolvmDb{fn open()->Result<Self>{F.with(|f|if f.borrow().db_error{Err(Error("original database failure".into()))}else{Ok(Self)})} fn get_vm(&self,_:&str)->Result<Option<Record>>{F.with(|f|Ok(f.borrow().record.clone()))}}
fn mark_unreachable_if_zombie(_: &str){F.with(|f|f.borrow_mut().marks+=1);}
pub mod agent{#[derive(Debug)] pub struct AgentClient;impl AgentClient{pub fn connect_with_retry(_: &std::path::Path)->crate::Result<Self>{crate::F.with(|f|f.borrow_mut().connections+=1);Ok(Self)}} pub mod state_probe{pub(crate) fn resolve_state(_: &str,r:&crate::Record)->crate::RecordState{r.state}}}
FUNCTION
fn message(name:Option<String>)->String{match ensure_running_and_connect(&name){Err(e)=>e.0,Ok(_)=>"connected".into()}}
fn fixture(state:RecordState,live:bool){F.with(|f|*f.borrow_mut()=Fixture{record:Some(Record{state,live,pid:Some(62942)}),..Fixture::default()});}
fn main(){
 fixture(RecordState::Running,true);let live=message(Some("heavy".into()));assert!(live.contains("unresponsive"),"{live}");assert!(!live.contains("Use '")&&!live.contains("not running"),"{live}");
 fixture(RecordState::Running,true);F.with(|f|f.borrow_mut().db_error=true);assert_eq!(message(Some("heavy".into())),"original database failure");
 fixture(RecordState::Running,true);F.with(|f|f.borrow_mut().record=None);assert!(message(Some("missing".into())).contains("not found"));
 fixture(RecordState::Stopped,false);let stopped=message(Some("heavy".into()));assert!(stopped.contains("smolvm machine start --name heavy"),"{stopped}");
 fixture(RecordState::Frozen,true);let frozen=message(Some("heavy".into()));assert!(frozen.contains("frozen"),"{frozen}");
 fixture(RecordState::Running,true);let default=message(None);assert!(default.contains("unresponsive")&&!default.contains("Use '"),"{default}");
 fixture(RecordState::Running,true);F.with(|f|f.borrow_mut().connected=true);assert_eq!(message(None),"connected");F.with(|f|assert_eq!(f.borrow().connections,1));
}
'''.replace('FUNCTION',function)
  with tempfile.TemporaryDirectory(prefix='smol-unreachable-') as d:
   p=Path(d);(p/'test.rs').write_text(harness);subprocess.run(['rustc','--edition=2021','-D','warnings','-A','dead_code',str(p/'test.rs'),'-o',str(p/'test')],check=True);subprocess.run([str(p/'test')],check=True,timeout=5)
if __name__=='__main__':unittest.main()
