"""Intent: plans/2026-09-19-machine-exec-record-errors.md. No VM or Cargo build."""
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
SOURCE=pathlib.Path(os.environ.get('EXEC_SOURCE',str(pathlib.Path(__file__).resolve().parents[1]/'src/cli/machine.rs')))
class Route(unittest.TestCase):
    def test_database_errors_are_not_bare_vm_routes(self):
        source=SOURCE.read_text();start=source.index('impl ExecCmd {');tail=source[start:]
        expression=re.search(r'let record = smolvm::db::SmolvmDb::open\(\)[\s\S]*?;',tail).group(0)
        rust='''#[derive(Clone,Copy)] enum Case { OpenError, GetError, Image, Bare, Absent }
thread_local! { static CASE: std::cell::Cell<Case> = const {std::cell::Cell::new(Case::Image)}; }
struct Record { image: Option<&'static str> }
mod smolvm { pub mod db {
 pub struct SmolvmDb;
 impl SmolvmDb {
  pub fn open()->Result<Self,&'static str> { super::super::CASE.with(|c| match c.get() {super::super::Case::OpenError=>Err("database open failed"),_=>Ok(Self)}) }
  pub fn get_vm(&self,_name:&str)->Result<Option<super::super::Record>,&'static str> {super::super::CASE.with(|c|match c.get(){
   super::super::Case::GetError=>Err("database read failed"),
   super::super::Case::Image=>Ok(Some(super::super::Record{image:Some("nixos")})),
   super::super::Case::Bare=>Ok(Some(super::super::Record{image:None})),
   super::super::Case::Absent=>Ok(None),
   super::super::Case::OpenError=>Err("open should have stopped execution"),
  })}
 }
}}
fn route(case:Case)->Result<Option<&'static str>,&'static str>{
 CASE.with(|c|c.set(case));let name="owned-machine";
''' + expression + '''
 Ok(record.and_then(|r|r.image))
}
#[test] fn open_error_stops_route(){assert_eq!(route(Case::OpenError),Err("database open failed"));}
#[test] fn get_error_stops_route(){assert_eq!(route(Case::GetError),Err("database read failed"));}
#[test] fn image_remains_container(){assert_eq!(route(Case::Image),Ok(Some("nixos")));}
#[test] fn valid_bare_remains_bare(){assert_eq!(route(Case::Bare),Ok(None));}
#[test] fn absent_record_semantics_unchanged(){assert_eq!(route(Case::Absent),Ok(None));}
'''
        with tempfile.TemporaryDirectory(prefix='smol-exec-record-') as td:
            p=pathlib.Path(td);(p/'route.rs').write_text(rust)
            subprocess.run(['rustc','--edition=2021','-Dwarnings','--test',str(p/'route.rs'),'-o',str(p/'route')],check=True,capture_output=True,text=True)
            result=subprocess.run([str(p/'route')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
if __name__=='__main__':unittest.main()
