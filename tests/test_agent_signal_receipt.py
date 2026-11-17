"""crates/smolvm-agent/src/INTENT.md: exact signal-handler ordering."""
import json,os,pathlib,subprocess,tempfile,unittest
SOURCE=pathlib.Path(os.environ.get('SIGNAL_SOURCE',str(pathlib.Path(__file__).resolve().parents[1]/'crates/smolvm-agent/src/main.rs')))
def handler(source):
 start=source.index('unsafe extern "C" fn handle_term_signal(');opening=source.index('{',start);end=opening+1;depth=1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]
PRE=r'''#![allow(non_camel_case_types)]
mod libc {
 pub type c_int=i32; pub const SIGTERM:i32=15; pub const SIGINT:i32=2; pub const STDERR_FILENO:i32=2;
 pub unsafe fn write(fd:i32,p:*const std::ffi::c_void,n:usize)->isize {
  use std::io::Write;
  if fd!=2 {return -1;}
  match std::io::stderr().write_all(std::slice::from_raw_parts(p.cast::<u8>(),n)) {Ok(())=>n as isize,Err(_)=>-1}
 }
 pub unsafe fn sync(){eprintln!("{{\"step\":\"sync\"}}");}
 pub unsafe fn _exit(code:i32)->!{std::process::exit(code)}
}
'''
POST=r'''fn main()->Result<(),Box<dyn std::error::Error>> {
 let signal=std::env::args().nth(1).ok_or("signal required")?.parse()?;
 unsafe {handle_term_signal(signal)}; Ok(())
}'''
class Signal(unittest.TestCase):
 def test_exact_handler_before_sync(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'probe.rs').write_text(PRE+handler(SOURCE.read_text())+POST)
   r=subprocess.run(['rustc','--edition=2021','-Adead_code',str(p/'probe.rs'),'-o',str(p/'probe')],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
   for sig in [15,2,99]:
    with self.subTest(signal=sig):
     r=subprocess.run([str(p/'probe'),str(sig)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
     self.assertEqual([json.loads(line) for line in r.stderr.splitlines()],[{'event':'smol_hotfork_agent_signal','signal':sig if sig in [15,2] else 'unexpected'},{'step':'sync'}])
if __name__=='__main__':unittest.main()
