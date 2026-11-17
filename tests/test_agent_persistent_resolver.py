"""Intent: crates/smolvm-agent/src/INTENT.md. Execute extracted production reuse/remount body and DNS policy."""
import os, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parent
SOURCE=pathlib.Path(os.environ.get('RESOLVER_SOURCE',str(ROOT.parent/'crates/smolvm-agent/src/storage.rs')))
def function(src,name):
 start=src.index('fn '+name+'(');brace=src.index('{',start);depth=1;i=brace+1
 while depth:
  depth+=(src[i]=='{')-(src[i]=='}');i+=1
 return src[start:i]
PRE='''use std::path::{Path,PathBuf}; use std::io::Write;
type Result<T> = std::io::Result<T>;
struct StorageError; impl StorageError {fn new(s:String)->std::io::Error {std::io::Error::other(s)}}
macro_rules! info {($($x:tt)*)=>{()};} macro_rules! warn {($($x:tt)*)=>{eprintln!("resolver warning")};}
mod guest_env {pub const DNS:&str="SMOLVM_NETWORK_DNS";pub const DNS_FILTER:&str="SMOLVM_DNS_FILTER";}
mod paths {pub fn main_container_id_path(_: &str)->std::path::PathBuf {std::path::PathBuf::from("/absent-fixture-container")}}
struct CrunCommand; impl CrunCommand {fn delete(_: &str,_:bool)->Self{Self} fn output(&self)->std::io::Result<()>{Ok(())}}
fn is_mountpoint(_: &Path)->bool {std::env::var("CASE_MODE").as_deref()==Ok("reuse")}
fn mounted_overlay_is_healthy(_: &Path)->bool{true} fn detach_mount(_: &Path){}
struct OverlayInfo;
struct OverlaySetup {upper_path:PathBuf,work_path:PathBuf,merged_path:PathBuf,workload_id:String}
impl OverlaySetup {
 fn create_bundle(&self)->Result<()> {Ok(())}
 fn into_overlay_info(self)->OverlayInfo{OverlayInfo}
 fn verify_layers(&self,_:&[String])->Result<()> {Ok(())}
 fn mount(&self,_:&[String])->Result<()> {std::fs::copy(self.upper_path.join("etc/resolv.conf"),self.merged_path.join("etc/resolv.conf"))?;Ok(())}
 fn verify_mount(&self)->usize{0}
 fn execute(self,_:Vec<String>)->Result<OverlayInfo>{Err(std::io::Error::other("unexpected fresh overlay"))}
'''
POST='''fn main()->Result<()> {let root=PathBuf::from(std::env::args().nth(1).ok_or_else(||std::io::Error::other("root"))?);let s=OverlaySetup{upper_path:root.join("upper"),work_path:root.join("work"),merged_path:root.join("merged"),workload_id:"fixture".into()};s.execute_or_remount(vec![])?;Ok(())}'''
class Resolver(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.bin=pathlib.Path(cls.temp.name)/'probe';src=SOURCE.read_text()
  helper=function(src,'refresh_overlay_resolver') if 'fn refresh_overlay_resolver(' in src else ''
  rust=PRE+function(src,'execute_or_remount')+'}\n'+function(src,'overlay_resolv_conf_contents')+'\n'+helper+'\n'+POST
  p=pathlib.Path(cls.temp.name)/'probe.rs';p.write_text(rust)
  subprocess.run(['rustc','--edition','2021','-A','unused',str(p),'-o',str(cls.bin)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def run_case(self,mode,dns=None,filtered=False,broken=False):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for sub in ['upper','merged']:
    p=root/sub/'etc';p.mkdir(parents=True);(p/'resolv.conf').write_text('nameserver 100.96.0.1\n');(p/'unrelated').write_bytes(b'preserve-me');(p/'hosts').write_text('custom-hosts')
   if broken:
    p=root/('merged' if mode=='reuse' else 'upper')/'etc/resolv.conf';p.unlink();p.mkdir()
   env={k:v for k,v in os.environ.items() if k not in ['SMOLVM_NETWORK_DNS','SMOLVM_DNS_FILTER']};env['CASE_MODE']=mode
   if dns:env['SMOLVM_NETWORK_DNS']=dns
   if filtered:env['SMOLVM_DNS_FILTER']='1'
   result=subprocess.run([str(self.bin),d],env=env,capture_output=True,text=True)
   if broken:self.assertNotEqual(result.returncode,0);self.assertIn('resolver warning',result.stderr);return
   self.assertEqual(result.returncode,0,result.stderr)
   expected='nameserver 127.0.0.1\n' if filtered else ('nameserver '+dns+'\n' if dns else 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n')
   self.assertEqual((root/'merged/etc/resolv.conf').read_text(),expected)
   for sub in ['upper','merged']:
    self.assertEqual((root/sub/'etc/unrelated').read_bytes(),b'preserve-me');self.assertEqual((root/sub/'etc/hosts').read_text(),'custom-hosts')
 def test_virtio_to_tsi(self):
  for mode in ['reuse','remount']:
   with self.subTest(mode=mode):self.run_case(mode)
 def test_explicit_override(self):
  for mode in ['reuse','remount']:
   with self.subTest(mode=mode):self.run_case(mode,'9.9.9.9')
 def test_filter_precedence(self):
  for mode in ['reuse','remount']:
   with self.subTest(mode=mode):self.run_case(mode,'9.9.9.9',True)
 def test_write_failure_loud(self):
  for mode in ['reuse','remount']:
   with self.subTest(mode=mode):self.run_case(mode,broken=True)
if __name__=='__main__':unittest.main()
