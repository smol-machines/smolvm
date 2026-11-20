# Run with: python3 tests/bridge_udp/run.py /path/to/config.json
# Config keys: engine, docker, rootfs, lib, probe, out (absolute paths).
# Build guest.rs for the guest architecture with rustc --edition=2021
# --target <arch>-unknown-linux-musl -C linker=rust-lld -o /path/to/probe.
# Requires KVM or an HVF-entitled engine and the ordinary guest rootfs and runtime.
# Uses only a private engine socket, Docker config, and temporary state directory.
from concurrent.futures import ThreadPoolExecutor
import hashlib, json, os, pathlib, socket, subprocess, sys, tarfile, tempfile, threading, time, traceback

cfg=json.loads(pathlib.Path(sys.argv[1]).read_text())
out=pathlib.Path(cfg['out']);out.mkdir(parents=True,exist_ok=True)
engine=pathlib.Path(cfg['engine']);docker=cfg['docker'];image='smol-bridge-udp-probe:local'
state=pathlib.Path(tempfile.mkdtemp(prefix='smol-bridge-udp-',dir='/tmp'))
sock=state/'api.sock'
env={k:v for k,v in os.environ.items() if not k.startswith(('SMOLVM_','DOCKER_','BUILDX_','DYLD_','LD_LIBRARY_'))}
env.update(SMOLVM_DATA_DIR=str(state/'data'),SMOLVM_CONFIG=str(state/'config.toml'),SMOLVM_AGENT_ROOTFS=cfg['rootfs'],SMOLVM_LIB_DIR=cfg['lib'],LD_LIBRARY_PATH=cfg['lib'],DYLD_LIBRARY_PATH=cfg['lib'],DOCKER_CONFIG=str(state/'docker'))
result={'phase':'running','pid':os.getpid(),'state':str(state),'cases':[],'commands':[],'cleanup_errors':[],
        'hashes':{k:hashlib.sha256(pathlib.Path(cfg[k]).read_bytes()).hexdigest() for k in ['engine','probe']}}
containers=[];processes=[]
def save(): (out/'result.json').write_text(json.dumps(result,indent=2))
def run(args,expected=0):
    p=subprocess.run(list(map(str,args)),env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
    record={'args':list(map(str,args)),'exit':p.returncode,'stdout':p.stdout.decode(errors='replace')[-4000:],'stderr':p.stderr.decode(errors='replace')[-4000:]}
    result['commands'].append(record);save()
    if expected is not None: assert p.returncode==expected,record
    return p
def d(*args,expected=0):return run([docker,'-H','unix://'+str(sock),*args],expected)
def check(name):result['cases'].append({'name':name,'passed':True});save();print(name,'PASS',flush=True)
def create(mode,*args,ip='127.0.0.1',ports=None):
    identifier=d('create','--network',mode,*args,image,'serve',ip,*(ports or [])).stdout.decode().strip()
    containers.append(identifier);return identifier
def ready(identifier, previous=0):
    start=time.monotonic()
    while time.monotonic()-start<15:
        p=d('logs',identifier,expected=None)
        lines=[line for line in p.stdout.decode().splitlines() if line.startswith('READY ')]
        if len(lines)>previous:return lines[-1].split()[1:]
        time.sleep(.1)
    raise RuntimeError('container did not announce sockets')
def address(value):
    ip,port=value.rsplit(':',1);return ip.strip('[]'),int(port)
def host_tcp(value):
    with socket.create_connection(address(value),timeout=3) as s:
        s.sendall(b'PING');assert s.recv(4)==b'PONG'
def host_udp(value,sizes=(0,1,4096,65507)):
    ip,port=address(value);family=socket.AF_INET6 if ':' in ip else socket.AF_INET
    with socket.socket(family,socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        # macOS defaults its host UDP send buffer below the largest legal datagram.
        s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,256*1024)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
        for size in sizes:
            data=bytes([17])*size;s.sendto(data,(ip,port))
            try:got,peer=s.recvfrom(65535)
            except socket.timeout:raise AssertionError('UDP echo timed out: address='+value+' size='+str(size))
            assert got==data and peer[:2]==(ip,port)
def no_owned_port(value):
    ip,port=address(value);family=socket.AF_INET6 if ':' in ip else socket.AF_INET
    with socket.socket(family,socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind((ip,port))
try:
    save()
    log=(out/'server.log').open('w')
    server=subprocess.Popen([str(engine),'engine','serve','--root',str(state/'engine'),'--socket',str(sock)],env=env,stdout=log,stderr=log);processes.append(server)
    deadline=time.monotonic()+30
    while not sock.exists():
        assert server.poll() is None and time.monotonic()<deadline;time.sleep(.05)
    hold=subprocess.Popen([docker,'-H','unix://'+str(sock),'events'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(hold)
    archive=state/'image.tar'
    with tarfile.open(archive,'w') as tar:
        tar.add(cfg['probe'],arcname='probe')
        for path in ['etc','tmp','proc','sys','dev']:
            member=tarfile.TarInfo(path);member.type=tarfile.DIRTYPE;member.mode=0o755;tar.addfile(member)
    d('import','-c','ENTRYPOINT ["/probe"]',str(archive),image)
    bridge=create('bridge','-p','127.0.0.1::8080','-p','127.0.0.1::8081/udp',ip='0.0.0.0',ports=['8080','8081'])
    d('start',bridge);ready(bridge)
    bindings=json.loads(d('inspect',bridge).stdout)[0]['NetworkSettings']['Ports']
    host_tcp('127.0.0.1:'+bindings['8080/tcp'][0]['HostPort'])
    bridge_udp='127.0.0.1:'+bindings['8081/udp'][0]['HostPort']
    host_udp(bridge_udp)
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending=[pool.submit(host_udp,bridge_udp,(size,)) for size in (4096,8192,65507)]
        for future in pending:future.result()
    check('bridge TCP and full-size IPv4 UDP work, including concurrent fragmented datagrams')
    # Use the host's routed address: bridge egress must keep denying loopback.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1',9));host_ip=route.getsockname()[0]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as echo:
        echo.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,256*1024)
        echo.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
        echo.bind((host_ip,0));echo.settimeout(.1);stopping=threading.Event()
        def echo_packets():
            while not stopping.is_set():
                try:data,peer=echo.recvfrom(65535)
                except socket.timeout:continue
                echo.sendto(data,peer)
        worker=threading.Thread(target=echo_packets);worker.start()
        try:d('run','--rm','--network','bridge',image,'udp',host_ip+':'+str(echo.getsockname()[1]))
        finally:stopping.set();worker.join(timeout=3)
        assert not worker.is_alive()
    check('bridge outbound UDP reassembles requests and fragments full-size replies')
    result['phase']='passed'
except BaseException:
    result['phase']='failed';result['error']=traceback.format_exc();print(result['error'],flush=True)
finally:
    for identifier in reversed(containers):
        try:d('rm','-f',identifier)
        except BaseException as e:result['cleanup_errors'].append(str(e))
    try:d('image','rm',image)
    except BaseException as e:result['cleanup_errors'].append(str(e))
    for p in reversed(processes):
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    save()
sys.exit(0 if result['phase']=='passed' and not result['cleanup_errors'] else 1)
