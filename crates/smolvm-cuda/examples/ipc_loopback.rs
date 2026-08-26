//! Live CUDA IPC validation across two independent RPC sessions.
//!
//! Each client owns a different GPU primary context, matching two local NCCL
//! ranks. The producer exports memory and an interprocess event; the consumer
//! opens both through the daemon-local capability registry and verifies data.

use smolvm_cuda::client::Client;
use smolvm_cuda::host::{serve, Backend, GpuBackend};
use std::net::{TcpListener, TcpStream};

const COPY_PTX: &str = r#".version 7.0
.target sm_52
.address_size 64
.visible .entry copy_peer(.param .u64 src, .param .u64 dst, .param .u32 n)
{ .reg .pred %p; .reg .b32 %r<5>; .reg .b64 %rd<8>;
 ld.param.u64 %rd1,[src]; ld.param.u64 %rd2,[dst]; ld.param.u32 %r1,[n];
 mov.u32 %r2,%ntid.x; mov.u32 %r3,%ctaid.x; mov.u32 %r4,%tid.x;
 mad.lo.s32 %r2,%r3,%r2,%r4; setp.ge.u32 %p,%r2,%r1; @%p bra DONE;
 cvta.to.global.u64 %rd3,%rd1; cvta.to.global.u64 %rd4,%rd2;
 mul.wide.u32 %rd5,%r2,4; add.s64 %rd6,%rd3,%rd5; add.s64 %rd7,%rd4,%rd5;
 ld.global.u32 %r3,[%rd6]; st.global.u32 [%rd7],%r3;
DONE: ret; }
"#;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            workers.push(std::thread::spawn(move || {
                let mut backend: Box<dyn Backend> =
                    Box::new(GpuBackend::load().expect("load CUDA driver"));
                serve(stream, backend.as_mut()).expect("serve client");
            }));
        }
        for worker in workers {
            worker.join().expect("join server worker");
        }
    });

    let mut producer = Client::new(TcpStream::connect(addr).expect("connect producer"));
    producer.init(0).expect("initialize producer");
    let count = producer.device_get_count().expect("device count");
    if count < 2 {
        eprintln!("ipc_loopback requires at least two GPUs");
        std::process::exit(2);
    }
    producer
        .primary_ctx_retain(0)
        .expect("retain producer context");

    let mut consumer = Client::new(TcpStream::connect(addr).expect("connect consumer"));
    consumer.init(0).expect("initialize consumer");
    let consumer_ctx1 = consumer
        .primary_ctx_retain(1)
        .expect("retain consumer context");

    let source: Vec<u32> = (0..1024).map(|value| value ^ 0x5a5a_5a5a).collect();
    let source_bytes = unsafe {
        std::slice::from_raw_parts(
            source.as_ptr().cast::<u8>(),
            source.len() * std::mem::size_of::<u32>(),
        )
    };
    let dptr = producer
        .mem_alloc(source_bytes.len() as u64)
        .expect("allocate producer memory");
    producer
        .memcpy_htod(dptr, source_bytes, 0)
        .expect("upload producer memory");

    let event = producer.event_create(0x6).expect("create IPC event");
    producer.event_record(event, 0).expect("record IPC event");
    let memory_token = producer
        .ipc_get_mem_handle(dptr)
        .expect("export IPC memory");
    let event_token = producer
        .ipc_get_event_handle(event)
        .expect("export IPC event");

    // CUDA IPC events are device-local: validate their cross-session ABI in a
    // device-0 context, then switch back to device 1 for the peer memory map.
    consumer
        .primary_ctx_retain(0)
        .expect("retain event consumer context");
    let imported_event = consumer
        .ipc_open_event_handle(event_token)
        .expect("open IPC event");
    consumer
        .event_synchronize(imported_event)
        .expect("wait imported event");
    consumer
        .event_destroy(imported_event)
        .expect("destroy imported event");
    consumer
        .ctx_set_current(consumer_ctx1)
        .expect("restore memory consumer context");
    consumer.primary_ctx_release(0).ok();
    let imported = consumer
        .ipc_open_mem_handle(memory_token, 1)
        .expect("open IPC memory");
    let copied = consumer
        .memcpy_dtoh(imported, source_bytes.len() as u64, 0)
        .expect("read imported memory");
    assert_eq!(copied, source_bytes);

    // A host copy can use explicit peer-copy machinery even if peer global
    // loads are broken. NCCL kernels dereference imported pointers directly,
    // so validate that stronger contract as well.
    let module = consumer
        .module_load_data(COPY_PTX.as_bytes())
        .expect("load peer-copy module");
    let function = consumer
        .module_get_function(module, "copy_peer")
        .expect("resolve peer-copy kernel");
    let output = consumer
        .mem_alloc(source_bytes.len() as u64)
        .expect("allocate consumer output");
    consumer
        .launch_kernel(
            function,
            [4, 1, 1],
            [256, 1, 1],
            0,
            0,
            &[
                imported.to_le_bytes().to_vec(),
                output.to_le_bytes().to_vec(),
                (source.len() as u32).to_le_bytes().to_vec(),
            ],
        )
        .expect("launch peer-copy kernel");
    consumer.ctx_synchronize().expect("sync peer-copy kernel");
    let kernel_copied = consumer
        .memcpy_dtoh(output, source_bytes.len() as u64, 0)
        .expect("read peer-copy output");
    assert_eq!(kernel_copied, source_bytes);
    consumer.mem_free(output).ok();
    consumer.module_unload(module).ok();

    consumer
        .ipc_close_mem_handle(imported)
        .expect("close IPC memory");
    consumer.primary_ctx_release(1).ok();
    drop(consumer);

    producer.event_destroy(event).ok();
    producer.mem_free(dptr).ok();
    producer.primary_ctx_release(0).ok();
    drop(producer);
    server.join().expect("join server");
    println!("IPC-MULTI-GPU-OK: cross-session memory and event sharing verified");
}
