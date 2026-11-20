#![allow(clippy::unwrap_used)]
use criterion::*;
use rand_core::TryRng;
use std::hint;

pub fn bench(c: &mut Criterion) {
    let mut rand_generator = hint::black_box(rand::rng());

    let mut packet_length = hint::black_box(vec![0u8; 4]);

    for cipher_name in [super::CHACHA20_POLY1305, super::AES_256_GCM] {
        let cipher = super::CIPHERS.get(&cipher_name).unwrap();

        let mut key = vec![0; cipher.key_len()];
        rand_generator.try_fill_bytes(&mut key).unwrap();
        let mut nonce = vec![0; cipher.nonce_len()];
        rand_generator.try_fill_bytes(&mut nonce).unwrap();

        let mut sk = cipher.make_sealing_key(&key, &nonce, &[], &crate::mac::_NONE);
        let mut ok = cipher.make_opening_key(&key, &nonce, &[], &crate::mac::_NONE);

        let mut group = c.benchmark_group(format!("Cipher: {}", cipher_name.0));
        for size in [100usize, 1000, 10000] {
            let iterations = 10000 / size;

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(format!("Block size: {size}"), |b| {
                b.iter_with_setup(
                    || {
                        let mut in_out = hint::black_box(vec![0u8; size]);
                        rand_generator.try_fill_bytes(&mut in_out).unwrap();
                        rand_generator.try_fill_bytes(&mut packet_length).unwrap();
                        in_out
                    },
                    |mut in_out| {
                        for _ in 0..iterations {
                            let len = in_out.len();
                            let (data, tag) = in_out.split_at_mut(len - sk.tag_len());
                            sk.seal(0, data, tag);
                            ok.open(0, &mut in_out).unwrap();
                        }
                    },
                );
            });
        }
        group.finish();
    }
}
