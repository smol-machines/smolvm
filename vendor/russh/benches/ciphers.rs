#[cfg(feature = "_bench")]
criterion::criterion_group!(benches, russh::cipher::benchmark::bench);
#[cfg(feature = "_bench")]
criterion::criterion_main!(benches);

#[cfg(not(feature = "_bench"))]
fn main() {}
