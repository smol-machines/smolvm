fn main() {
    // Announce the soname a CUDA 11.x program links against, so the dynamic
    // linker satisfies `libcudart.so.11.0`. Build artifact is libcudart.so;
    // installers stage it as libcudart.so.11.0 (or LD_PRELOAD it).
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libcudart.so.11.0");
    }
}
