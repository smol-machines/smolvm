fn main() {
    // The library must announce itself as libcuda.so.1 so the dynamic linker
    // satisfies programs linked against (or dlopen-ing) the real driver's
    // soname. The build artifact is libcuda.so; installers symlink/rename to
    // libcuda.so.1.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libcuda.so.1");
    }
}
