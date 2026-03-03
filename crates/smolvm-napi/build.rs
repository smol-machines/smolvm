//! Build script for smolvm-napi.
//!
//! Calls napi_build::setup() for NAPI-RS and replicates the libkrun
//! discovery logic from smolvm's build.rs so the .node binary can
//! dynamically link libkrun at load time.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "linux")]
fn is_lfs_pointer(path: &Path) -> bool {
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > 500 {
            return false;
        }
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        return content.starts_with("version https://git-lfs.github.com/spec/v1");
    }
    false
}

fn link_krun() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-arg=-Wl,-weak-lkrun");
    #[cfg(not(target_os = "macos"))]
    println!("cargo:rustc-link-lib=krun");
}

fn main() {
    napi_build::setup();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    link_libkrun();
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn link_libkrun() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_STATIC");
    println!("cargo:rerun-if-env-changed=LIBKRUN_BUNDLE");
    println!("cargo:rerun-if-env-changed=LIBKRUN_DIR");

    // Option 1: Bundle libraries with the binary
    if let Ok(bundle_path) = std::env::var("LIBKRUN_BUNDLE") {
        println!("cargo:rustc-link-search=native={}", bundle_path);
        link_krun();

        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path");
            println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");

            let lib_path = std::path::Path::new(&bundle_path).join("libkrun.dylib");
            if lib_path.exists() {
                let _ = Command::new("install_name_tool")
                    .args(["-id", "@rpath/libkrun.dylib", lib_path.to_str().unwrap()])
                    .status();
                let _ = Command::new("codesign")
                    .args(["--force", "--sign", "-", lib_path.to_str().unwrap()])
                    .status();
            }
        }
        #[cfg(target_os = "linux")]
        {
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
        }
        return;
    }

    // Option 2: Static linking
    if let Ok(static_path) = std::env::var("LIBKRUN_STATIC") {
        let path = std::path::Path::new(&static_path);
        if path.is_dir() {
            println!("cargo:rustc-link-search=native={}", static_path);
        } else if path.is_file() {
            if let Some(dir) = path.parent() {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        } else {
            panic!("LIBKRUN_STATIC path does not exist: {}", static_path);
        }
        println!("cargo:rustc-link-lib=static=krun");

        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-lib=framework=Hypervisor");
            println!("cargo:rustc-link-lib=framework=vmnet");
        }
        return;
    }

    // Option 3: Custom directory
    if let Ok(dir) = std::env::var("LIBKRUN_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        link_krun();
        return;
    }

    // Option 4: Bundled libraries in lib/linux-{arch}/ (Linux only)
    #[cfg(target_os = "linux")]
    {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        // Look in the smolvm root (two levels up from crates/smolvm-napi/)
        let smolvm_root = std::path::Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(std::path::Path::new("."));
        let lib_dir = smolvm_root.join(format!("lib/linux-{}", arch));
        let libkrun_path = lib_dir.join("libkrun.so");

        if libkrun_path.exists() && !is_lfs_pointer(&libkrun_path) {
            println!(
                "cargo:warning=Using bundled Linux libraries from {}",
                lib_dir.display()
            );
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            link_krun();
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/lib");
            return;
        }
    }

    // Option 5: System installation via pkg-config
    if pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("libkrun")
        .is_ok()
    {
        return;
    }

    // Option 6: Common installation paths
    #[cfg(target_os = "macos")]
    {
        let paths = [
            "/opt/homebrew/lib",
            "/usr/local/lib",
            "/opt/homebrew/opt/libkrun/lib",
            "/usr/local/opt/libkrun/lib",
        ];

        for path in paths {
            if std::path::Path::new(path).join("libkrun.dylib").exists() {
                println!("cargo:rustc-link-search=native={}", path);
                link_krun();
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path);
                return;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let paths = [
            "/usr/lib",
            "/usr/local/lib",
            "/usr/lib64",
            "/usr/local/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ];

        for path in paths {
            if std::path::Path::new(path).join("libkrun.so").exists() {
                println!("cargo:rustc-link-search=native={}", path);
                link_krun();
                return;
            }
        }
    }

    // Fallback: let the linker figure it out
    link_krun();
}
