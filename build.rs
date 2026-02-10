//! Build script for smolvm.
//!
//! Handles finding and linking libkrun.
//!
//! # Linking Options
//!
//! ## Dynamic (default)
//! Requires libkrun installed on the system:
//! ```sh
//! brew install libkrun  # macOS
//! cargo build
//! ```
//!
//! ## Bundle Pre-built Library (Recommended for Distribution)
//! Copy Homebrew's libkrun to your bundle directory and build:
//! ```sh
//! mkdir -p lib
//! cp /opt/homebrew/opt/libkrun/lib/libkrun.dylib lib/
//! # Also copy libkrunfw if bundling
//! cp /opt/homebrew/opt/libkrunfw/lib/libkrunfw.dylib lib/
//! LIBKRUN_BUNDLE=$PWD/lib cargo build --release
//! ```
//! The binary will use @rpath to find libraries in ./lib or ../lib.
//!
//! ## Build from Submodule (Experimental)
//! Build libkrun from the vendored submodule:
//! ```sh
//! LIBKRUN_BUILD=1 cargo build
//! ```
//! Note: This builds a minimal libkrun. Block device support (`krun_add_disk2`)
//! requires building libkrun separately with `make BLK=1` and using LIBKRUN_BUNDLE.
//!
//! ## Static (libkrun only)
//! Statically link libkrun (still dynamically links libkrunfw):
//! ```sh
//! LIBKRUN_STATIC=/path/to/libkrun.a cargo build
//! ```

use std::path::PathBuf;
use std::process::Command;

/// Link libkrun — weak on macOS so the binary can start without it
/// (packed binary mode uses dlopen instead of link-time symbols).
fn link_krun() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-arg=-Wl,-weak-lkrun");
    #[cfg(not(target_os = "macos"))]
    link_krun();
}

fn main() {
    // On macOS, create a placeholder __SMOLVM,__smolvm Mach-O section.
    // This section is replaced with real data by `smolvm pack --single-file`.
    // The placeholder marker is NOT the SMOLSECT magic, so detect.rs won't
    // false-positive on a normal smolvm binary.
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let placeholder_path = format!("{}/smolvm_placeholder.bin", out_dir);
        let mut f = std::fs::File::create(&placeholder_path).unwrap();
        f.write_all(b"SMOLVM_SECTION_PLACEHOLDER_V1").unwrap();
        f.write_all(&[0u8; 4]).unwrap();
        println!(
            "cargo:rustc-link-arg=-Wl,-sectcreate,__SMOLVM,__smolvm,{}",
            placeholder_path
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    link_libkrun();
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn link_libkrun() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_STATIC");
    println!("cargo:rerun-if-env-changed=LIBKRUN_BUNDLE");
    println!("cargo:rerun-if-env-changed=LIBKRUN_DIR");
    println!("cargo:rerun-if-env-changed=LIBKRUN_BUILD");

    // Option 0: Build from submodule
    if std::env::var("LIBKRUN_BUILD").is_ok() {
        if let Some(lib_path) = build_libkrun_from_submodule() {
            println!("cargo:rustc-link-search=native={}", lib_path.display());
            link_krun();

            // Set rpath to find libraries relative to executable
            #[cfg(target_os = "macos")]
            {
                println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/lib");
                println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib");
                // Also add the build output path for development
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path.display());
            }
            #[cfg(target_os = "linux")]
            {
                println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/lib");
                println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
            }
            return;
        }
    }

    // Option 1: Bundle libraries with the binary
    if let Ok(bundle_path) = std::env::var("LIBKRUN_BUNDLE") {
        println!("cargo:rustc-link-search=native={}", bundle_path);
        link_krun();

        // Set rpath to find libraries relative to executable
        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib");

            // Change the library's install_name to use @rpath and re-sign
            let lib_path = std::path::Path::new(&bundle_path).join("libkrun.dylib");
            if lib_path.exists() {
                let _ = Command::new("install_name_tool")
                    .args(["-id", "@rpath/libkrun.dylib", lib_path.to_str().unwrap()])
                    .status();
                // Re-sign after modification (macOS requires valid signature)
                let _ = Command::new("codesign")
                    .args(["--force", "--sign", "-", lib_path.to_str().unwrap()])
                    .status();
            }
        }
        #[cfg(target_os = "linux")]
        {
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

        // Static libkrun requires these frameworks on macOS
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

    // Option 4: Bundled libraries in lib/linux-{arch}/ (for distribution builds)
    #[cfg(target_os = "linux")]
    {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let lib_dir = format!("{}/lib/linux-{}", manifest_dir, arch);
        let lib_path = std::path::Path::new(&lib_dir);

        if lib_path.join("libkrun.so").exists() {
            println!(
                "cargo:warning=Using bundled Linux libraries from {}",
                lib_dir
            );
            println!("cargo:rustc-link-search=native={}", lib_dir);
            link_krun();

            // Set rpath to find libraries relative to executable
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
            // Also add the source directory for development builds
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir);
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
                // Set rpath so runtime linker can find dependencies
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

    // Fallback
    link_krun();
}

/// Build libkrun from the vendored submodule.
///
/// Returns the path to the directory containing the built library.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn build_libkrun_from_submodule() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    let libkrun_dir = manifest_dir.join("libkrun");

    // Check if submodule exists
    if !libkrun_dir.join("Cargo.toml").exists() {
        println!(
            "cargo:warning=libkrun submodule not found at {}. \
             Run: git submodule update --init",
            libkrun_dir.display()
        );
        return None;
    }

    // On macOS, libkrun embeds the init binary via include_bytes!()
    // We need to ensure init/init exists (copy from init/init.krun if needed)
    #[cfg(target_os = "macos")]
    {
        let init_dst = libkrun_dir.join("init/init");
        let init_src = libkrun_dir.join("init/init.krun");
        if !init_dst.exists() && init_src.exists() {
            println!("cargo:warning=Copying init.krun to init for embedding...");
            if let Err(e) = std::fs::copy(&init_src, &init_dst) {
                println!("cargo:warning=Failed to copy init binary: {}", e);
                return None;
            }
        } else if !init_dst.exists() {
            println!("cargo:warning=init binary not found. Need init/init or init/init.krun");
            return None;
        }
    }

    // Determine profile
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "release".to_string());

    println!(
        "cargo:warning=Building libkrun from submodule ({} build)...",
        profile
    );

    // Build libkrun using cargo directly (make has issues on macOS)
    // Note: blk,net features require additional setup and are optional
    let libkrun_manifest = libkrun_dir.join("src/libkrun/Cargo.toml");
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&libkrun_manifest);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd.status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=libkrun built successfully");
        }
        Ok(s) => {
            println!(
                "cargo:warning=libkrun build failed with exit code: {:?}",
                s.code()
            );
            return None;
        }
        Err(e) => {
            println!("cargo:warning=Failed to run cargo: {}", e);
            return None;
        }
    }

    // Find the built library
    let target_dir = if profile == "release" {
        libkrun_dir.join("target/release")
    } else {
        libkrun_dir.join("target/debug")
    };

    #[cfg(target_os = "macos")]
    let lib_name = "libkrun.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "libkrun.so";

    if target_dir.join(lib_name).exists() {
        // Copy library to smolvm's target directory for bundling
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").ok()?);
        let lib_out_dir = out_dir.join("lib");
        std::fs::create_dir_all(&lib_out_dir).ok()?;

        let src = target_dir.join(lib_name);
        let dst = lib_out_dir.join(lib_name);
        std::fs::copy(&src, &dst).ok()?;

        println!(
            "cargo:warning=Copied {} to {}",
            src.display(),
            dst.display()
        );

        // On macOS, change the install_name to use @rpath so the binary finds
        // the bundled library instead of a system-installed one
        #[cfg(target_os = "macos")]
        {
            let install_name = format!("@rpath/{}", lib_name);
            let status = Command::new("install_name_tool")
                .args(["-id", &install_name, dst.to_str().unwrap()])
                .status();
            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:warning=Set install_name to {}", install_name);
                    // Re-sign after modification
                    let _ = Command::new("codesign")
                        .args(["--force", "--sign", "-", dst.to_str().unwrap()])
                        .status();
                }
            }
        }

        // Tell cargo to rebuild if libkrun source changes
        println!(
            "cargo:rerun-if-changed={}",
            libkrun_dir.join("src").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            libkrun_dir.join("init").display()
        );

        Some(lib_out_dir)
    } else {
        println!(
            "cargo:warning=Built library not found at {}",
            target_dir.join(lib_name).display()
        );
        None
    }
}
