{
  description = "smolvm — OCI-native microVM runtime";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    libkrunfw-src = {
      url = "github:smol-machines/libkrunfw/351d354b4b3b3e45f38e29897af8acec9966fd41";
      flake = false;
    };
    libkrun-src = {
      url = "github:smol-machines/libkrun/0d3a0f61de7ec4713c09ca737a53709ebdeccf09";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, libkrunfw-src, libkrun-src }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        lib = nixpkgs.lib;
        isDarwin = lib.hasSuffix "darwin" system;
        isLinux = lib.hasSuffix "linux" system;

        # Guest VM architecture — matches host for best compatibility
        guestArch = if pkgs.stdenv.hostPlatform.isAarch64 then "aarch64" else "x86_64";
        guestKernelArch = if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86_64";
        guestBundleType = if pkgs.stdenv.hostPlatform.isAarch64 then "Image" else "vmlinux";
        guestKernelImage = if pkgs.stdenv.hostPlatform.isAarch64
          then "linux-6.12.76/arch/arm64/boot/Image"
          else "linux-6.12.76/vmlinux";

        # Pre-fetched Linux kernel tarball (avoids network access during build)
        kernelTarball = pkgs.fetchurl {
          url = "mirror://kernel/linux/kernel/v6.x/linux-6.12.76.tar.xz";
          hash = "sha256-u7Q+g0xG5r1JpcKPIuZ5qTdENATh9lMgTUskkp862JY=";
        };

        # Cross-compilation toolchain for macOS → Linux (kernel build & init.c)
        linuxCrossPkgs = if pkgs.stdenv.hostPlatform.isAarch64 then
          pkgs.pkgsCross.aarch64-multiplatform
        else
          pkgs.pkgsCross.gnu64;

        # ============================================================
        # libkrunfw — bundles the guest Linux kernel as a shared library
        # ============================================================
        libkrunfw = pkgs.stdenv.mkDerivation {
          pname = "libkrunfw";
          version = "5.3.0";

          src = libkrunfw-src;

          postPatch =
            ''
              # Replace curl download with symlink to pre-fetched tarball
              substituteInPlace Makefile \
                --replace 'curl $(KERNEL_REMOTE) -o $(KERNEL_TARBALL)' 'ln -s ${kernelTarball} $(KERNEL_TARBALL)'
            ''
            + lib.optionalString isDarwin ''
              # On macOS the Makefile delegates to build_on_krunvm.sh (needs a running VM).
              # We build the kernel ourselves in preBuild, so neutralise the script call.
              sed -i 's|./build_on_krunvm.sh|echo "kernel.c pre-built by Nix"|' Makefile
            '';

          # On macOS we must build the guest kernel before `make` runs, because the
          # Makefile's Darwin path delegates to a VM script which can't run in the
          # Nix sandbox.  We cross-compile the Linux kernel using Nix's cross-toolchain.
          preBuild = lib.optionalString isDarwin ''
            echo "Building guest Linux kernel for ${guestArch} on macOS (Nix cross-compilation)..."
            tar xf ${kernelTarball}
            for p in patches/0*.patch; do
              [ -f "$p" ] && patch -p1 -d linux-6.12.76 < "$p"
            done
            cp config-libkrunfw_${guestArch} linux-6.12.76/.config
            make -C linux-6.12.76 olddefconfig \
              ARCH=${guestKernelArch} \
              CROSS_COMPILE=${linuxCrossPkgs.stdenv.cc.targetPrefix}
            make -C linux-6.12.76 -j$NIX_BUILD_CORES \
              ARCH=${guestKernelArch} \
              CROSS_COMPILE=${linuxCrossPkgs.stdenv.cc.targetPrefix} \
              ${guestBundleType}
            python3 bin2cbundle.py -t ${guestBundleType} ${guestKernelImage} kernel.c
            echo "kernel.c generated successfully"
          '';

          nativeBuildInputs = with pkgs; [
            gnumake
            gcc
            bc
            bison
            flex
            perl
            python3
            python3.pkgs.pyelftools
          ] ++ lib.optionals isDarwin [
            linuxCrossPkgs.stdenv.cc
          ];

          buildInputs = lib.optionals isLinux [ pkgs.elfutils ];

          # aarch64 needs crypto extensions for the kernel build
          env = lib.optionalAttrs pkgs.stdenv.hostPlatform.isAarch64 {
            NIX_CFLAGS_COMPILE = "-march=armv8-a+crypto";
          };

          makeFlags = [ "PREFIX=$(out)" ];

          enableParallelBuilding = true;
        };

        # ============================================================
        # libkrun — VMM library (Rust cdylib + C headers)
        # ============================================================
        libkrun = pkgs.stdenv.mkDerivation {
          pname = "libkrun";
          version = "1.17.3";

          src = libkrun-src;

          cargoRoot = ".";
          cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
            src = libkrun-src;
            hash = lib.fakeHash; # FIXME: replace with correct hash after first build
          };

          nativeBuildInputs = with pkgs; [
            gnumake
            rustPlatform.cargoSetupHook
            cargo
            pkg-config
            rustc
          ] ++ lib.optionals isDarwin [
            linuxCrossPkgs.stdenv.cc
          ];

          buildInputs =
            [ libkrunfw ]
            ++ lib.optionals isLinux (with pkgs; [
              glibc
              glibc.static
            ])
            ++ lib.optionals isDarwin (with pkgs; [
              darwin.apple_sdk.frameworks.Hypervisor
              darwin.apple_sdk.frameworks.vmnet
              libiconv
            ]);

          # On Linux: link libkrunfw directly so dlopen() finds it at runtime.
          # On macOS: provide cross-compiler for init.c (the guest init binary).
          env =
            lib.optionalAttrs isLinux {
              RUSTFLAGS = toString (
                map (f: "-C link-arg=" + f) [
                  "-Wl,--push-state,--no-as-needed"
                  "-lkrunfw"
                  "-Wl,--pop-state"
                ]
              );
            }
            // lib.optionalAttrs isDarwin {
              CC_LINUX = "${linuxCrossPkgs.stdenv.cc}/bin/${linuxCrossPkgs.stdenv.cc.targetPrefix}gcc";
            };

          makeFlags = [
            "PREFIX=$(out)"
            "BLK=1"
            "NET=1"
          ];

          postInstall = lib.optionalString isLinux ''
            # Move headers and pkg-config to dev output
            mkdir -p $dev/lib/pkgconfig
            mv $out/lib64/pkgconfig $dev/lib/ 2>/dev/null || true
            mv $out/include $dev/ 2>/dev/null || true
          '';

          outputs = [ "out" "dev" ];

          enableParallelBuilding = true;
        };

        # ============================================================
        # smolvm — OCI-native microVM runtime CLI
        # ============================================================
        smolvm = pkgs.rustPlatform.buildRustPackage {
          pname = "smolvm";
          version = "0.5.20";

          src = self;

          cargoHash = lib.fakeHash; # FIXME: replace with correct hash after first build

          nativeBuildInputs = with pkgs; [ pkg-config ];

          buildInputs =
            [ libkrun libkrunfw ]
            ++ lib.optionals isDarwin (with pkgs; [
              darwin.apple_sdk.frameworks.Hypervisor
              darwin.apple_sdk.frameworks.vmnet
              Foundation
              libiconv
            ]);

          # Point smolvm's build.rs to our pre-built libkrun
          LIBKRUN_DIR = "${lib.getLib libkrun}/${if isDarwin then "lib" else "lib64"}";
        };

      in
      {
        packages = {
          default = smolvm;
          inherit smolvm libkrun libkrunfw;
        };

        apps.default = {
          type = "app";
          program = "${smolvm}/bin/smolvm";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ rustc cargo pkg-config ];

          buildInputs = [ libkrun libkrunfw ];

          LIBKRUN_DIR = "${lib.getLib libkrun}/${if isDarwin then "lib" else "lib64"}";

          shellHook = ''
            echo "smolvm development shell"
            echo "  libkrun:   ${lib.getLib libkrun}"
            echo "  libkrunfw: ${lib.getLib libkrunfw}"
          '';
        };
      }
    );
}
