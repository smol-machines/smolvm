{
  description = "smolvm — OCI-native microVM runtime";

  outputs = { self }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];

      forAllSystems = fn: builtins.listToAttrs (
        map (system: { name = system; value = fn system; }) systems
      );

      nixpkgsFor = system:
        import (builtins.fetchTarball {
          url = "https://github.com/NixOS/nixpkgs/archive/01fbdeef22b76df85ea168fbfe1bfd9e63681b30.tar.gz";
        }) { inherit system; };

    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor system;
          lib = pkgs.lib;
          isDarwin = lib.hasSuffix "darwin" system;

          guestArch = if pkgs.stdenv.hostPlatform.isAarch64 then "aarch64" else "x86_64";
          guestKernelArch = if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "x86_64";
          guestBundleType = if pkgs.stdenv.hostPlatform.isAarch64 then "Image" else "vmlinux";
          guestKernelImage = if pkgs.stdenv.hostPlatform.isAarch64
            then "linux-6.12.76/arch/arm64/boot/Image"
            else "linux-6.12.76/vmlinux";

          kernelTarball = pkgs.fetchurl {
            url = "mirror://kernel/linux/kernel/v6.x/linux-6.12.76.tar.xz";
            hash = "sha256-u7Q+g0xG5r1JpcKPIuZ5qTdENATh9lMgTUskkp862JY=";
          };

          linuxCrossPkgs = if pkgs.stdenv.hostPlatform.isAarch64 then
            pkgs.pkgsCross.aarch64-multiplatform
          else
            pkgs.pkgsCross.gnu64;

          libkrunfw = pkgs.stdenv.mkDerivation {
            pname = "libkrunfw";
            version = "5.3.0";

            src = pkgs.fetchFromGitHub {
              owner = "smol-machines";
              repo = "libkrunfw";
              rev = "351d354b4b3b3e45f38e29897af8acec9966fd41";
              hash = "sha256-fhG/bP1HzmhyU2N+wnr1074WEGsD9RdTUUBhYUFpWlA=";
            };

            postPatch =
              ''
                substituteInPlace Makefile \
                  --replace 'curl $(KERNEL_REMOTE) -o $(KERNEL_TARBALL)' 'ln -s ${kernelTarball} $(KERNEL_TARBALL)'
              ''
              + lib.optionalString (lib.hasSuffix "darwin" system) ''
                sed -i 's|./build_on_krunvm.sh|echo "kernel.c pre-built by Nix"|' Makefile
              '';

            preBuild = lib.optionalString (lib.hasSuffix "darwin" system) ''
              echo "Building guest Linux kernel for ${guestArch} on macOS..."
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
            '';

            nativeBuildInputs = with pkgs; [
              gnumake gcc bc bison flex perl python3 python3.pkgs.pyelftools
            ] ++ lib.optionals (lib.hasSuffix "darwin" system) [ linuxCrossPkgs.stdenv.cc ];

            buildInputs = lib.optionals (lib.hasSuffix "linux" system) [ pkgs.elfutils ];

            env = lib.optionalAttrs pkgs.stdenv.hostPlatform.isAarch64 {
              NIX_CFLAGS_COMPILE = "-march=armv8-a+crypto";
            };

            makeFlags = [ "PREFIX=$(out)" ];
            enableParallelBuilding = true;
          };

          libkrun = pkgs.stdenv.mkDerivation {
            pname = "libkrun";
            version = "1.17.3";

            src = pkgs.fetchFromGitHub {
              owner = "smol-machines";
              repo = "libkrun";
              rev = "0d3a0f61de7ec4713c09ca737a53709ebdeccf09";
              hash = "sha256-Th4vCg3xHb6lbo26IDZES7tLOUAJTebQK2+h3xSYX7U=";
            };

            cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
              src = pkgs.fetchFromGitHub {
                owner = "smol-machines";
                repo = "libkrun";
                rev = "0d3a0f61de7ec4713c09ca737a53709ebdeccf09";
                hash = "sha256-Th4vCg3xHb6lbo26IDZES7tLOUAJTebQK2+h3xSYX7U=";
              };
              hash = "sha256-0xpAyNe1jF1OMtc7FXMsejqIv0xKc1ktEvm3rj/mVFU=";
            };

            nativeBuildInputs = with pkgs; [
              gnumake rustPlatform.cargoSetupHook cargo pkg-config rustc
            ] ++ lib.optionals (lib.hasSuffix "darwin" system) [ linuxCrossPkgs.stdenv.cc ];

            buildInputs = [ libkrunfw ]
              ++ lib.optionals (lib.hasSuffix "linux" system) (with pkgs; [ glibc glibc.static ])
              ++ lib.optionals (lib.hasSuffix "darwin" system) (with pkgs; [
                darwin.apple_sdk.frameworks.Hypervisor
                darwin.apple_sdk.frameworks.vmnet
                libiconv
              ]);

            env =
              lib.optionalAttrs (lib.hasSuffix "linux" system) {
                RUSTFLAGS = toString (map (f: "-C link-arg=" + f) [
                  "-Wl,--push-state,--no-as-needed" "-lkrunfw" "-Wl,--pop-state"
                ]);
              }
              // lib.optionalAttrs (lib.hasSuffix "darwin" system) {
                CC_LINUX = "${linuxCrossPkgs.stdenv.cc}/bin/${linuxCrossPkgs.stdenv.cc.targetPrefix}gcc";
              };

            makeFlags = [ "PREFIX=$(out)" "BLK=1" "NET=1" ];

            postInstall = lib.optionalString (lib.hasSuffix "linux" system) ''
              mkdir -p $dev/lib/pkgconfig
              mv $out/lib64/pkgconfig $dev/lib/ 2>/dev/null || true
              mv $out/include $dev/ 2>/dev/null || true
            '';

            outputs = [ "out" "dev" ];
            enableParallelBuilding = true;
          };

          smolvm = pkgs.rustPlatform.buildRustPackage {
            pname = "smolvm";
            version = "0.5.20";
            src = self;
            cargoHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

            nativeBuildInputs = with pkgs; [ pkg-config ];

            buildInputs = [ libkrun libkrunfw ]
              ++ lib.optionals (lib.hasSuffix "darwin" system) (with pkgs; [
                darwin.apple_sdk.frameworks.Hypervisor
                darwin.apple_sdk.frameworks.vmnet
                Foundation
                libiconv
              ]);

            LIBKRUN_DIR = "${lib.getLib libkrun}/${if lib.hasSuffix "darwin" system then "lib" else "lib64"}";
          };

        in {
          default = smolvm;
          inherit smolvm libkrun libkrunfw;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/smolvm";
        };
      });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor system;
          libkrun = self.packages.${system}.libkrun;
          libkrunfw = self.packages.${system}.libkrunfw;
          isDarwin = pkgs.lib.hasSuffix "darwin" system;
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ rustc cargo pkg-config ];
            buildInputs = [ libkrun libkrunfw ];
            LIBKRUN_DIR = "${pkgs.lib.getLib libkrun}/${if isDarwin then "lib" else "lib64"}";
          };
        }
      );
    };
}
