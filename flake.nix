{
  description = "Ship and run software with isolation by default.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    libkrun-src = {
      url = "github:smol-machines/libkrun/98163265197caa24a789699f16a68b98e917b65b";
      flake = false;
    };

    libkrunfw-src = {
      url = "github:smol-machines/libkrunfw/516ceece6aed60ccc84ac8faa459885062e39400";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      libkrun-src,
      libkrunfw-src,
      ...
    }:
    let
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system: function (nixpkgs.legacyPackages.${system}.extend overlay)
        );

      overlay = final: prev: {
        smolvm-libkrunfw = final.callPackage ./nix/libkrunfw.nix {
          src = libkrunfw-src;
        };

        smolvm-libkrun = final.callPackage ./nix/libkrun.nix {
          src = libkrun-src;
          libkrunfw = final.smolvm-libkrunfw;
          withBlk = true;
          withNet = true;
          withGpu = final.stdenv.hostPlatform.isLinux;
        };

        smolvm = final.callPackage ./nix/smolvm.nix { };
      };
    in
    {
      overlays.default = overlay;

      formatter = forAllSystems (pkgs: pkgs.alejandra);

      packages = forAllSystems (pkgs: {
        libkrunfw = pkgs.smolvm-libkrunfw;
        libkrun = pkgs.smolvm-libkrun;
        smolvm = pkgs.smolvm;
        default = pkgs.smolvm;
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/smolvm";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [
            self.packages.${pkgs.stdenv.hostPlatform.system}.libkrun
          ];

          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            cargo-make
            pkg-config
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          LIBKRUN_DIR = "${pkgs.lib.getLib self.packages.${pkgs.stdenv.hostPlatform.system}.libkrun}/${
            if pkgs.stdenv.hostPlatform.isDarwin then "lib" else "lib64"
          }";
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });
    };
}
