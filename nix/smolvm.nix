{
  lib,
  stdenv,
  fetchurl,
  makeWrapper,
  patchelf,
  gcc-unwrapped,
  bzip2,
  # Runtime tools smolvm shells out to on the host. The binary looks for these
  # on PATH (and hardcodes FHS paths like /sbin/mkfs.ext4 that do not exist on
  # NixOS), so the wrapper must put them there.
  crun,
  jq,
  e2fsprogs,
  util-linux,
  gzip,
  gnutar,
  coreutils,
}: let
  version = "1.15.0";

  releases = {
    x86_64-linux = {
      asset = "smolvm-${version}-linux-x86_64.tar.gz";
      root = "smolvm-${version}-linux-x86_64";
      hash = "sha256-lKHtsMQrIKxWLDdZ7SFrqyyrnifDgvZWCWkUT3vR3OM=";
    };
    aarch64-linux = {
      asset = "smolvm-${version}-linux-arm64.tar.gz";
      root = "smolvm-${version}-linux-arm64";
      hash = "sha256-ZZszEXNPLiznMWB+OP9mfLG11BPwYm4SrGSUOoBDbf8=";
    };
    aarch64-darwin = {
      asset = "smolvm-${version}-darwin-arm64.tar.gz";
      root = "smolvm-${version}-darwin-arm64";
      hash = "sha256-SEtjxqfHTE0F3OLmP8zj0TXg+6VqHXcSgCTlc20zhKg=";
    };
  };

  release = releases.${stdenv.hostPlatform.system} or (throw "smolvm release tarball is not available for ${stdenv.hostPlatform.system}");

  linuxRpath = lib.makeLibraryPath [
    gcc-unwrapped.lib
    bzip2
  ];

  # e2fsprogs is needed on EVERY host, not just Linux: `resize2fs` shrinks a
  # machine's disk whenever one is asked for below the template size
  # (src/disk_utils.rs:112 and :135 at 8dd8b18d), and the macOS branch of that
  # error tells the user to `brew install e2fsprogs`. Without it on PATH the
  # shrink is skipped with a warning and the machine silently gets the full
  # template instead of the size that was requested. crun and util-linux stay
  # Linux-only: the container runtime and mkfs.ext4 only matter there.
  runtimeDeps =
    [
      e2fsprogs
      jq
      gzip
      gnutar
      coreutils
    ]
    ++ lib.optionals stdenv.hostPlatform.isLinux [
      crun
      util-linux
    ];
in
  stdenv.mkDerivation {
    pname = "smolvm";
    inherit version;

    src = fetchurl {
      url = "https://github.com/smol-machines/smolvm/releases/download/v${version}/${release.asset}";
      inherit (release) hash;
    };

    sourceRoot = release.root;

    nativeBuildInputs =
      [
        makeWrapper
      ]
      ++ lib.optionals stdenv.hostPlatform.isLinux [
        patchelf
      ];

    dontPatchELF = true;
    dontPatchShebangs = true;
    dontStrip = true;

    installPhase =
      ''
        runHook preInstall

        mkdir -p $out/libexec/smolvm $out/bin
        cp -R . $out/libexec/smolvm/
        # 1.15+ tarballs keep executables in bin/; older ones are flat.
        bindir=$out/libexec/smolvm
        if [ -d $out/libexec/smolvm/bin ]; then
          bindir=$out/libexec/smolvm/bin
        fi
        chmod +x $bindir/smolvm $bindir/smolvm-bin
        patchShebangs $bindir/smolvm
      ''
      + lib.optionalString stdenv.hostPlatform.isLinux ''
        patchelf --set-interpreter ${stdenv.cc.bintools.dynamicLinker} \
          --set-rpath '$ORIGIN/lib:$ORIGIN/../lib:${linuxRpath}' \
          $bindir/smolvm-bin

        for library in $out/libexec/smolvm/lib/*.so*; do
          if patchelf --print-needed "$library" >/dev/null 2>&1; then
            patchelf --set-rpath '$ORIGIN:${linuxRpath}' "$library"
          fi
        done
      ''
      + ''
        makeWrapper $bindir/smolvm $out/bin/smolvm \
          --set-default SMOLVM_AGENT_ROOTFS $out/libexec/smolvm/agent-rootfs \
          --prefix PATH : ${lib.makeBinPath runtimeDeps}

        runHook postInstall
      '';

    meta = {
      description = "Ship and run software with isolation by default";
      homepage = "https://github.com/smol-machines/smolvm";
      license = lib.licenses.asl20;
      platforms = builtins.attrNames releases;
      mainProgram = "smolvm";
      sourceProvenance = with lib.sourceTypes; [binaryNativeCode];
    };
  }
