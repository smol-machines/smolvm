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
  version = "1.5.2";

  releases = {
    x86_64-linux = {
      asset = "smolvm-${version}-linux-x86_64.tar.gz";
      root = "smolvm-${version}-linux-x86_64";
      hash = "sha256-eZ2/o6zXdAR6SItNpN8uP5ovG1LpCqq9mT9Y4uJ73jQ=";
    };
    aarch64-linux = {
      asset = "smolvm-${version}-linux-arm64.tar.gz";
      root = "smolvm-${version}-linux-arm64";
      hash = "sha256-HyLzUReV8K7N7PHk5vjztmi8duIIyjcg8PJZskn32ic=";
    };
    aarch64-darwin = {
      asset = "smolvm-${version}-darwin-arm64.tar.gz";
      root = "smolvm-${version}-darwin-arm64";
      hash = "sha256-0sL56qrNNXuoKOcWYhaJs7Fnm4CCRjuGe8iRook1i6c=";
    };
  };

  release = releases.${stdenv.hostPlatform.system} or (throw "smolvm release tarball is not available for ${stdenv.hostPlatform.system}");

  linuxRpath = lib.makeLibraryPath [
    gcc-unwrapped.lib
    bzip2
  ];

  # crun/e2fsprogs/util-linux are Linux-only; the container runtime and mkfs.ext4
  # only matter there. On darwin smolvm uses the host's own facilities.
  runtimeDeps =
    [
      jq
      gzip
      gnutar
      coreutils
    ]
    ++ lib.optionals stdenv.hostPlatform.isLinux [
      crun
      e2fsprogs
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
        chmod +x $out/libexec/smolvm/smolvm $out/libexec/smolvm/smolvm-bin
        patchShebangs $out/libexec/smolvm/smolvm
      ''
      + lib.optionalString stdenv.hostPlatform.isLinux ''
        patchelf --set-interpreter ${stdenv.cc.bintools.dynamicLinker} \
          --set-rpath '$ORIGIN/lib:${linuxRpath}' \
          $out/libexec/smolvm/smolvm-bin

        for library in $out/libexec/smolvm/lib/*.so*; do
          if patchelf --print-needed "$library" >/dev/null 2>&1; then
            patchelf --set-rpath '$ORIGIN:${linuxRpath}' "$library"
          fi
        done
      ''
      + ''
        makeWrapper $out/libexec/smolvm/smolvm $out/bin/smolvm \
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
