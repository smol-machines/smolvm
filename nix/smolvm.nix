{
  lib,
  stdenv,
  fetchurl,
  makeWrapper,
  patchelf,
  gcc-unwrapped,
  bzip2,
}: let
  version = "0.8.2";

  releases = {
    x86_64-linux = {
      asset = "smolvm-${version}-linux-x86_64.tar.gz";
      root = "smolvm-${version}-linux-x86_64";
      hash = "sha256-FEzCyn9yauzy/ydXZxeD2DK1cXVg2XYlOil6UeUKJeA=";
    };
    aarch64-linux = {
      asset = "smolvm-${version}-linux-arm64.tar.gz";
      root = "smolvm-${version}-linux-arm64";
      hash = "sha256-214tjfCntQbk40FiX3TleC9c2xQA0GuTAzJ1QDisn18=";
    };
    aarch64-darwin = {
      asset = "smolvm-${version}-darwin-arm64.tar.gz";
      root = "smolvm-${version}-darwin-arm64";
      hash = "sha256-jDHrgsq/Ca0UKahufRHMuA2B/i4Y2JKKUpDqWmVWKgI=";
    };
  };

  release = releases.${stdenv.hostPlatform.system} or (throw "smolvm release tarball is not available for ${stdenv.hostPlatform.system}");

  linuxRpath = lib.makeLibraryPath [
    gcc-unwrapped.lib
    bzip2
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
          --set-default SMOLVM_AGENT_ROOTFS $out/libexec/smolvm/agent-rootfs

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
