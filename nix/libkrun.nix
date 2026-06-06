{
  lib,
  stdenv,
  rustPlatform,
  src,
  cargo,
  curl,
  cacert,
  pkg-config,
  glibc,
  openssl,
  libcap_ng,
  libepoxy,
  libdrm,
  pipewire,
  virglrenderer,
  libkrunfw,
  rustc,
  pkgsCross,
  darwin,
  apple-sdk_15 ? null,
  libiconv,
  libarchive ? null,
  libnsm ? null,
  withBlk ? false,
  withNet ? false,
  withGpu ? false,
  withSound ? false,
  withInput ? false,
  withTimesync ? false,
  withAwsNitro ? false,
  variant ? null,
}:

assert lib.elem variant [
  null
  "sev"
  "tdx"
];
assert withAwsNitro -> variant == null;
assert withAwsNitro -> stdenv.hostPlatform.isLinux;
assert withAwsNitro -> libarchive != null && libnsm != null;

let
  linuxCrossPkgs = if stdenv.hostPlatform.isAarch64
    then pkgsCross.aarch64-multiplatform
    else pkgsCross.gnu64;
  libkrunfw' = (libkrunfw.override { inherit variant; });
in
stdenv.mkDerivation (finalAttrs: {
  pname = "libkrun"
    + lib.optionalString (variant != null) "-${variant}"
    + lib.optionalString withAwsNitro "-awsnitro";
  version = "1.17.3";

  inherit src;

  outputs = [
    "out"
    "dev"
  ];

  cargoDeps = rustPlatform.fetchCargoVendor {
    inherit (finalAttrs) src;
    hash = "sha256-b6Rk6ljpHNKwVD7r/NhppGE1TLKRXo8MxZNAszcOH5I=";
  };

  postPatch = ''
    substituteInPlace Makefile \
      --replace 'cargo build --release $(FEATURE_FLAGS)' 'cargo build -p libkrun --release $(FEATURE_FLAGS)' \
      --replace 'cargo build $(FEATURE_FLAGS)' 'cargo build -p libkrun $(FEATURE_FLAGS)'
  '' + lib.optionalString stdenv.hostPlatform.isDarwin ''
    substituteInPlace Makefile \
      --replace 'CC_LINUX=$(CLANG) -target $(GCC_TRIPLET) -fuse-ld=lld -Wl,-strip-debug --sysroot $(abspath $(SYSROOT_LINUX)) -B$(GCC_LIB_DIR) -L$(GCC_LIB_DIR) -Wno-c23-extensions' 'CC_LINUX=${linuxCrossPkgs.stdenv.cc}/bin/${linuxCrossPkgs.stdenv.cc.targetPrefix}gcc -L${linuxCrossPkgs.glibc.static}/lib' \
      --replace 'mv target/release/libkrun.dylib target/release/$(KRUN_BASE_$(OS))' 'true'
  '';

  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    rustPlatform.bindgenHook
    cargo
    pkg-config
    rustc
    curl
    cacert
  ] ++ lib.optional stdenv.hostPlatform.isDarwin linuxCrossPkgs.stdenv.cc;

  buildInputs = [
    libkrunfw'
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    libcap_ng
    glibc
    glibc.static
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin [
    apple-sdk_15
    libiconv
  ]
  ++ lib.optionals withGpu [
    libepoxy
    libdrm
    virglrenderer
  ]
  ++ lib.optional withSound pipewire
  ++ lib.optional (variant == "sev" || variant == "tdx") openssl
  ++ lib.optionals withAwsNitro [
    libarchive
    libnsm
  ];

  makeFlags = [
    "PREFIX=${placeholder "out"}"
  ]
  ++ lib.optional withBlk "BLK=1"
  ++ lib.optional withNet "NET=1"
  ++ lib.optional withGpu "GPU=1"
  ++ lib.optional withSound "SND=1"
  ++ lib.optional withInput "INPUT=1"
  ++ lib.optional withTimesync "TIMESYNC=1"
  ++ lib.optional withAwsNitro "AWS_NITRO=1"
  ++ lib.optional (variant == "sev") "SEV=1"
  ++ lib.optional (variant == "tdx") "TDX=1";

  postInstall = ''
    mkdir -p $dev/lib/pkgconfig
    mv $out/${if stdenv.hostPlatform.isDarwin then "lib" else "lib64"}/pkgconfig $dev/lib/
    mv $out/include $dev/
  '';

  env = {
    OPENSSL_NO_VENDOR = true;
  }
  // lib.optionalAttrs stdenv.hostPlatform.isLinux {
    # Make sure libkrunfw can be found by dlopen().
    RUSTFLAGS = toString (
      map (flag: "-C link-arg=" + flag) [
        "-Wl,--push-state,--no-as-needed"
        ("-lkrunfw" + lib.optionalString (variant != null) "-${variant}")
        "-Wl,--pop-state"
      ]
    );
  }
  // lib.optionalAttrs stdenv.hostPlatform.isDarwin {
    CC_LINUX = "${linuxCrossPkgs.stdenv.cc}/bin/${linuxCrossPkgs.stdenv.cc.targetPrefix}gcc -L${linuxCrossPkgs.glibc.static}/lib";
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  meta = {
    description = "Dynamic library providing Virtualization-based process isolation capabilities";
    homepage = "https://github.com/smol-machines/libkrun";
    license = lib.licenses.asl20;
    platforms = libkrunfw'.meta.platforms;
  };
})
