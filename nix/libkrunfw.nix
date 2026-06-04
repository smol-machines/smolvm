{
  lib,
  stdenv,
  fetchurl,
  src,
  pkgsCross,
  flex,
  bison,
  bc,
  cpio,
  perl,
  elfutils,
  libelf,
  python3,
  variant ? null,
}:

assert lib.elem variant [
  null
  "sev"
  "tdx"
];

let
  linuxCrossCc = if stdenv.hostPlatform.isAarch64
    then pkgsCross.aarch64-multiplatform.stdenv.cc
    else pkgsCross.gnu64.stdenv.cc;
in
stdenv.mkDerivation (finalAttrs: {
  pname = "libkrunfw" + lib.optionalString (variant != null) "-${variant}";
  version = "5.4.0";

  inherit src;

  kernelSrc = fetchurl {
    url = "mirror://kernel/linux/kernel/v6.x/linux-6.12.87.tar.xz";
    hash = "sha256-zBKnZEtM754GYnsp3odT4is9B2cDqbUr6EJj4FyLmDA=";
  };

  postPatch = ''
    substituteInPlace Makefile \
      --replace 'curl $(KERNEL_REMOTE) -o $(KERNEL_TARBALL)' 'ln -s $(kernelSrc) $(KERNEL_TARBALL)'
  '' + lib.optionalString stdenv.hostPlatform.isDarwin ''
    substituteInPlace Makefile \
      --replace 'for patch in $(KERNEL_PATCHES); do patch -p1 -d $(KERNEL_SOURCES) < "$$patch"; done' 'for patch in $(KERNEL_PATCHES); do patch -p1 -d $(KERNEL_SOURCES) < "$$patch"; done; perl -0pi -e "s/typedef struct \\{\\n\\t__u8 b\\[16\\];\\n\\} uuid_t;/#ifndef __APPLE__\\ntypedef struct {\\n\\t__u8 b[16];\\n} uuid_t;\\n#endif/; s/uuid->b\\[/(*uuid)[/g" $(KERNEL_SOURCES)/scripts/mod/file2alias.c' \
      --replace '$(MAKE) olddefconfig' '$(MAKE) HOSTCC=cc HOSTCFLAGS=-I../host-include olddefconfig' \
      --replace '$(MAKE) $(MAKEFLAGS) $(KERNEL_FLAGS)' '$(MAKE) HOSTCC=cc HOSTCFLAGS=-I../host-include $(MAKEFLAGS) $(KERNEL_FLAGS)'
  '';

  preBuild = lib.optionalString stdenv.hostPlatform.isDarwin ''
    mkdir -p host-include
    cp ${linuxCrossCc.libc.dev}/include/elf.h host-include/
    cat > host-include/byteswap.h <<'EOF'
    #pragma once
    #define bswap_16(x) __builtin_bswap16(x)
    #define bswap_32(x) __builtin_bswap32(x)
    #define bswap_64(x) __builtin_bswap64(x)
    EOF
    export HOSTCC=cc
  '';

  nativeBuildInputs = [
    stdenv.cc
    flex
    bison
    bc
    cpio
    perl
    python3
    python3.pkgs.pyelftools
  ] ++ lib.optionals stdenv.hostPlatform.isDarwin [
    linuxCrossCc
    libelf
  ];

  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    elfutils
  ];

  makeFlags = [
    "PREFIX=${placeholder "out"}"
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin [
    "OS=Linux"
    "ARCH=${stdenv.hostPlatform.linuxArch}"
    "CROSS_COMPILE=${linuxCrossCc.targetPrefix}"
  ]
  ++ lib.optionals (variant == "sev") [
    "SEV=1"
  ]
  ++ lib.optionals (variant == "tdx") [
    "TDX=1"
  ];

  # Fixes https://github.com/containers/libkrunfw/issues/55
  env = lib.optionalAttrs stdenv.targetPlatform.isAarch64 {
    NIX_CFLAGS_COMPILE = "-march=armv8-a+crypto";
  };

  enableParallelBuilding = true;

  meta = {
    description = "Dynamic library bundling the guest payload consumed by libkrun";
    homepage = "https://github.com/smol-machines/libkrunfw";
    license = with lib.licenses; [
      lgpl2Only
      lgpl21Only
    ];
    platforms = [
      "x86_64-linux"
    ]
    ++ lib.optionals (variant == null) [
      "aarch64-linux"
      "riscv64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ];
  };
})
