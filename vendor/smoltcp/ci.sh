#!/usr/bin/env bash

set -eox pipefail

export DEFMT_LOG=trace

MSRV="1.91.0"

RUSTC_VERSIONS=(
    $MSRV
    "stable"
    "nightly"
)

FEATURES_TEST=(
    "default"
    "std,proto-ipv4"
    "std,medium-ethernet,phy-raw_socket,proto-ipv6,socket-udp,socket-dns"
    "std,medium-ethernet,phy-tuntap_interface,proto-ipv6,socket-udp"
    "std,medium-ethernet,proto-ipv4,proto-ipv4-fragmentation,socket-raw,socket-dns"
    "std,medium-ethernet,proto-ipv4,multicast,socket-raw,socket-dns"
    "std,medium-ethernet,proto-ipv4,socket-udp,socket-tcp,socket-dns"
    "std,medium-ethernet,proto-ipv4,proto-dhcpv4,socket-udp"
    "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv6,multicast,proto-rpl,socket-udp,socket-dns,auto-icmp-echo-reply"
    "std,medium-ethernet,proto-ipv6,socket-tcp"
    "std,medium-ethernet,proto-ipv6,socket-tcp,proto-ipv6-slaac"
    "std,medium-ethernet,medium-ip,proto-ipv4,socket-icmp,socket-tcp"
    "std,medium-ip,proto-ipv6,socket-icmp,socket-tcp"
    "std,medium-ieee802154,proto-sixlowpan,socket-udp,auto-icmp-echo-reply"
    "std,medium-ieee802154,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp,auto-icmp-echo-reply"
    "std,medium-ieee802154,proto-rpl,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp,auto-icmp-echo-reply"
    "std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-udp"
    "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv4,proto-ipv6,multicast,proto-rpl,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async,auto-icmp-echo-reply,proto-ipv6-slaac"
    "std,medium-ip,proto-ipv4,proto-ipv6,multicast,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "std,medium-ieee802154,medium-ip,proto-ipv4,socket-raw,auto-icmp-echo-reply"
    "std,medium-ethernet,proto-ipv4,proto-ipsec,socket-raw"
    "alloc,medium-ethernet,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp,proto-ipv6-slaac"
)

FEATURES_CHECK=(
    "medium-ip,medium-ethernet,medium-ieee802154,proto-ipv6,proto-ipv6-slaac,multicast,proto-dhcpv4,proto-ipsec,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "defmt,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6-slaac,multicast,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "defmt,alloc,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6-slaac,multicast,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "medium-ieee802154,proto-sixlowpan,socket-dns,auto-icmp-echo-reply"
)

test() {
    local version=$1
    rustup toolchain install $version

    for features in ${FEATURES_TEST[@]}; do
        cargo +$version test --no-default-features --features "$features"
    done
}

netsim() {
    cargo test --release --features _netsim netsim
}

check() {
    local version=$1
    rustup toolchain install $version

    export DEFMT_LOG="trace"

    for features in ${FEATURES_CHECK[@]}; do
        cargo +$version check --no-default-features --features "$features"
    done

    cargo +$version check --examples

    if [[ $version == "nightly" ]]; then
        cargo +$version check --benches
    fi
}

clippy() {
    rustup toolchain install $MSRV
    rustup component add clippy --toolchain=$MSRV
    cargo +$MSRV clippy --tests --examples -- -D warnings
}

build_16bit() {
    rustup toolchain install nightly
    rustup +nightly component add rust-src

    TARGET_WITH_16BIT_POINTER=msp430-none-elf
    for features in ${FEATURES_CHECK[@]}; do
        cargo +nightly build -Z build-std=core,alloc --target $TARGET_WITH_16BIT_POINTER --no-default-features --features=$features
    done
}

coverage() {
    for features in ${FEATURES_TEST[@]}; do
        cargo llvm-cov --no-report --no-default-features --features "$features"
    done
    cargo llvm-cov report --lcov --output-path lcov.info
}

if [[ $1 == "test" || $1 == "all" ]]; then
    if [[ -n $2 ]]; then
        if [[ $2 == "msrv" ]]; then
            test $MSRV
        else
            test $2
        fi
    else
        for version in ${RUSTC_VERSIONS[@]}; do
            test $version
        done
    fi
fi

if [[ $1 == "check" || $1 == "all" ]]; then
    if [[ -n $2 ]]; then
        if [[ $2 == "msrv" ]]; then
            check $MSRV
        else
            check $2
        fi
    else
        for version in ${RUSTC_VERSIONS[@]}; do
            check $version
        done
    fi
fi

if [[ $1 == "clippy" || $1 == "all" ]]; then
    clippy
fi

if [[ $1 == "build_16bit" || $1 == "all" ]]; then
    build_16bit
fi

if [[ $1 == "coverage" || $1 == "all" ]]; then
    coverage
fi

if [[ $1 == "netsim" || $1 == "all" ]]; then
    netsim
fi
