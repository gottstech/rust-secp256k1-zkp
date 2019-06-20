[![Build Status](https://travis-ci.org/gottstech/rust-secp256k1-zkp.svg?branch=master)](https://travis-ci.org/gottstech/rust-secp256k1-zkp)

### rust-secp256k1-zkp

This is a rust wrapper around [secp256k1](https://github.com/bitcoin/secp256k1).

This rust library:

* exposes type-safe Rust bindings for all `libsecp256k1` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations

### Build and Run

```
git clone --recursive https://github.com/gottstech/rust-secp256k1-zkp.git
cd rust-secp256k1-zkp
cargo build --release
```

