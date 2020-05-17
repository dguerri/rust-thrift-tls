# Apache Thrift TLS with mutual authentication

**NOTES**:

- I have just started learning Rust. This could be (and probably is) using bad practices and very close to be garbage.
- There is not even a unit test, yet.
- I should really try to submit a PR later, when I know better what I am doing ;)
- The `simple_service` demo is adapted from [this tutorial](https://www.allengeorge.com/2017/05/07/thrift-and-rust/)
- `tls_*.rs` files contain a lot of copy-pasted code from the offical [Apache Thrift codebase](https://github.com/apache/thrift)

Anyway....

# How do I use this?

You can find a client-server example under `thrift-tls-example` using TLS mutual authentication.

1. Run `setup.sh` to create X509 certs and related keys and to create the Thift spec file
2. Launch the server: `RUST_LOG=debug cargo run --bin server`
3. Launch the client: `RUST_LOG=debug cargo run --bin client`
