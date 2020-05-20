# Apache Thrift TLS with mutual authentication

This package aims to provide full TLS (1.2 and 1.3) support to Apache Thrift for Rust.
It provides such support by being as unobtrusive as possible and with very little overhead in terms of additional code needed.

TLS support is provided via [Rustls](https://github.com/ctz/rustls), a modern, fast and powerfull TLS library written in Rust.

**Note**:

- My way of learning RUST is trying to do something useful with it... so this could be (and probably is) using bad practices and very close to be garbage.
- I should really try to submit a PR to the Apache Thrify codebase later, when I know what I am doing
- `tls_*.rs` files contain a lot of copy-pasted code from the offical [Apache Thrift codebase](https://github.com/apache/thrift)

**Technical note**

- Thrift library uses separated input and output protocol by cloning the TCP (cient or server) stream. Rustls, and specifically its sessions, [doesn't currently support full-duplex](https://github.com/ctz/rustls/issues/288) so the quick solution I came up with is to wrap the session in a `Arc<Mutex>`, providing syncronization for concurrent use.
  This solution should be working with Thrift, but might present corner cases from performance and behaviour perspectve.
  If you have a better idea, please step forward :-)

# How do I use this?

## Client and server demo

There is a client-server example in the Github repo: https://github.com/dguerri/rust-thrift-tls.
You will find a client-server example under `thrift-tls-example` using TLS mutual authentication.

1. Run `setup.sh` to create X509 certs and related keys and to create the Thift spec file
2. Run the server: `cargo run --bin server`
3. Run the client: `cargo run --bin client`

Use `RUST_LOG=debug` to see debug messages

## Code example

### Client (no client auth)

```rust
    let mut c = TLSTTcpChannel::new();
    // create a new TLS session with default (embedded) RootCertStore
    c.open(
        "localhost:9000",
        None, // Do not perform client auth
        None, // Default (embedded RootCertStore)
    )?;

    // build the input/output protocol as usual (see "plain" Thrift examples)
    // [...]
```

### Server example

```rust
    // build transport factories and protocols as usual (see "plain" Thrift examples)
    // [...]

    // create a pre-threaded server
    let mut server = TLSTServer::new(
        i_tran_fact,
        i_prot_fact,
        o_tran_fact,
        o_prot_fact,
        processor,
        10,
        X509Credentials::new("x509/server.crt", "x509/server.key"),
        None,   // Default (embedded RootCertStore)
        false,  // Client authentication not required
    );

    // set listen address
    let listen_address = "127.0.0.1:9000";
    log::info!("binding to {}", listen_address);
    server.listen(&listen_address)
```
