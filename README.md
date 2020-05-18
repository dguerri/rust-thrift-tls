# Apache Thrift TLS with mutual authentication

**NOTE**:

- I have just started learning Rust. This could be (and probably is) using bad practices and very close to be garbage.
- There is not even a unit test, yet.
- I should really try to submit a PR later, when I know what I am doing
- The `simple_service` demo is adapted from [this tutorial](https://www.allengeorge.com/2017/05/07/thrift-and-rust/)
- `tls_*.rs` files contain a lot of copy-pasted code from the offical [Apache Thrift codebase](https://github.com/apache/thrift)

Anyway....

# How do I use this?

## Client and server demo

You can find a client-server example under `thrift-tls-example` using TLS mutual authentication.

1. Run `setup.sh` to create X509 certs and related keys and to create the Thift spec file
2. Run the server: `cargo run --bin server`
3. Run the client: `cargo run --bin client`

Use `RUST_LOG=debug` to see debug messages

## Code

### Client example (no client auth)

```rust
    let mut c = TLSTTcpChannel::new();
    // create a new TLS session with default (embedded) RootCertStore
    c.open("localhost:9000", None, None)?;

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
        KeyPair {
            cert_file: "x509/server.crt",
            key_file: "x509/server.key",
        },
        None,   // Default (embedded RootCertStore)
        false,  // Client authentication not required
    );

    // set listen address
    let listen_address = "127.0.0.1:9000";
    log::info!("binding to {}", listen_address);
    server.listen(&listen_address)
```
