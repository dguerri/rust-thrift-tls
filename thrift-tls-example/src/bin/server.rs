use std::fs::File;
use std::io::BufReader;

use env_logger;
use log;
use rust_thrift_tls::{KeyPair, TLSTServer};
use rustls::RootCertStore;
use thrift::protocol::{TCompactInputProtocolFactory, TCompactOutputProtocolFactory};
use thrift::transport::{TFramedReadTransportFactory, TFramedWriteTransportFactory};

use thrift_tls_example::{SimpleServiceSyncHandler, SimpleServiceSyncProcessor};

fn main() {
    env_logger::init();
    log::debug!("starting up");

    match run() {
        Ok(()) => log::info!("server ran successfully"),
        Err(e) => {
            log::error!("server failed with error {:?}", e);
            std::process::exit(1);
        }
    }
}

fn run() -> thrift::Result<()> {
    let mut cert_store = RootCertStore::empty();

    let file = File::open("x509/rootCA.crt").expect("couldn't open file");
    let mut file = BufReader::new(file);

    cert_store
        .add_pem_file(&mut file)
        .expect("failed to add cert to store");

    // set listen address
    let listen_address = "127.0.0.1:9000";

    // create input protocol/transport factory
    let i_tran_fact = TFramedReadTransportFactory::new();
    let i_prot_fact = TCompactInputProtocolFactory::new();

    // create output  protocol/transport factory
    let o_tran_fact = TFramedWriteTransportFactory::new();
    let o_prot_fact = TCompactOutputProtocolFactory::new();

    // create the server and start listening
    let processor = SimpleServiceSyncProcessor::new(SimpleServiceHandlerImpl {});
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
        Some(cert_store),
        true,
    );

    log::info!("binding to {}", listen_address);
    server.listen(&listen_address)
}

// server implementation
#[derive(Default)]
struct SimpleServiceHandlerImpl;
impl SimpleServiceSyncHandler for SimpleServiceHandlerImpl {
    fn handle_hello(&self, name: String) -> thrift::Result<String> {
        log::debug!("Request received for name: '{}'", name);
        Ok(format!("Hello {}!", name))
    }
}
