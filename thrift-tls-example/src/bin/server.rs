use std::fs::File;
use std::io::BufReader;

use env_logger::{self, Env};
use log;
use rust_thrift_tls::{TLSTServer, X509Credentials};
use rustls::RootCertStore;
use thrift::protocol::{TCompactInputProtocolFactory, TCompactOutputProtocolFactory};
use thrift::transport::{TFramedReadTransportFactory, TFramedWriteTransportFactory};

use thrift_tls_example::{SimpleServiceSyncHandler, SimpleServiceSyncProcessor};

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();

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
    // load the demo root CA certs into the RootCertStore (used to authenticate the clients)
    let file = File::open("x509/rootCA.crt").expect("couldn't open file");
    let mut file = BufReader::new(file);
    let mut cert_store = RootCertStore::empty();
    cert_store
        .add_pem_file(&mut file)
        .expect("failed to add cert to store");

    // create input protocol/transport factory
    let i_tran_fact = TFramedReadTransportFactory::new();
    let i_prot_fact = TCompactInputProtocolFactory::new();

    // create output  protocol/transport factory
    let o_tran_fact = TFramedWriteTransportFactory::new();
    let o_prot_fact = TCompactOutputProtocolFactory::new();

    // create the server and start listening
    let processor = SimpleServiceSyncProcessor::new(SimpleServiceHandlerImpl {});

    // create a pre-threaded server
    let mut server = TLSTServer::new(
        i_tran_fact,
        i_prot_fact,
        o_tran_fact,
        o_prot_fact,
        processor,
        10,
        X509Credentials::new("x509/server.crt", "x509/server.key"),
        Some(cert_store),
        true,
    );

    // set listen address
    let listen_address = "127.0.0.1:9000";
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
