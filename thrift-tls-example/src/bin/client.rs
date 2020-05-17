use log;
use std::fs::File;
use std::io::BufReader;

use rust_thrift_tls::{KeyPair, TLSTTcpChannel};
use rustls::RootCertStore;
use thrift::protocol::{TCompactInputProtocol, TCompactOutputProtocol};
use thrift::transport::{TFramedReadTransport, TFramedWriteTransport, TIoChannel};

use thrift_tls_example::{SimpleServiceSyncClient, TSimpleServiceSyncClient};

fn main() {
    env_logger::init();
    log::info!("starting up");

    match run() {
        Ok(()) => log::info!("client ran successfully"),
        Err(e) => {
            log::error!("client failed with error {:?}", e);
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

    let mut c = TLSTTcpChannel::new();
    let key_pair = KeyPair {
        cert_file: "x509/client.crt",
        key_file: "x509/client.key",
    };
    c.open("localhost:9000", Some(key_pair), Some(cert_store))?;
    let (i_chan, o_chan) = c.split()?;

    // build the input/output protocol
    let i_prot = TCompactInputProtocol::new(TFramedReadTransport::new(i_chan));
    let o_prot = TCompactOutputProtocol::new(TFramedWriteTransport::new(o_chan));

    // use the input/output protocol to create a Thrift client
    let mut client = SimpleServiceSyncClient::new(i_prot, o_prot);

    // make service calls
    let res = client.hello("Davide".to_owned())?;
    log::info!("{}", res);

    // done!
    Ok(())
}
