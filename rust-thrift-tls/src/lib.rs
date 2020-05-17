pub mod tls_socket;
pub mod tls_threaded;

pub use tls_socket::*;
pub use tls_threaded::*;

use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, Certificate, ClientConfig,
    KeyLogFile, NoClientAuth, PrivateKey, RootCertStore, ServerConfig,
};

pub struct KeyPair<'a> {
    pub cert_file: &'a str,
    pub key_file: &'a str,
}

fn load_certs(filename: &str) -> Vec<Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn make_tls_client_config(
    key_pair: Option<KeyPair>,
    root_cert_store: Option<RootCertStore>,
) -> Arc<ClientConfig> {
    let mut config = ClientConfig::new();
    config.key_log = Arc::new(KeyLogFile::new());

    if let Some(kp) = key_pair {
        let certs = load_certs(kp.cert_file);
        let privkey = load_private_key(kp.key_file);
        config
            .set_single_client_cert(certs, privkey)
            .expect("bad certificates/private key");
    }

    if let Some(rcs) = root_cert_store {
        config.root_store = rcs;
    } else {
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }

    Arc::new(config)
}

fn make_tls_server_config(
    key_pair: KeyPair,
    root_cert_store: Option<RootCertStore>,
    require_client_auth: bool,
) -> Arc<ServerConfig> {
    let client_auth = match root_cert_store {
        Some(rcs) => {
            if require_client_auth {
                AllowAnyAuthenticatedClient::new(rcs)
            } else {
                AllowAnyAnonymousOrAuthenticatedClient::new(rcs)
            }
        }
        None => NoClientAuth::new(),
    };

    let mut config = rustls::ServerConfig::new(client_auth);
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let certs = load_certs(key_pair.cert_file);
    let privkey = load_private_key(key_pair.key_file);
    config
        .set_single_cert(certs, privkey)
        .expect("bad certificates/private key");

    Arc::new(config)
}
