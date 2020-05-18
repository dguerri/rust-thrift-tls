pub mod tls_socket;
pub mod tls_threaded;

pub use tls_socket::*;
pub use tls_threaded::*;

use std::ffi::OsString;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, Certificate, ClientConfig,
    KeyLogFile, NoClientAuth, PrivateKey, RootCertStore, ServerConfig,
};
use webpki_roots;

#[derive(Debug)]
pub struct X509Credentials {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

impl X509Credentials {
    pub fn new(certs_file: &OsString, key_file: &OsString) -> X509Credentials {
        X509Credentials {
            certs: load_certs(certs_file),
            key: load_private_key(key_file),
        }
    }
}

fn load_certs(filename: &OsString) -> Vec<Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &OsString) -> PrivateKey {
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
    key_pair: Option<X509Credentials>,
    root_cert_store: Option<RootCertStore>,
) -> Arc<ClientConfig> {
    let mut config = ClientConfig::new();
    config.key_log = Arc::new(KeyLogFile::new());

    if let Some(kp) = key_pair {
        config
            .set_single_client_cert(kp.certs, kp.key)
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
    key_pair: X509Credentials,
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

    config
        .set_single_cert(key_pair.certs, key_pair.key)
        .expect("bad certificates/private key");

    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use pem_parser;
    use std::io::{self, Write};
    use tempfile::NamedTempFile;
    use webpki_roots;

    use super::*;

    const PEM_CA_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIICADCCAaoCCQC9bBNLH4836TANBgkqhkiG9w0BAQsFADCBhjEdMBsGA1UEAwwU
RG8gTm90IFRydXN0IFRoaXMgQ0ExCzAJBgNVBAYTAlVLMRAwDgYDVQQIDAdFbmds
YW5kMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoMBE5vbmUxJjAkBgkqhkiG9w0B
CQEWF2RhdmlkZS5ndWVycmlAZ21haWwuY29tMB4XDTIwMDUxODE3MjIyNVoXDTIz
MDMwODE3MjIyNVowgYYxHTAbBgNVBAMMFERvIE5vdCBUcnVzdCBUaGlzIENBMQsw
CQYDVQQGEwJVSzEQMA4GA1UECAwHRW5nbGFuZDEPMA0GA1UEBwwGTG9uZG9uMQ0w
CwYDVQQKDAROb25lMSYwJAYJKoZIhvcNAQkBFhdkYXZpZGUuZ3VlcnJpQGdtYWls
LmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDiONU03BbXrt703kwjBXtqXhPK
yY3bpHgWIrRSBTTdA/PeAO1UWIMecwRibZNVUZLqzmyo87SJugBX+WlKByOpAgMB
AAEwDQYJKoZIhvcNAQELBQADQQCccYOh+tx9V3C/x/shtlPA7hYcxu/KqJjiXa+X
elvt5HZZojCpjXV1JRhWyS5Xr4pJx+oCL2XZPvkRvC04k5Sn
-----END CERTIFICATE-----";

    const PEM_SERVER_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIICQDCCAeqgAwIBAgIJANCyXuBQtdx8MA0GCSqGSIb3DQEBCwUAMIGGMR0wGwYD
VQQDDBREbyBOb3QgVHJ1c3QgVGhpcyBDQTELMAkGA1UEBhMCVUsxEDAOBgNVBAgM
B0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRvbjENMAsGA1UECgwETm9uZTEmMCQGCSqG
SIb3DQEJARYXZGF2aWRlLmd1ZXJyaUBnbWFpbC5jb20wHhcNMjAwNTE4MTcyMjI1
WhcNMjEwNTE4MTcyMjI1WjB7MRIwEAYDVQQDDAlsb2NhbGhvc3QxCzAJBgNVBAYT
AlVLMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoM
BE5vbmUxJjAkBgkqhkiG9w0BCQEWF2RhdmlkZS5ndWVycmlAZ21haWwuY29tMFww
DQYJKoZIhvcNAQEBBQADSwAwSAJBAOQy2bdlCXUuauC0GfEqFLPyWEnNgQ5yrwhX
pAw//mCO0qFIyFXN4JpWVKjKierLKiy3K79nUOs9lK7nrK6fXl8CAwEAAaNFMEMw
CQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYD
VR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA0EAx85ygDKhjALI2NsA
DbNbPrGzi99lraho4xoD5m693054sEbecIlKsVwJXxeQUK0WGbERzwC2208aTTNB
8oZfZA==
-----END CERTIFICATE-----";

    const PEM_KEY: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwFy6nDQXikXYQu8+SxF9MHW6fpGfwLZHWeHSGRnIgA+Vaqq7
P0VILbpAeki/lmEclkwyOhDbjVYAsOJIFm3GY6VYNEwB8yiwg7JO8/MEwo2afSMK
9LaBRddAQa0+bUu3bkVht9bledhPGFlg3p7D8Aq+Jn/P9976tXCUrrsvDqPbGZEY
QkeQ5EVoQ5Fr4jRAkxEjM4PKLT2fxrCzQWo+tUV4ZGLvkK+nm3Yp4/6KFFBKDi+K
NrCDLDnwkJVAUQFNGGIPF/+JKaLq2RWPKh2URXs+bwZRNWGt1+KVYKNVB4VGkC/n
SI+na4XMoHAeCILRIK6CoeIHZMIEp+zTYzzBCQIDAQABAoIBAQC0gQ8W7oa8WIfz
Xz5MANBBfeePRyTqF+FiRVX5+ci76mOh4S2t1FxDlIdWeBdXjC7gFgX3mMP8nxws
31kXutCzxn67LCuUObVRDyupHHx195xlGlH4iZ1KpQ6F0oRG2Qr6LZ7hfIR+zmyC
A7SzkbV49QuzYrIK/TCyuz65q6ofiB7nzT8kwaC9pKhwhb3YH4IMg3O2hSiAVTW8
KZK6xb2meKYUwpw/BEFSQJyHVlGNmjkKMOW7dbuZbkqLokr8hBTF1edyz9fQ1Z9N
KQKkS6xW/FiEVAKaleIHoYrETQL402iRIy5riWC6eUFOE5Gwf3rnkXyhRuUtRJZr
9MGb0Vd1AoGBAO2vfPnFsqfhWUu0fnbo6i2/13zGCDbzPzSTWVnXMoocDta0Xa8C
BZiwyoWCc74bGVsiLI1e++3KAjjGxNifsbzsVDRFJXXM3A5ILv9iW45hyWyQepvW
t4GJ+7jbd00IE1jeiJUXfRwmDznC0gn4tug4Gi8qg4/4ygXTGqrP/tVXAoGBAM8v
NSOAuHALGK2ekCbZUltXUCUcOa2FW8LTd2QNuOeYm8oj1/ClPcLxgY6cGdodaC01
T4NIdhugBwWDKvS5npWhPyqK42OuT9RsqpFwoy2aoE8XjZtkMwGM102oVgypLXpV
AMtH0I7tSWZdKpYkB/1o/fGjHz+NVJcJsSUlk8CfAoGBAIcf/0LYW+sJOATMBiF/
5LJBoDY1NzJWM5amNmPW7cqKjP0O6Tu3QIs/5sLkGPz41v9yfDWazEqxT3YLupkU
oK0xBeX5cYR5BJmx+9YAiuB1Q1fPA4VZGlYwpcTAMCDA+I7LZIauJdg84ucJlPNK
TGHUkz5BQy40WFXbYAu/17ZdAoGAU00ZwnKItZPgkj4Em3oZYNxUPveAQUIzSLwZ
bsMNqyBy0u1ib0Eg+fZ8LsiYpFfagQLEO3aw9h57dD3u0YKoPmUcrpA1KOj28+PV
GLD/CuD2v5Yqu2WoFGF6V6DtKB4FSQBQV2tCcZT6RAwFiWRnSf4izDrX34eFkUy2
Ssc3BuUCgYBXZ426GlSB58Lzy2zUMlFsen2F/vwfIqaxParPHemJ++rwrbtyRvuP
F8D7y25oZ7hwzLEKXS/ezuQnLAScqI3cYow+Ff+bJ2m7fHunBcEyFbSYjIJX6rm7
FBb23qfrJDhcsJ8vi+WO8Jrc5vG5crIKZTG+tmjFt7xU861fraZc6Q==
-----END RSA PRIVATE KEY-----";

    #[test]
    fn x509_credentials_new_test() -> io::Result<()> {
        let mut certs_file = NamedTempFile::new()?;
        writeln!(certs_file, "{}", PEM_CA_CERT)?;
        writeln!(certs_file, "{}", PEM_SERVER_CERT)?;

        let mut key_file = NamedTempFile::new()?;
        writeln!(key_file, "{}", PEM_KEY)?;

        let x509_credentials = X509Credentials::new(
            &certs_file.into_temp_path().to_path_buf().into_os_string(),
            &key_file.into_temp_path().to_path_buf().into_os_string(),
        );

        let der_ca_cert = pem_parser::pem_to_der(PEM_CA_CERT);
        let der_server_cert = pem_parser::pem_to_der(PEM_SERVER_CERT);
        let der_key = pem_parser::pem_to_der(PEM_KEY);

        assert_eq!(der_key, x509_credentials.key.0);
        assert_eq!(der_ca_cert, x509_credentials.certs[0].0);
        assert_eq!(der_server_cert, x509_credentials.certs[1].0);

        Ok(())
    }

    #[test]
    fn load_certs_test() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", PEM_CA_CERT)?;
        writeln!(file, "{}", PEM_SERVER_CERT)?;

        let certs: Vec<Certificate> =
            load_certs(&file.into_temp_path().to_path_buf().into_os_string());

        assert_eq!(2, certs.len(), "unexpected number of certificates loaded");

        Ok(())
    }

    #[test]
    fn load_key_test() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", PEM_KEY)?;

        let key: PrivateKey =
            load_private_key(&file.into_temp_path().to_path_buf().into_os_string());

        assert_eq!(1192, key.0.len(), "unexpected key len");

        Ok(())
    }

    #[test]
    fn make_tls_client_config_test_embedded_roots() -> io::Result<()> {
        let mut certs_file = NamedTempFile::new()?;
        writeln!(certs_file, "{}", PEM_CA_CERT)?;
        writeln!(certs_file, "{}", PEM_SERVER_CERT)?;

        let mut key_file = NamedTempFile::new()?;
        writeln!(key_file, "{}", PEM_KEY)?;

        let x509_creds = X509Credentials::new(
            &certs_file.into_temp_path().to_path_buf().into_os_string(),
            &key_file.into_temp_path().to_path_buf().into_os_string(),
        );

        let tls_client_config = make_tls_client_config(Some(x509_creds), None);

        assert_eq!(
            tls_client_config.root_store.len(),
            webpki_roots::TLS_SERVER_ROOTS.0.len()
        );

        Ok(())
    }
}
