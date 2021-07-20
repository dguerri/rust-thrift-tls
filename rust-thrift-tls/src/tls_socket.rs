// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};

use thrift::transport::{ReadHalf, TIoChannel, WriteHalf};
use thrift::{new_transport_error, TransportErrorKind};

use rustls::StreamOwned as RusTLSStream;
use rustls::{ClientSession, RootCertStore, ServerSession, Session};
use webpki;

use super::X509Credentials;

pub type TLSStream<S> = Arc<Mutex<RusTLSStream<S, TcpStream>>>;

/// Bidirectional TCP/IP channel.
///
pub struct TLSTTcpChannel<S>
where
    S: Session,
{
    stream: Option<TLSStream<S>>,
    shutdown: Shutdown,
}

impl<S> TLSTTcpChannel<S>
where
    S: Session,
{
    /// Create an uninitialized `TLSTTcpChannel`.
    ///
    /// The returned instance must be opened using `TLSTTcpChannel::open(...)`
    /// before it can be used.
    pub fn new() -> TLSTTcpChannel<S> {
        TLSTTcpChannel {
            stream: None,
            shutdown: Shutdown::Both,
        }
    }

    /// Create a `TLSTTcpChannel` from an existing TLSStream<S>.
    ///
    /// The returned instance must be opened using `TLSTTcpChannel::open(...)`
    /// before it can be used.
    pub fn with_stream(stream: TLSStream<S>) -> TLSTTcpChannel<S> {
        TLSTTcpChannel {
            stream: Option::from(stream),
            shutdown: Shutdown::Both,
        }
    }

    /// Shut down this channel.
    ///
    /// Both send and receive halves are closed, and this instance can no
    /// longer be used to communicate with another endpoint.
    pub fn close(&mut self) -> thrift::Result<()> {
        let shutdown_direction = self.shutdown;
        self.if_set(|s| s.get_mut().shutdown(shutdown_direction))
            .map_err(From::from)
    }

    fn if_set<F, T>(&mut self, mut stream_operation: F) -> io::Result<T>
    where
        F: FnMut(&mut RusTLSStream<S, TcpStream>) -> io::Result<T>,
    {
        if let Some(ref mut s) = self.stream {
            stream_operation(&mut s.lock().unwrap())
        } else {
            Err(io::Error::new(
                ErrorKind::NotConnected,
                "tcp endpoint not connected",
            ))
        }
    }
}

impl TLSTTcpChannel<ServerSession> {
    /// Create a `TLSTTcpChannel` that wraps an existing `TLSStream`.
    ///
    /// The passed-in stream is assumed to have been opened before being wrapped
    /// by the created `TLSTTcpChannel` instance.
    pub fn with_stream(stream: TLSStream<ServerSession>) -> TLSTTcpChannel<ServerSession> {
        TLSTTcpChannel {
            stream: Some(stream),
            shutdown: Shutdown::Both,
        }
    }
}

impl TLSTTcpChannel<ClientSession> {
    /// Connect to `remote_address`, which should have the form `host:port`.
    /// Client authentication can be enabled by passing a `rust_thrift_tls::X509Credentials`
    /// By Default `webpki_roots::TLS_SERVER_ROOTS` is used to validate server certs
    /// that can be overrode by passing a cusrom `rustls::RootCertStore`
    pub fn open(
        &mut self,
        remote_address: &str,
        key_pair: Option<X509Credentials>,
        root_cert_store: Option<RootCertStore>,
    ) -> thrift::Result<()> {
        if self.stream.is_some() {
            Err(new_transport_error(
                TransportErrorKind::AlreadyOpen,
                "TLS session connection previously opened",
            ))
        } else {
            let tsap: Vec<&str> = remote_address.rsplit(':').collect();
            if tsap.len() != 2 {
                return Err(new_transport_error(
                    TransportErrorKind::Unknown,
                    format!("Invalid remote address: '{}'", remote_address),
                ));
            }

            let dns_name = match webpki::DNSNameRef::try_from_ascii_str(tsap[1]) {
                Ok(dns_nameref) => dns_nameref,
                Err(e) => {
                    return Err(new_transport_error(
                        TransportErrorKind::Unknown,
                        format!("Invalid DNS name: '{}'", e),
                    ))
                }
            };
            let config = super::make_tls_client_config(key_pair, root_cert_store);

            let sess = ClientSession::new(&config, dns_name);
            let sock = TcpStream::connect(remote_address).unwrap();
            self.stream = Some(Arc::new(Mutex::new(RusTLSStream::new(sess, sock))));

            Ok(())
        }
    }
}

impl<S> TIoChannel for TLSTTcpChannel<S>
where
    S: Session,
{
    fn split(self) -> thrift::Result<(ReadHalf<Self>, WriteHalf<Self>)>
    where
        Self: Sized,
    {
        if let Some(stream) = self.stream {
            let read_half = ReadHalf::new(TLSTTcpChannel {
                stream: Some(stream.clone()),
                shutdown: Shutdown::Read,
            });
            let write_half = WriteHalf::new(TLSTTcpChannel {
                stream: Some(stream),
                shutdown: Shutdown::Write,
            });
            Ok((read_half, write_half))
        } else {
            Err(new_transport_error(
                TransportErrorKind::Unknown,
                "cannot clone underlying tcp stream",
            ))
        }
    }
}

impl<S> Read for TLSTTcpChannel<S>
where
    S: Session,
{
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.if_set(|s| s.read(b))
    }
}

impl<S> Write for TLSTTcpChannel<S>
where
    S: Session,
{
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.if_set(|s| s.write(b))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.if_set(|s| s.flush())
    }
}
