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

use log;
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;

use thrift::protocol::{
    TInputProtocol, TInputProtocolFactory, TOutputProtocol, TOutputProtocolFactory,
};
use thrift::server::TProcessor;
use thrift::transport::{TIoChannel, TReadTransportFactory, TWriteTransportFactory};
use thrift::{ApplicationError, ApplicationErrorKind};

use rustls::ServerSession as RusTLSServerSession;
use rustls::StreamOwned as RusTLSStream;
use rustls::{RootCertStore, ServerConfig, Session};

use super::{TLSStream, TLSTTcpChannel, X509Credentials};

/// Fixed-size thread-pool blocking Thrift server.
///
/// A `TLSTServer` listens on a given address and submits accepted connections
/// to an **unbounded** queue. Connections from this queue are serviced by
/// the first available worker thread from a **fixed-size** thread pool. Each
/// accepted connection is handled by that worker thread, and communication
/// over this thread occurs sequentially and synchronously (i.e. calls block).
/// Accepted connections have an input half and an output half, each of which
/// uses a `TTransport` and `TInputProtocol`/`TOutputProtocol` to translate
/// messages to and from byes. Any combination of `TInputProtocol`, `TOutputProtocol`
/// and `TTransport` may be used.
pub struct TLSTServer<PRC, RTF, IPF, WTF, OPF>
where
    PRC: TProcessor + Send + Sync + 'static,
    RTF: TReadTransportFactory + 'static,
    IPF: TInputProtocolFactory + 'static,
    WTF: TWriteTransportFactory + 'static,
    OPF: TOutputProtocolFactory + 'static,
{
    r_trans_factory: RTF,
    i_proto_factory: IPF,
    w_trans_factory: WTF,
    o_proto_factory: OPF,
    processor: Arc<PRC>,
    worker_pool: ThreadPool,
    tls_config: Arc<ServerConfig>,
}

impl<PRC, RTF, IPF, WTF, OPF> TLSTServer<PRC, RTF, IPF, WTF, OPF>
where
    PRC: TProcessor + Send + Sync + 'static,
    RTF: TReadTransportFactory + 'static,
    IPF: TInputProtocolFactory + 'static,
    WTF: TWriteTransportFactory + 'static,
    OPF: TOutputProtocolFactory + 'static,
{
    /// Create a `TLSTServer`.
    ///
    /// Each accepted connection has an input and output half, each of which
    /// requires a `TTransport` and `TProtocol`. `TLSTServer` uses
    /// `read_transport_factory` and `input_protocol_factory` to create
    /// implementations for the input, and `write_transport_factory` and
    /// `output_protocol_factory` to create implementations for the output.
    pub fn new(
        read_transport_factory: RTF,
        input_protocol_factory: IPF,
        write_transport_factory: WTF,
        output_protocol_factory: OPF,
        processor: PRC,
        num_workers: usize,
        key_pair: X509Credentials,
        root_cert_store: Option<RootCertStore>,
        require_client_auth: bool,
    ) -> TLSTServer<PRC, RTF, IPF, WTF, OPF> {
        TLSTServer {
            r_trans_factory: read_transport_factory,
            i_proto_factory: input_protocol_factory,
            w_trans_factory: write_transport_factory,
            o_proto_factory: output_protocol_factory,
            processor: Arc::new(processor),
            worker_pool: ThreadPool::with_name("Thrift service processor".to_owned(), num_workers),
            tls_config: super::make_tls_server_config(
                key_pair,
                root_cert_store,
                require_client_auth,
            ),
        }
    }

    /// Listen for incoming connections on `listen_address`.
    ///
    /// `listen_address` should be in the form `host:port`,
    /// for example: `127.0.0.1:8080`.
    ///
    /// Return `()` if successful.
    ///
    /// Return `Err` when the server cannot bind to `listen_address` or there
    /// is an unrecoverable error.
    pub fn listen(&mut self, listen_address: &str) -> thrift::Result<()> {
        let listener = TcpListener::bind(listen_address)?;
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let tls_session = RusTLSServerSession::new(&self.tls_config);
                    let mut so = RusTLSStream::new(tls_session, s);
                    so.flush().unwrap(); // Execute the TLS handshake
                    log::debug!("connection from client: {}", so.sock.peer_addr().unwrap());
                    log::debug!(
                        "TLS Protocol version: {:?}",
                        so.sess.get_protocol_version().unwrap()
                    );
                    log::debug!(
                        "TLS Negotiated Cipersuite: {:?}",
                        so.sess.get_negotiated_ciphersuite().unwrap()
                    );
                    let ts = Arc::new(Mutex::new(so));
                    let (i_prot, o_prot) = self.new_protocols_for_connection(ts)?;
                    let processor = self.processor.clone();
                    self.worker_pool
                        .execute(move || handle_incoming_connection(processor, i_prot, o_prot));
                }
                Err(e) => {
                    log::warn!("failed to accept remote connection with error {:?}", e);
                }
            }
        }

        Err(thrift::Error::Application(ApplicationError {
            kind: ApplicationErrorKind::Unknown,
            message: "aborted listen loop".into(),
        }))
    }

    fn new_protocols_for_connection(
        &mut self,
        stream: TLSStream<RusTLSServerSession>,
    ) -> thrift::Result<(
        Box<dyn TInputProtocol + Send>,
        Box<dyn TOutputProtocol + Send>,
    )> {
        // create the shared tcp stream
        let channel = TLSTTcpChannel::with_stream(stream);

        // split it into two - one to be owned by the
        // input tran/proto and the other by the output
        let (r_chan, w_chan) = channel.split()?;

        // input protocol and transport
        let r_tran = self.r_trans_factory.create(Box::new(r_chan));
        let i_prot = self.i_proto_factory.create(r_tran);

        // output protocol and transport
        let w_tran = self.w_trans_factory.create(Box::new(w_chan));
        let o_prot = self.o_proto_factory.create(w_tran);

        Ok((i_prot, o_prot))
    }
}

fn handle_incoming_connection<PRC>(
    processor: Arc<PRC>,
    i_prot: Box<dyn TInputProtocol>,
    o_prot: Box<dyn TOutputProtocol>,
) where
    PRC: TProcessor,
{
    let mut i_prot = i_prot;
    let mut o_prot = o_prot;
    loop {
        let r = processor.process(&mut *i_prot, &mut *o_prot);
        if let Err(e) = r {
            log::debug!("processor completed with error: {:?}", e);
            break;
        }
    }
}
