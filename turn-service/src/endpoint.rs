use crate::session::{Protocol, SessionID};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use std::{
    fmt::Debug,
    io::{self, Error},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc::{self, UnboundedSender, error::SendError},
    time::{error::Elapsed, timeout},
};

#[derive(Error, Debug)]
pub enum EndpointError {
    #[error("IO Error {0}")]
    AcceptError(#[from] io::Error),

    #[error("UDP Send Error {0}")]
    SendError(#[from] SendError<Bytes>),
}

#[async_trait]
pub trait TurnEndpoint: Debug {
    async fn accept(&mut self) -> Result<(EndpointStream, SessionID), EndpointError>;
}

#[derive(Debug)]
pub struct Endpoint {
    listen_addr: SocketAddr,
}

impl Endpoint {
    pub fn new(listen_addr: SocketAddr) -> Endpoint {
        Endpoint { listen_addr }
    }

    pub async fn build_tcp(self) -> Result<TcpEndpoint, io::Error> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        Ok(TcpEndpoint::new(listener))
    }

    pub fn build_udp(self) -> Result<UdpEndpoint, io::Error> {
        let socket = std::net::UdpSocket::bind(self.listen_addr)?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        Ok(UdpEndpoint::new(socket))
    }
}

#[derive(Debug)]
pub enum EndpointStream {
    Tcp(TcpStream),
    Udp(mpsc::UnboundedReceiver<Bytes>, Arc<UdpSocket>, SocketAddr),
}

impl EndpointStream {
    /// Cancel Safety : This method is cancel safe because the underlying inner functions `read_buf` and `recv()` are cancel safe
    pub async fn read(&mut self) -> Result<Option<Bytes>, io::Error> {
        match self {
            Self::Tcp(stream) => {
                let mut buffer = BytesMut::with_capacity(2048);
                match stream.read_buf(&mut buffer).await {
                    Ok(0) => Ok(None), // Disconnected,
                    Ok(n) => Ok(Some(buffer.split_to(n).freeze())),
                    Err(e) => Err(e)?,
                }
            }
            Self::Udp(recv, _, _) => Ok(recv.recv().await),
        }
    }

    pub async fn read_with_timeout(&mut self, duration: Duration) -> Result<Result<Option<Bytes>, io::Error>, Elapsed> {
        timeout(duration, self.read()).await
    }

    pub async fn write<B: Buf>(&mut self, mut data: B) -> Result<(), Error> {
        match self {
            Self::Tcp(stream) => stream.write_all_buf(&mut data).await?,
            Self::Udp(_, socket, remote) => {
                while data.has_remaining() {
                    let n = socket.send_to(data.chunk(), *remote).await?;
                    data.advance(n);
                }
            }
        };
        Ok(())
    }
}

#[derive(Debug)]
pub struct TcpEndpoint {
    pub listener: TcpListener,
}

impl TcpEndpoint {
    fn new(listener: TcpListener) -> Self {
        Self { listener }
    }
}

#[derive(Debug)]
pub struct UdpEndpoint {
    pub socket: Arc<UdpSocket>,
    pub senders: DashMap<SessionID, UnboundedSender<Bytes>>,
}

impl UdpEndpoint {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            senders: DashMap::new(),
        }
    }
}

#[async_trait]
impl TurnEndpoint for TcpEndpoint {
    async fn accept(&mut self) -> Result<(EndpointStream, SessionID), EndpointError> {
        let (stream, remote) = self.listener.accept().await?;
        let sid = SessionID {
            local: self.listener.local_addr()?,
            remote,
            protocol: Protocol::TCP,
        };
        Ok((EndpointStream::Tcp(stream), sid))
    }
}

#[async_trait]
impl TurnEndpoint for UdpEndpoint {
    // An attempt to make UDP Datagrams behave like TCP Accept. This makes it little convenient to handle endpoints
    // without worrying about underlying protocol.
    // TODO : Need more testing.
    // NOTE : accept() must be polled in loop continously for this to work on UDP. If not, no new packets will be read by the UDPSocket.
    async fn accept(&mut self) -> Result<(EndpointStream, SessionID), EndpointError> {
        loop {
            let mut buffer = BytesMut::with_capacity(2048);
            let (len, remote) = self.socket.recv_buf_from(&mut buffer).await?;
            let sid = SessionID {
                local: self.socket.local_addr()?,
                remote,
                protocol: Protocol::UDP,
            };

            let data = buffer.split_to(len).freeze();
            let mut closed = false;

            // Find the Sender for the SessionID and send the data, if the channel is closed or does not exist, create a new one and send it.
            'sender: loop {
                if let (Some(sender), false) = (self.senders.get(&sid), closed) {
                    if !sender.is_closed() {
                        sender.send(data)?; // Send Data if the channel is not closed.
                        break 'sender;
                    }
                    closed = true; // else mark it as closed. Hopefully, in the next iteration, new session will created.
                } else {
                    let (send, recv) = mpsc::unbounded_channel::<Bytes>();
                    send.send(data)?;
                    let _ = self.senders.insert(sid.clone(), send);
                    let stream = EndpointStream::Udp(recv, Arc::clone(&self.socket), remote);
                    return Ok((stream, sid));
                }
            }
        }
    }
}
