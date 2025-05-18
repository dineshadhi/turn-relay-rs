use crate::{
    config::InstanceConfig,
    endpoint::{Endpoint, TurnEndpoint},
    portallocator::{PortAllocator, RandomPortAllocator},
    session::TurnSession,
};
use bytes::Bytes;
use dashmap::DashMap;
use state::{Build, Init};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{Instrument, Level, field, span};
use turn_proto::{config::ProtoConfig, events::InputEvent, wire::error::TurnErrorCode};

macro_rules! ipv4_listener_socket {
    ($port:expr) => {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), $port)
    };
}

macro_rules! ipv6_listener_socket {
    ($port:expr) => {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), $port)
    };
}

pub(crate) type Relays = DashMap<SocketAddr, UnboundedSender<InputEvent<Bytes>>>;

pub trait TurnService: Sync + Send + 'static {
    /// Callback function to obtain the password for the corresponding username.
    fn get_password(&self, username: &str) -> Result<String, TurnErrorCode>;

    /// Checks if a permission can be issued for the given SocketAddr. This is useful to enforce Strict TURN policy ignoring all Permission requests for Server-reflexive or Host address.
    fn check_permission(&self, _: SocketAddr) -> Result<(), TurnErrorCode> {
        Ok(())
    }
}

mod state {
    use crate::{
        config::InstanceConfig,
        endpoint::{TcpEndpoint, UdpEndpoint},
    };

    pub trait State {}

    pub struct Init {
        pub udp: Vec<u16>,
        pub tcp: Vec<u16>,
        pub ipv6: bool,
        pub config: InstanceConfig,
    }

    pub struct Build {
        pub endpoints_tcp: Vec<TcpEndpoint>,
        pub endpoints_udp: Vec<UdpEndpoint>,
        pub config: InstanceConfig,
    }

    impl State for Init {}
    impl State for Build {}
}

// TurnInstance is generic over `TurnService` - a trait that gives an extension to provide credentials and determines the behaviour of TURN implementation
// and PortAllocator - a trait that gives the app freedom to choose and provide ports (convenient to enforce business logic).
#[derive(Debug)]
pub struct TurnInstance<S: TurnService, P: PortAllocator> {
    pub service: S,
    pub allocator: P,
    pub config: InstanceConfig,
    pub proto_config: Arc<ProtoConfig>,
    pub relays: Relays,
}

pub struct AppBuilder<S: state::State = Init> {
    inner: S,
}

impl AppBuilder<Init> {
    pub fn builder(config: InstanceConfig) -> Self {
        Self {
            inner: Init {
                udp: vec![],
                tcp: vec![],
                ipv6: false,
                config,
            },
        }
    }

    pub fn with_udp(mut self, udp: Vec<u16>) -> Self {
        self.inner.udp = udp;
        self
    }

    pub fn with_tcp(mut self, tcp: Vec<u16>) -> Self {
        self.inner.tcp = tcp;
        self
    }

    pub fn with_ipv6(mut self, val: bool) -> Self {
        self.inner.ipv6 = val;
        self
    }

    pub async fn build(self) -> AppBuilder<Build> {
        let mut endpoints_udp = Vec::new();
        for port in self.inner.udp {
            endpoints_udp.push(Endpoint::new(ipv4_listener_socket!(port)).build_udp().unwrap());
            if self.inner.ipv6 {
                endpoints_udp.push(Endpoint::new(ipv6_listener_socket!(port)).build_udp().unwrap());
            }
        }

        let mut endpoints_tcp = Vec::new();
        for port in self.inner.tcp {
            endpoints_tcp.push(Endpoint::new(ipv4_listener_socket!(port)).build_tcp().await.unwrap());
            if self.inner.ipv6 {
                endpoints_tcp.push(Endpoint::new(ipv6_listener_socket!(port)).build_tcp().await.unwrap());
            }
        }

        AppBuilder {
            inner: Build {
                endpoints_tcp,
                endpoints_udp,
                config: self.inner.config,
            },
        }
    }
}

impl AppBuilder<Build> {
    async fn handle_endpoint<T: TurnEndpoint, S: TurnService, P: PortAllocator>(mut endpoint: T, instance: Arc<TurnInstance<S, P>>) {
        tracing::info!("TURN Endpoint Listening : {:?}", endpoint);
        loop {
            match endpoint.accept().await {
                Ok((stream, sid)) => {
                    let session = TurnSession::new(sid, stream, Arc::clone(&instance));
                    let span = span!(Level::INFO, "TurnSession", remote = ?session.sid.remote, local = ?session.sid.local, username = field::Empty, relay_addr = field::Empty);
                    tokio::spawn(async move {
                        let _ = session.run().instrument(span).await;
                    });
                }
                Err(e) => break tracing::error!("Error accepting connection: {:?}", e),
            }
        }
    }

    fn spawn<S: TurnService, P: PortAllocator>(self, service: S, allocator: P) {
        let instance = Arc::new(TurnInstance {
            service,
            allocator,
            config: self.inner.config.clone(),
            proto_config: Arc::new(self.inner.config.into()), // Wrapping with a redundant Arc, because we need to pass it again to TurnNode later
            relays: DashMap::new(),
        });

        for endpoint in self.inner.endpoints_udp {
            let instance = Arc::clone(&instance);
            tokio::spawn(async move { Self::handle_endpoint(endpoint, instance).await });
        }

        for endpoint in self.inner.endpoints_tcp {
            let instance = Arc::clone(&instance);
            tokio::spawn(async move { Self::handle_endpoint(endpoint, instance).await });
        }
    }

    pub fn run<S: TurnService>(self, service: S) {
        self.spawn(service, RandomPortAllocator::new());
    }

    pub fn run_with_allocator<S: TurnService, P: PortAllocator>(self, service: S, allocator: P) {
        self.spawn(service, allocator);
    }
}
