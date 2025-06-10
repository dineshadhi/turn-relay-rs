use clap::Parser;
use opentelemetry::{global, trace::TracerProvider};
use props_util::Properties;
use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use turnny_service::{
    config::InstanceConfig,
    error::TurnErrorCode,
    instance::{Instance, TurnService},
};

#[derive(Debug)]
pub struct CustomTurnService {}

impl TurnService for CustomTurnService {
    fn get_password(&self, _username: &str) -> Result<String, TurnErrorCode> {
        Ok("test".into())
    }
}

pub fn setup_tracing() -> anyhow::Result<()> {
    let resource = opentelemetry_sdk::Resource::builder().with_service_name("turnny-rs").build();
    let exporter = opentelemetry_otlp::SpanExporter::builder().with_tonic().build()?; // Build a Span Exporter. Exports the Traces and Spans via GRPC.

    // A Provider that batches the spans and uses the exporter
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone()); // Setting the provider as global provider
    let tracer = provider.tracer("turnny-rs"); // Make sure all the traces are attached to the subsriber

    // This outputs the traces in the terminal
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    Ok(())
}

pub fn setup_metrics() -> anyhow::Result<()> {
    let resource = opentelemetry_sdk::Resource::builder().with_service_name("turn-rs").build();
    let exporter = opentelemetry_otlp::MetricExporter::builder().with_tonic().build()?;

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(exporter)
        .build();

    global::set_meter_provider(provider.clone());

    Ok(())
}

#[derive(Properties, Debug, Clone)]
struct ServerConfig {
    #[prop(env = "TURNNY_SERVER_ADDR")]
    pub server_addr: Ipv4Addr,
    #[prop(env = "TURNNY_SERVER_ADDR_V6")]
    pub server_addr_v6: Option<Ipv6Addr>,
    #[prop(env = "TURNNY_REALM", default = "turn-rs")]
    pub realm: String,
    #[prop(env = "TURNNY_UDP_PORTS", default = "3478")]
    pub udp_ports: Vec<u16>,
    #[prop(env = "TURNNY_TCP_PORTS", default = "3478")]
    pub tcp_ports: Vec<u16>,
    #[prop(env = "TURNNY_ISC_PORT")]
    pub isc_port: Option<u16>,
    #[prop(env = "TURNNY_IPV6", default = "true")]
    pub ipv6: bool,
    #[prop(default = "600")]
    pub nonce_max_time: u64,
    #[prop(default = "300")]
    pub permission_max_time: u64,
    #[prop(default = "300")]
    pub max_alloc_time: u32,
    #[prop(default = "100")]
    pub session_idle_time: u64,
}

#[derive(Parser, Debug)]
struct TurnArgs {
    #[arg(long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing().unwrap();
    setup_metrics().unwrap();

    let args = TurnArgs::parse();
    let config = match args.config {
        Some(config) => config,
        None => std::env::var("TURN_SERVER_CONFIG").unwrap_or("./turnserver.conf".into()),
    };

    let config = ServerConfig::from_file(&config).expect("Unable to load config : {config}");
    let service = CustomTurnService {};

    tracing::info!("Server Config : {:?}", config.clone());

    Instance::builder(InstanceConfig::from(config.clone())?)
        .with_udp(config.udp_ports.clone())
        .with_tcp(config.tcp_ports.clone())
        .with_isc(config.isc_port)
        .with_ipv6(config.ipv6)
        .build()
        .await?
        .run(service);

    tokio::signal::ctrl_c().await?;
    Ok(())
}
