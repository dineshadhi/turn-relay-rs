use opentelemetry::{global, trace::TracerProvider};
use std::{collections::HashMap, fmt::Debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use turn_service::{
    config::InstanceConfig,
    error::TurnErrorCode,
    instance::{AppBuilder, TurnService},
};

#[derive(Debug)]
pub struct CustomTurnService {}

impl TurnService for CustomTurnService {
    fn get_password(&self, username: &str) -> Result<String, TurnErrorCode> {
        match username {
            "dinesh" => Ok("test".into()),
            "boose" => Ok("dumeel".into()),
            _ => panic!("{}", username),
        }
    }
}

pub fn setup_tracing() -> anyhow::Result<()> {
    let resource = opentelemetry_sdk::Resource::builder().with_service_name("turn-rs").build();

    // Build a Span Exporter. Exports the Traces and Spans via GRPC.
    let exporter = opentelemetry_otlp::SpanExporter::builder().with_tonic().build()?;
    // A Provider that batches the spans and uses the exporter
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    // Setting the provider as global provider
    global::set_tracer_provider(provider.clone());

    // Make sure all the traces are attached to the subsriber
    let tracer = provider.tracer("turn-rs");
    // This outputs the traces in the terminal
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer));

    subscriber.init();

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing().unwrap();
    setup_metrics().unwrap();

    let service = CustomTurnService {};
    let mut hm = HashMap::new();
    hm.insert("server_addr", "69.69.69.69");

    let config = InstanceConfig::from_hash_map(&hm).unwrap();
    let app = AppBuilder::builder(config).with_udp(vec![3000]).with_tcp(vec![3000]).build().await;
    app.run(service);

    tokio::signal::ctrl_c().await.unwrap();
    Ok(())
}
