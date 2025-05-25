use props_util::Properties;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Properties, Debug, Clone)]
#[allow(unused)]
pub struct InstanceConfig {
    pub server_addr: Ipv4Addr,
    pub server_addr_v6: Option<Ipv6Addr>,
    #[prop(default = "8443")]
    pub grpc_port: u16,
    #[prop(default = "600")]
    pub nonce_max_time: u64,
    #[prop(default = "300")]
    pub permission_max_time: u64,
    #[prop(default = "300")]
    pub max_alloc_time: u32,
    #[prop(default = "100")]
    pub session_idle_time: u64,
    #[prop(default = "turn-rs")]
    pub realm: String,
    #[prop(default = "")]
    pub trusted_turn_ips: Vec<IpAddr>,
}
