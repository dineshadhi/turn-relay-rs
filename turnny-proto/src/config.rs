use props_util::Properties;
use std::net::IpAddr;

#[derive(Properties, Clone, Debug)]
#[allow(unused)]
pub struct ProtoConfig {
    #[prop(default = "600")]
    pub max_alloc_time: u32,
    #[prop(default = "300")]
    pub permission_max_time: u64,
    #[prop(default = "600")]
    pub nonce_max_time: u64,
    #[prop(default = "turn-rs")]
    pub realm: String,
    #[prop(key = "trusted_turn_ips")]
    pub trusted_turn_ips: Vec<IpAddr>,
}
