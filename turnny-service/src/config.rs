use std::net::{Ipv4Addr, Ipv6Addr};

use props_util::Properties;
use turn_proto::config::ProtoConfig;

#[derive(Properties, Debug, Clone)]
#[allow(unused)]
pub struct InstanceConfig {
    pub server_addr_v4: Ipv4Addr,
    pub server_addr_v6: Option<Ipv6Addr>,
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
}

impl From<InstanceConfig> for ProtoConfig {
    fn from(val: InstanceConfig) -> Self {
        ProtoConfig {
            max_alloc_time: val.max_alloc_time,
            permission_max_time: val.permission_max_time,
            nonce_max_time: val.nonce_max_time,
            realm: val.realm,
            trusted_turn_ips: vec![val.server_addr_v4.into()],
        }
    }
}
