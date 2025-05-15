use std::net::Ipv4Addr;

use props_util::Properties;
use turn_proto::config::ProtoConfig;

#[derive(Properties, Debug, Clone)]
#[allow(unused)]
pub struct InstanceConfig {
    #[prop(key = "server_addr_v4")]
    pub server_addr_v4: Ipv4Addr,
    // #[prop(key = "server_addr_v6")]
    // pub server_addr_ipv6: Ipv6Addr,
    #[prop(key = "nonce_max_time", default = "600")]
    pub nonce_max_time: u64,
    #[prop(key = "permission_max_time", default = "300")]
    pub permission_max_time: u64,
    #[prop(key = "max_alloc_time", default = "300")]
    pub max_alloc_time: u32,
    #[prop(key = "session_idle_time", default = "100")]
    pub session_idle_time: u64,
    #[prop(key = "realm", default = "turn-rs")]
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
