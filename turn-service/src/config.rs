use props_util::Properties;
use turn_proto::config::ProtoConfig;

#[derive(Properties, Debug, Clone)]
#[allow(unused)]
pub struct InstanceConfig {
    #[prop(key = "server_addr")]
    pub server_addr: String,
    // #[prop(key = "server_addr_ipv6")]
    // pub server_addr_ipv6: String,
    #[prop(key = "nonce_max_time", default = "600")]
    pub nonce_max_time: u64,
    #[prop(key = "permission_max_time", default = "300")]
    pub permission_max_time: u64,
    #[prop(key = "max_alloc_time", default = "300")]
    pub max_alloc_time: u32,
    #[prop(key = "session_idle_time", default = "10")]
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
        }
    }
}
