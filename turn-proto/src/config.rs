use props_util::Properties;

#[derive(Properties, Clone, Debug)]
#[allow(unused)]
pub struct ProtoConfig {
    #[prop(key = "max_alloc_time", default = "600")]
    pub max_alloc_time: u32,
    #[prop(key = "permission_max_time", default = "300")]
    pub permission_max_time: u64,
    #[prop(key = "nonce_max_time", default = "600")]
    pub nonce_max_time: u64,
    #[prop(key = "realm", default = "turn-rs")]
    pub realm: String,
}

impl ProtoConfig {}
