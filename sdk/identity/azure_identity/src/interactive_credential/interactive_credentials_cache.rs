#[derive(Debug)]
pub struct IdTokenCache {
    pub oid: String,
    pub tid: String,
    pub scopes: Vec<String>,
}
