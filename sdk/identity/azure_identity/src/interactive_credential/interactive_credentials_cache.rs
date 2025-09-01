use async_lock::RwLock;
use azure_core::credentials::AccessToken;
use azure_core::time::{Duration, OffsetDateTime};
use std::{
    collections::HashMap,
    future::Future,
    hash::{Hash, Hasher},
};
use tracing::trace;

#[derive(Debug)]
pub struct IdTokenCache {
    pub oid: String,
    pub tid: String,
    pub scopes: Vec<String>,
}

impl PartialEq for IdTokenCache {
    fn eq(&self, other: &Self) -> bool {
        let self_scopes = self
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let other_scopes = other
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        self.oid.eq(&other.oid) && self.tid.eq(&other.tid) && self_scopes.eq(&other_scopes)
    }
}

impl Hash for IdTokenCache {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let self_scopes = self
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        self.oid.hash(state);
        self.tid.hash(state);
        self_scopes.hash(state);
    }
}

impl Eq for IdTokenCache {}

impl IdTokenCache {
    fn new(oid: String, tid: String, scopes: Vec<String>) -> Self {
        IdTokenCache { oid, tid, scopes }
    }
}

#[derive(Debug)]
pub(crate) struct TokenCache(RwLock<HashMap<IdTokenCache, AccessToken>>);

impl TokenCache {
    pub(crate) fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    #[allow(dead_code)]
    pub(crate) async fn clear(&self) -> azure_core::Result<()> {
        let mut token_cache = self.0.write().await;
        token_cache.clear();
        Ok(())
    }

    pub(crate) async fn get_token(
        &self,
        scopes: &[&str],
        oid: String,
        tid: String,
        callback: impl Future<Output = azure_core::Result<(AccessToken, String, String)>>,
    ) -> azure_core::Result<(AccessToken, String, String)> {
        // if the current cached token for this resource is good, return it.
        let token_cache = self.0.read().await;
        let scopes = scopes.iter().map(ToString::to_string).collect::<Vec<_>>();

        let id_token_cache = IdTokenCache::new(oid, tid, scopes.clone());

        if let Some(token) = token_cache.get(&id_token_cache) {
            if !should_refresh(token) {
                trace!("returning cached token");
                return Ok((
                    token.clone(),
                    id_token_cache.oid.clone(),
                    id_token_cache.tid.clone(),
                ));
            }
        }

        // otherwise, drop the read lock and get a write lock to refresh the token
        drop(token_cache);
        let mut token_cache = self.0.write().await;

        // check again in case another thread refreshed the token while we were
        // waiting on the write lock
        if let Some(token) = token_cache.get(&id_token_cache) {
            if !should_refresh(token) {
                trace!("returning token that was updated while waiting on write lock");
                return Ok((
                    token.clone(),
                    id_token_cache.oid.clone(),
                    id_token_cache.tid.clone(),
                ));
            }
        }

        trace!("falling back to callback");
        let token = callback.await?;
        let new_id_token_cache =
            IdTokenCache::new(token.1.clone(), token.2.clone(), scopes.clone());

        // NOTE: we do not check to see if the token is expired here, as at
        // least one credential, `AzureCliCredential`, specifies the token is
        // immediately expired after it is returned, which indicates the token
        // should always be refreshed upon use.
        token_cache.insert(new_id_token_cache, token.0.clone());
        Ok((token.0, token.1.clone(), token.2.clone()))
    }
}
fn should_refresh(token: &AccessToken) -> bool {
    token.expires_on <= OffsetDateTime::now_utc() + Duration::seconds(300)
}
impl Default for TokenCache {
    fn default() -> Self {
        TokenCache::new()
    }
}
