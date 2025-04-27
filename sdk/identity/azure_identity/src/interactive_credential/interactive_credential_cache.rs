// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use async_lock::RwLock;
use azure_core::credentials::AccessToken;
use futures::Future;
use std::collections::HashMap;
use tracing::trace;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct IdTokenCache {
    pub oid: String,
    pub tid: String,
    pub scopes: Vec<String>,
}

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
            if !token.is_expired(None) {
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
            if !token.is_expired(None) {
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

impl Default for TokenCache {
    fn default() -> Self {
        TokenCache::new()
    }
}
