use std::time::Instant;

use dashmap::DashMap;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use crate::config::Config;

pub fn build_webauthn(config: &Config) -> Webauthn {
    let rp_origin =
        Url::parse(&config.webauthn_rp_origin).expect("invalid WEBAUTHN_RP_ORIGIN URL");

    WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)
        .expect("failed to build Webauthn")
        .rp_name("wirewarden")
        .build()
        .expect("failed to finalize Webauthn")
}

/// In-memory store for WebAuthn challenge state with a 5-minute TTL.
#[derive(Debug)]
pub struct ChallengeStore {
    inner: DashMap<String, (serde_json::Value, Instant)>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn insert(&self, key: String, state: serde_json::Value) {
        self.cleanup();
        self.inner.insert(key, (state, Instant::now()));
    }

    pub fn take(&self, key: &str) -> Option<serde_json::Value> {
        self.inner.remove(key).and_then(|(_, (state, created))| {
            if created.elapsed().as_secs() < 300 {
                Some(state)
            } else {
                None
            }
        })
    }

    fn cleanup(&self) {
        self.inner
            .retain(|_, (_, created)| created.elapsed().as_secs() < 300);
    }
}
