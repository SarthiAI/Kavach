//! Integration tests against a real Redis instance.
//!
//! These tests only run when `TEST_REDIS_URL` is set (e.g.,
//! `TEST_REDIS_URL=redis://127.0.0.1:6379`). Absent the env var, every test
//! short-circuits to `Ok(())`, contributors without a local Redis don't see
//! false failures, and CI can opt-in by setting the variable.
//!
//! Each test uses a unique key namespace so concurrent runs don't collide.

use kavach_core::context::SessionState;
use kavach_core::invalidation::InvalidationBroadcaster;
use kavach_core::rate_limit::RateLimitStore;
use kavach_core::session_store::SessionStore;
use kavach_core::verdict::{InvalidationScope, InvalidationTarget};
use kavach_redis::{
    RedisInvalidationBroadcaster, RedisRateLimitStore, RedisSessionStore,
};
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

/// Fetch the test Redis URL, returning `None` if the env var is unset.
///
/// Tests short-circuit on `None` so the crate remains test-able without
/// a running Redis instance.
fn redis_url() -> Option<String> {
    std::env::var("TEST_REDIS_URL").ok()
}

macro_rules! require_redis {
    () => {{
        match redis_url() {
            Some(u) => u,
            None => {
                eprintln!("skipping, TEST_REDIS_URL not set");
                return;
            }
        }
    }};
}

fn unique_key(prefix: &str) -> String {
    format!("{prefix}:{}", Uuid::new_v4())
}

// ─── RateLimitStore ──────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_record_then_count_returns_one() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let key = unique_key("test-rl");

    store.record(&key, 100).await.unwrap();
    assert_eq!(store.count_in_window(&key, 100, 60).await.unwrap(), 1);
}

#[tokio::test]
async fn rate_limit_count_without_record_returns_zero() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let key = unique_key("test-rl-missing");

    assert_eq!(store.count_in_window(&key, 100, 60).await.unwrap(), 0);
}

#[tokio::test]
async fn rate_limit_sliding_window_evicts_old_entries() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let key = unique_key("test-rl-window");

    store.record(&key, 100).await.unwrap();
    store.record(&key, 150).await.unwrap();
    store.record(&key, 200).await.unwrap();

    // now=200, window=60s → cutoff=140 → only t=150 and t=200 qualify.
    assert_eq!(store.count_in_window(&key, 200, 60).await.unwrap(), 2);
}

#[tokio::test]
async fn rate_limit_same_timestamp_counted_twice() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let key = unique_key("test-rl-dup");

    // Two records with identical `at` must both count, the uuid suffix in
    // the sorted-set member is what makes them distinct.
    store.record(&key, 100).await.unwrap();
    store.record(&key, 100).await.unwrap();

    assert_eq!(store.count_in_window(&key, 100, 60).await.unwrap(), 2);
}

#[tokio::test]
async fn rate_limit_count_excludes_future_entries() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let key = unique_key("test-rl-future");

    store.record(&key, 200).await.unwrap();
    // Query at now=100 → entry at t=200 is "in the future" and must not count.
    assert_eq!(store.count_in_window(&key, 100, 60).await.unwrap(), 0);
}

#[tokio::test]
async fn rate_limit_keys_are_isolated() {
    let url = require_redis!();
    let store = RedisRateLimitStore::from_url(&url).await.unwrap();
    let a = unique_key("test-rl-isolated-a");
    let b = unique_key("test-rl-isolated-b");

    store.record(&a, 100).await.unwrap();
    store.record(&a, 101).await.unwrap();
    store.record(&b, 100).await.unwrap();

    assert_eq!(store.count_in_window(&a, 200, 3600).await.unwrap(), 2);
    assert_eq!(store.count_in_window(&b, 200, 3600).await.unwrap(), 1);
}

#[tokio::test]
async fn rate_limit_fails_closed_on_bad_url() {
    // A URL pointing at a dead port should fail rather than succeed. The
    // ConnectionManager's default backoff retries for ~60s before giving up;
    // we wrap in a 3-second timeout so CI doesn't sit idle. Either outcome
    // (timeout or inner error) means the gate's fail-closed path kicks in.
    let result = timeout(
        Duration::from_secs(3),
        RedisRateLimitStore::from_url("redis://127.0.0.1:1"),
    )
    .await;
    match result {
        Err(_) => { /* outer timeout, still a failure from caller's pov */ }
        Ok(Err(_)) => { /* inner construction error, also good */ }
        Ok(Ok(_)) => panic!("dead port must not yield a working store"),
    }
}

// ─── SessionStore ────────────────────────────────────────────────────

#[tokio::test]
async fn session_store_get_missing_returns_none() {
    let url = require_redis!();
    let store = RedisSessionStore::from_url(&url).await.unwrap();
    let key = unique_key("test-sess-missing");

    assert!(store.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn session_store_put_then_get_roundtrip() {
    let url = require_redis!();
    let store = RedisSessionStore::from_url(&url).await.unwrap();
    let key = unique_key("test-sess-roundtrip");
    let session = SessionState::new();

    store.put(&key, session.clone()).await.unwrap();
    let loaded = store.get(&key).await.unwrap().expect("session present");
    assert_eq!(loaded.session_id, session.session_id);
}

#[tokio::test]
async fn session_store_put_overwrites_existing() {
    let url = require_redis!();
    let store = RedisSessionStore::from_url(&url).await.unwrap();
    let key = unique_key("test-sess-overwrite");
    let mut session = SessionState::new();

    store.put(&key, session.clone()).await.unwrap();
    session.invalidated = true;
    store.put(&key, session.clone()).await.unwrap();

    let loaded = store.get(&key).await.unwrap().unwrap();
    assert!(loaded.invalidated);
}

#[tokio::test]
async fn session_store_delete_is_idempotent() {
    let url = require_redis!();
    let store = RedisSessionStore::from_url(&url).await.unwrap();
    let key = unique_key("test-sess-delete");
    let session = SessionState::new();

    store.put(&key, session).await.unwrap();
    store.delete(&key).await.unwrap();
    assert!(store.get(&key).await.unwrap().is_none());

    // Second delete on the same key must still succeed.
    store.delete(&key).await.unwrap();
}

#[tokio::test]
async fn session_store_ttl_respected() {
    let url = require_redis!();
    // TTL of 1 second, the session should expire almost immediately.
    let store = RedisSessionStore::from_url_with_ttl(&url, 1)
        .await
        .unwrap();
    let key = unique_key("test-sess-ttl");
    let session = SessionState::new();

    store.put(&key, session).await.unwrap();
    assert!(store.get(&key).await.unwrap().is_some());

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        store.get(&key).await.unwrap().is_none(),
        "session should have expired via Redis TTL"
    );
}

#[tokio::test]
async fn session_store_ttl_zero_rejected() {
    let url = require_redis!();
    let client = redis::Client::open(url.as_str()).unwrap();
    let result = RedisSessionStore::with_ttl(client, 0).await;
    assert!(result.is_err(), "ttl=0 must be rejected");
}

#[tokio::test]
async fn session_store_cleanup_is_no_op() {
    let url = require_redis!();
    let store = RedisSessionStore::from_url(&url).await.unwrap();
    // Always returns Ok(0), Redis TTL handles expiration.
    let removed = store.cleanup(60).await.unwrap();
    assert_eq!(removed, 0);
}

// ─── InvalidationBroadcaster ─────────────────────────────────────────

#[tokio::test]
async fn broadcaster_publish_then_local_subscriber_receives() {
    let url = require_redis!();
    let channel = unique_key("test-inv-channel");
    let b = RedisInvalidationBroadcaster::from_url(&url, channel.clone())
        .await
        .unwrap();

    let mut rx = b.subscribe();

    // Give the bridge a moment to actually SUBSCRIBE before we PUBLISH,
    // Redis drops messages published before the subscription is active.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let scope = InvalidationScope {
        target: InvalidationTarget::Session(Uuid::new_v4()),
        reason: "test".into(),
        evaluator: "test".into(),
    };
    b.publish(scope.clone()).await.unwrap();

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("receive within timeout")
        .expect("channel open");
    assert_eq!(got.reason, scope.reason);
    assert_eq!(got.evaluator, scope.evaluator);
}

#[tokio::test]
async fn broadcaster_cross_instance_delivery() {
    let url = require_redis!();
    let channel = unique_key("test-inv-cross");

    // Two broadcaster instances sharing a channel, this is the core
    // distributed scenario: node A publishes, node B receives.
    let publisher = RedisInvalidationBroadcaster::from_url(&url, channel.clone())
        .await
        .unwrap();
    let subscriber = RedisInvalidationBroadcaster::from_url(&url, channel.clone())
        .await
        .unwrap();

    let mut rx = subscriber.subscribe();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let scope = InvalidationScope {
        target: InvalidationTarget::Session(Uuid::new_v4()),
        reason: "cross-node-test".into(),
        evaluator: "test".into(),
    };
    publisher.publish(scope.clone()).await.unwrap();

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("receive within timeout")
        .expect("channel open");
    assert_eq!(got.reason, "cross-node-test");
}

#[tokio::test]
async fn broadcaster_publish_with_no_subscribers_succeeds() {
    let url = require_redis!();
    let channel = unique_key("test-inv-nosubs");
    let b = RedisInvalidationBroadcaster::from_url(&url, channel)
        .await
        .unwrap();

    let scope = InvalidationScope {
        target: InvalidationTarget::Session(Uuid::new_v4()),
        reason: "nobody-listening".into(),
        evaluator: "test".into(),
    };
    // Publishing with nobody subscribed is not an error, the local verdict
    // doesn't depend on peers acknowledging.
    b.publish(scope).await.unwrap();
}

#[tokio::test]
async fn broadcaster_fails_closed_on_bad_url() {
    // Bounded timeout, see rate_limit_fails_closed_on_bad_url for rationale.
    let result = timeout(
        Duration::from_secs(3),
        RedisInvalidationBroadcaster::from_url("redis://127.0.0.1:1", "test-inv-bad-url"),
    )
    .await;
    match result {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("dead port must not yield a working broadcaster"),
    }
}
