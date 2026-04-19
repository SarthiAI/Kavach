//! Tests for GeoLocationDrift's configurable distance threshold.
//!
//! Covers the four reachable paths through `GeoLocationDrift::detect`:
//! 1. Strict mode (default, `max_distance_km = None`): any IP change → Violation.
//! 2. Tolerant mode, distance within threshold → Warning.
//! 3. Tolerant mode, distance beyond threshold → Violation.
//! 4. Tolerant mode, geo data missing (can't verify distance) → Violation (fail-closed).

use kavach_core::{
    ActionContext, ActionDescriptor, DriftDetector, DriftSignal, EnvContext, GeoLocation,
    GeoLocationDrift, Principal, PrincipalKind, SessionState,
};
use std::net::{IpAddr, Ipv4Addr};

fn principal() -> Principal {
    Principal {
        id: "agent-alice".into(),
        kind: PrincipalKind::Agent,
        roles: vec![],
        credentials_issued_at: chrono::Utc::now(),
        display_name: None,
    }
}

fn make_ctx(
    origin_ip: Option<IpAddr>,
    current_ip: Option<IpAddr>,
    origin_geo: Option<GeoLocation>,
    current_geo: Option<GeoLocation>,
) -> ActionContext {
    let mut session = SessionState::new();
    session.origin_ip = origin_ip;
    session.origin_geo = origin_geo;

    let env = EnvContext {
        ip: current_ip,
        device: None,
        geo: current_geo,
        user_agent: None,
    };

    ActionContext::new(principal(), ActionDescriptor::new("act"), session, env)
}

fn sf() -> GeoLocation {
    GeoLocation {
        country_code: "US".into(),
        region: Some("CA".into()),
        city: Some("San Francisco".into()),
        latitude: Some(37.7749),
        longitude: Some(-122.4194),
    }
}

fn oakland() -> GeoLocation {
    // ~13 km from SF
    GeoLocation {
        country_code: "US".into(),
        region: Some("CA".into()),
        city: Some("Oakland".into()),
        latitude: Some(37.8044),
        longitude: Some(-122.2712),
    }
}

fn london() -> GeoLocation {
    // ~8600 km from SF
    GeoLocation {
        country_code: "GB".into(),
        region: None,
        city: Some("London".into()),
        latitude: Some(51.5074),
        longitude: Some(-0.1278),
    }
}

#[tokio::test]
async fn strict_mode_any_ip_change_is_violation() {
    let drift = GeoLocationDrift::default();
    assert!(drift.max_distance_km.is_none(), "default must be strict");

    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        Some(sf()),
        Some(sf()),
    );
    match drift.detect(&ctx).await {
        DriftSignal::Violation(_) => {}
        other => panic!("strict mode must violate on any IP change, got {other:?}"),
    }
}

#[tokio::test]
async fn strict_mode_stable_when_ip_unchanged() {
    let drift = GeoLocationDrift::default();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ctx = make_ctx(Some(ip), Some(ip), None, None);
    assert!(matches!(drift.detect(&ctx).await, DriftSignal::Stable));
}

#[tokio::test]
async fn tolerant_mode_within_threshold_is_warning() {
    let drift = GeoLocationDrift::with_max_distance_km(100.0);
    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        Some(sf()),
        Some(oakland()),
    );
    match drift.detect(&ctx).await {
        DriftSignal::Warning(w) => {
            assert!(
                w.severity > 0.0 && w.severity <= 1.0,
                "severity must be in (0, 1], got {}",
                w.severity
            );
        }
        other => panic!("within-threshold move must warn, got {other:?}"),
    }
}

#[tokio::test]
async fn tolerant_mode_beyond_threshold_is_violation() {
    let drift = GeoLocationDrift::with_max_distance_km(100.0);
    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        Some(sf()),
        Some(london()),
    );
    match drift.detect(&ctx).await {
        DriftSignal::Violation(v) => {
            assert!(v.message.contains("threshold"));
        }
        other => panic!("beyond-threshold move must violate, got {other:?}"),
    }
}

#[tokio::test]
async fn tolerant_mode_missing_origin_geo_fails_closed() {
    let drift = GeoLocationDrift::with_max_distance_km(100.0);
    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        None, // origin_geo missing
        Some(sf()),
    );
    match drift.detect(&ctx).await {
        DriftSignal::Violation(v) => {
            assert!(
                v.evidence.contains("origin_geo_present=false"),
                "evidence should flag the missing origin_geo, got: {}",
                v.evidence
            );
        }
        other => panic!("missing origin_geo must fail closed, got {other:?}"),
    }
}

#[tokio::test]
async fn tolerant_mode_missing_current_geo_fails_closed() {
    let drift = GeoLocationDrift::with_max_distance_km(100.0);
    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        Some(sf()),
        None, // current geo missing
    );
    match drift.detect(&ctx).await {
        DriftSignal::Violation(v) => {
            assert!(
                v.evidence.contains("current_geo_present=false"),
                "evidence should flag the missing current geo, got: {}",
                v.evidence
            );
        }
        other => panic!("missing current geo must fail closed, got {other:?}"),
    }
}

#[tokio::test]
async fn tolerant_mode_missing_lat_long_fails_closed() {
    // geo present but lat/long None, distance_km returns None → violation
    let drift = GeoLocationDrift::with_max_distance_km(100.0);
    let partial = GeoLocation {
        country_code: "US".into(),
        region: None,
        city: None,
        latitude: None,
        longitude: None,
    };
    let ctx = make_ctx(
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        Some(partial.clone()),
        Some(partial),
    );
    assert!(matches!(
        drift.detect(&ctx).await,
        DriftSignal::Violation(_)
    ));
}
